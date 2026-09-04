# `--protocol-only`: protocol detection without service fingerprinting

Status: implemented on branch `protocol-only`
Issue: [praetorian-inc/nerva#421](https://github.com/praetorian-inc/nerva/issues/421)
Date: 2026-09-04

## Problem

Issue #421 asks for a mode that reports only the wire protocol on a port. Two
distinct complaints, which map to two different layers of nerva:

1. **Speed.** When `http`/`https` matches, `fingerprint()`
   (`pkg/plugins/services/http/http.go:508`) runs wappalyzer, then ~163 passive
   fingerprinters over the response body, then **26 additional sequential HTTP
   GETs** against probe endpoints (`/api/version`, `/login`, `/phpmyadmin/`,
   `/favicon.ico`, `/hub/api/users`, …), each with the full timeout budget. This
   dominates per-target cost for HTTP services.

2. **`protocol` is polluted with product names.** ~68 plugins identify a product
   rather than a protocol (`oracle_ebs`, `oracle_weblogic`, `docker`, `cups`, …).
   They register as ordinary TCP/TCPTLS plugins, most at `Priority() == -1`, so
   they run *before* the generic `http`/`https` plugins and claim the port.
   `Service.Protocol` is then set from the matching plugin's payload type in
   `CreateServiceFrom` (`pkg/plugins/types.go:986`), yielding `oracle_ebs`
   instead of `http`.

There is no existing flag for either. `--scan-depth fast|thorough` controls only
port-priority vs. all-plugin iteration.

## Goal

A `--protocol-only` mode where `Service.Protocol` always names a wire protocol,
no application-layer detection runs, and no requests are made beyond what
protocol identification requires.

Default behavior is unchanged.

## Non-goals

- Changing default behavior in any way.
- Per-plugin selection (`--plugins a,b`). Separate feature.
- Parallelizing the 26 active probe GETs. A real win, but orthogonal; worth
  raising as a follow-up on the PR.
- Bounding the thorough-mode slow lane. On an unrecognized port with no banner,
  nerva still tries every remaining plugin on a fresh connection each. This is
  inherent to the plugin architecture, not to fingerprinting. `--protocol-only`
  trims the list but does not change the shape. Explicitly accepted (option A).
- Fixing `pkg/plugins/services/sstp`, which is registered in code but never
  blank-imported by `pkg/scan/plugin_list.go` and therefore never active.
  Pre-existing, unrelated; report separately.

## Design

### Two registries, two mechanisms

Application-layer classification happens in two independent places, and
disabling it needs two different mechanisms.

**Mechanism 1 — app-layer plugins.** These live in the same registry as `http`
and `ssh`: `plugins.RegisterPlugin` appends into `plugins.Plugins[p.Type()]`
(`pkg/plugins/plugins.go:21`), and `setupPlugins()`
(`pkg/scan/simple_scan.go:88`) copies each transport's slice out and sorts by
`Priority()` ascending. They are disabled by **never entering the list the
scanner iterates**.

**Mechanism 2 — HTTP fingerprinters.** These are not plugins. They live in
`httpFingerprinters`, populated by `fingerprinters.Register()`
(`pkg/plugins/fingerprinters/registry.go:100`), and are reached only from
`fingerprint()` inside the `http`/`https` plugin's `Run`. Mechanism 1 cannot
touch them. They are disabled by **not calling them**.

### Marker interface

```go
// pkg/plugins/types.go

// AppLayerPlugin is implemented by plugins that identify a product running
// over a wire protocol nerva already detects generically (e.g. Oracle EBS
// over HTTP), rather than identifying the wire protocol itself.
// Protocol-only scans skip these so Service.Protocol always names a protocol.
type AppLayerPlugin interface {
	Plugin

	// BaseProtocol names the plugin that claims the port instead when this
	// one is skipped, e.g. "http", "https", "ipp", "redis". Informational:
	// it documents intent and is asserted by tests, but selection uses only
	// whether a plugin implements this interface.
	BaseProtocol() string
}
```

A plugin is app-layer **iff it has a `BaseProtocol() string` method**. No name
list, no central registry of exclusions.

### Classification rule

A plugin is app-layer when it identifies a *product* and a more generic protocol
plugin would answer for the same port. Speaking HTTP is **not** the test:

- `ipp` (RFC 8010) and `sstp` use HTTP as a *transport* and are genuine
  protocols. Not marked.
- `cups` is Apple's print *system*, which speaks IPP. Marked, with
  `BaseProtocol() == "ipp"` — not `"http"`. Both plugins sit on port 631, so
  exclusion falls through to `ipp` cleanly even under `--fast`.

### Plugin selection

```go
// pkg/scan/simple_scan.go
var sortedTCPPlugins, protocolTCPPlugins []plugins.Plugin   // ×4 transports

func setupPlugins() {
	// ...existing copy + sort by Priority()...
	protocolTCPPlugins = withoutAppLayer(sortedTCPPlugins)   // built once, at init
	// ...same for TCPTLS, UDP, SCTP
}

func withoutAppLayer(in []plugins.Plugin) []plugins.Plugin {
	out := make([]plugins.Plugin, 0, len(in))
	for _, p := range in {
		if _, isApp := p.(plugins.AppLayerPlugin); !isApp {
			out = append(out, p)
		}
	}
	return out
}

func (c *Config) tcpCandidates() []plugins.Plugin {
	if c.ProtocolOnly {
		return protocolTCPPlugins
	}
	return sortedTCPPlugins
}
```

Both lists are built once at process start, so protocol-only costs nothing per
target. The four iteration sites in `SimpleScanTarget` plus `UDPScanTarget` and
`SCTPScanTarget` swap their package-level slice for the accessor.
`FilterPluginsByFamily` is untouched — it filters whatever slice it is handed.

### Skipping the fingerprint phase

`fingerprint()` and `FingerprintResponse` swap their `host string,
misconfigs bool` parameters for the `plugins.Target` both callers already hold.
Fewer parameters, and it carries the new flag.

```go
func fingerprint(resp *http.Response, analyzer *wappalyzer.Wappalyze,
	client *http.Client, baseURL string, target plugins.Target) (...) {

	if target.ProtocolOnly {
		// Body deliberately unread; Run's existing defer closes it.
		return nil, nil, nil, nil, nil, "", nil, nil
	}
	// ...wappalyzer + 163 passive + 26 active probes...
}
```

This eliminates the wappalyzer call, all passive matches, all probe requests,
**and** the 10 MB body read.

`FingerprintResponse` is exported but is not part of the documented library
surface (README shows only `scan.Config` and `scan.ScanTargets`). Note the
signature change in the CHANGELOG under `### Changed`.

One extra guard in `Run`: `if target.Deep && !target.ProtocolOnly` around
`RunDeepProbes`, covering library callers who set both directly on
`scan.Config`, where the CLI validation does not run.

### Output

`ServiceHTTP`/`ServiceHTTPS` are unchanged. Every fingerprint field is already
`omitempty`, so the payload collapses on its own with no separate output path.

```json
{"host":"example.com","ip":"93.184.216.34","port":443,"protocol":"https",
 "tls":true,"transport":"tcp",
 "metadata":{"status":"200 OK","status_code":200}}
```

`status`/`status_code` are kept: they are the HTTP response line, they evidence
that the service really is HTTP, and 200 vs 401 is worth knowing. Dropped:
`title`, `response_headers`, `technologies`, `cpes`, `fingerprint_metadata`, and
the top-level `version` (which is the `Server` header — application-layer).

Preserving `title` would have required a new `<title>` regex extractor with
entity handling and its own divergence from wappalyzer's extraction, purely to
retain an application-layer detail. Dropping it is what makes "never read the
body" possible.

### Flag plumbing

```
--protocol-only
  └→ cliConfig.protocolOnly            (pkg/runner/types.go)
      └→ createScanConfig              (pkg/runner/utils.go)
          └→ scan.Config.ProtocolOnly
              ├→ c.tcpCandidates()                → mechanism 1
              └→ simplePluginRunner sets
                 plugins.Target.ProtocolOnly      → mechanism 2
```

`plugins.Target.ProtocolOnly` is a new field beside the existing `Misconfigs`
and `Deep`, using the same plumbing pattern (`simple_scan.go:391`, and the
UDP/SCTP paths in `scan_api.go`).

`StateConfig.ProtocolOnly` is added for resume, restored in `root.go` alongside
`misconfigs`/`deep`.

### Validation

`checkConfig` rejects `--protocol-only` combined with `--misconfigs` or
`--deep`. `--deep` is entirely fingerprinter-driven (`RunDeepProbes` iterates
only fingerprinters), and `checkDirectoryListing` needs the body protocol-only
no longer reads. Erroring beats a silent no-op.

## App-layer plugins: 68 structs across 31 packages

Verified by enumerating the live registry via reflection (225 plugins total:
133 TCP, 55 TCPTLS, 32 UDP, 8 SCTP).

`BaseProtocol() == "http"` for TCP variants, `"https"` for TCPTLS, except where
noted.

| Package | Structs |
|---|---|
| `cups` | `CUPSPlugin`, `CUPSTLSPlugin` — **both `"ipp"`** |
| `docker` | `DockerPlugin`, `DockerTLSPlugin` |
| `glassfish` | `GlassFishPlugin`, `GlassFishTLSPlugin` |
| `influxdb` | `InfluxDBPlugin` |
| `librechat` | `LibreChatPlugin`, `LibreChatTLSPlugin` |
| `milvus` | `MilvusPlugin` — **`"grpc"`**; `MilvusMetricsPlugin` |
| `oracleagile` | `AgilePLMPlugin`, `AgilePLMTLSPlugin` |
| `oracleebs` | `EBSPlugin`, `EBSTLSPlugin` |
| `oracleem` | `Plugin`, `TLSPlugin` |
| `oracleformsreports` | `FormsPlugin`, `FormsTLSPlugin`, `ReportsPlugin`, `ReportsTLSPlugin` |
| `oraclegoldengate` | `Plugin`, `TLSPlugin` |
| `oraclehttp` | `OHSPlugin`, `OHSTLSPlugin` |
| `oraclehyperion` | `HyperionPlugin`, `HyperionTLSPlugin`, `EssbasePlugin`, `EssbaseTLSPlugin` |
| `oracleidentity` | `OAMPlugin`, `OAMTLSPlugin`, `OIMPlugin`, `OIMTLSPlugin` |
| `oracleinfra` | `InfraPlugin`, `InfraTLSPlugin`, `VBoxWebPlugin` |
| `oraclejdesiebel` | `JDEPlugin`, `JDETLSPlugin`, `SiebelPlugin`, `SiebelTLSPlugin` |
| `oraclemft` | `MFTPlugin`, `MFTTLSPlugin` |
| `oracleobiee` | `Plugin`, `TLSPlugin` |
| `oracleords` | `ORDSPlugin`, `ORDSTLSPlugin` |
| `oracleouaf` | `OUAFPlugin`, `OUAFTLSPlugin` |
| `oracleprotocoldb` | `CoherenceHTTPPlugin`, `CoherenceHTTPTLSPlugin`, `NoSQLHTTPPlugin` |
| `oraclesbc` | `SBCPlugin`, `SBCTLSPlugin` |
| `oraclesoa` | `Plugin`, `TLSPlugin` |
| `oraclespatialstudio` | `SpatialStudioPlugin`, `SpatialStudioTLSPlugin` |
| `peoplesoft` | `PeopleSoftPlugin`, `PeopleSoftTLSPlugin` |
| `pulsar` | `AdminPlugin`, `AdminTLSPlugin` |
| `qdrant` | `QdrantPlugin` |
| `sonarqube` | `SonarQubePlugin` |
| `vmware` | `VMwarePlugin` |
| `webcenter` | `WebCenterPlugin`, `WebCenterTLSPlugin` |
| `weblogic` | `WebLogicPlugin`, `WebLogicTLSPlugin` |

### Deliberately not marked

| Plugin | Port | Reason |
|---|---|---|
| `ipp.IPPPlugin`, `ipp.IPPTLSPlugin` | 631 | IPP is an IETF protocol over HTTP transport |
| `oraclegoldengate.ClassicPlugin` | 7809 | Raw banner protocol, no generic fallback |
| `oracleprotocoldb.CoherencePlugin` | 7574 | Native wire protocol |
| `oracleprotocoldb.NoSQLPlugin` | 5000 | Native wire protocol |
| `oracleprotocoldb.TimesTenPlugin` | 6624, 6625 | Native wire protocol |
| `pulsar.Plugin`, `pulsar.TLSPlugin` | 6650, 6651 | Pulsar binary protocol |
| `redissentinel.RedisSentinelPlugin` | 26379 | Separate protocol, not a product over Redis (see below) |

Consequence: protocol-only can still emit product-shaped names such as
`oracle_timesten`. Those are wire protocols with no generic alternative;
excluding them would return nothing rather than something better.

### Considered and rejected: `redissentinel`

Redis Sentinel speaks RESP, and the generic `redis` plugin does claim port 26379
once Sentinel is excluded (verified against a fake Sentinel: protocol-only
reports `redis`). Under a literal reading of the rule it qualifies.

It is nevertheless **not** marked. Unlike Oracle EBS over HTTP, Sentinel is the
same `redis-server` binary in a different mode, on its own port, with its own
command vocabulary — a separate protocol rather than a product riding a generic
transport. Marking it would also make `--protocol-only --fast` return nothing on
26379, since `REDISPlugin.PortPriority` covers only 6379.

The cost of leaving it in is one extra plugin in the slow-lane candidate list,
accepted deliberately.

## Testing

- **Drift guard** (`pkg/plugins`): every registered `AppLayerPlugin` returns a
  non-empty `BaseProtocol()` naming a plugin that is itself registered and *not*
  app-layer. This is what keeps the marker honest as plugins are added. It does
  **not** assert port overlap — `qdrant` (6333) has no generic plugin on that
  port, by design.
- `pkg/scan`: `withoutAppLayer` drops exactly the app-layer set and retains
  `http`/`https`/`ssh`/`ipp`; each `*Candidates()` accessor switches on
  `Config.ProtocolOnly`.
- `pkg/plugins/services/http`: `httptest` server serving an EBS-shaped root page
  and **counting requests**. Protocol-only makes exactly one request, yields
  `protocol: "http"`, empty technologies/CPEs/fingerprint_metadata, no title, no
  version. Default mode makes more than one and populates technologies.
- `pkg/runner`: `checkConfig` rejects `--protocol-only` with `--misconfigs` and
  with `--deep`; `createScanConfig` maps the flag; state round-trip preserves
  `ProtocolOnly`.
- End-to-end through `scan.ScanTargets` against a local listener, asserting
  `protocol == "http"` where default mode returns an app-layer name.

Baseline before starting: `pkg/plugins`, `pkg/scan`, `pkg/runner`,
`pkg/plugins/fingerprinters` all green; `pkg/plugins/services/http` green when
skipping `TestHTTPSPlugin_WeakTLS_Live`, which is a pre-existing environmental
failure (needs a container serving TLS 1.0/1.1).

## Documentation

- README: flag-table row, a "Protocol detection only" usage subsection, a
  Features bullet.
- CHANGELOG `[Unreleased]`: `### Added` for the flag, `### Changed` for the
  `FingerprintResponse` signature.

## Known limitation to document

`--protocol-only --fast` can return **no result** on a port only an app-layer
plugin covers — `qdrant` on 6333 is not in `commonHTTPPorts`, so nothing generic
claims it in the fast lane. Thorough mode (the default) catches it, since the
slow lane tries every plugin regardless of port. Document under the flag.
