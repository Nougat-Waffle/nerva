// Copyright 2022 Praetorian Security, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package scan

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
)

// allRegisteredPlugins returns every plugin across all transports. This package
// blank-imports every service package (see plugin_list.go), so the registry is
// fully populated here — unlike in pkg/plugins itself.
func allRegisteredPlugins() []plugins.Plugin {
	var all []plugins.Plugin
	for _, proto := range []plugins.Protocol{plugins.TCP, plugins.TCPTLS, plugins.UDP, plugins.SCTP} {
		all = append(all, plugins.Plugins[proto]...)
	}
	return all
}

// TestAppLayerPluginsDeclareResolvableBaseProtocol is the drift guard for the
// AppLayerPlugin marker. A plugin added later that implements the interface
// with a typo'd or bogus BaseProtocol fails here rather than silently producing
// a protocol-only scan that skips a port with nothing to fall back to.
//
// It deliberately does NOT assert port overlap between the app-layer plugin and
// its base: qdrant listens on 6333, which no generic plugin claims by port. The
// fallback happens in the thorough-mode slow lane, which ignores port priority.
func TestAppLayerPluginsDeclareResolvableBaseProtocol(t *testing.T) {
	all := allRegisteredPlugins()

	// Names of every plugin that is NOT itself application-layer.
	protocolNames := make(map[string]bool)
	for _, p := range all {
		if _, isApp := p.(plugins.AppLayerPlugin); isApp {
			continue
		}
		protocolNames[strings.ToLower(p.Name())] = true
	}

	var appLayerCount int
	for _, p := range all {
		app, isApp := p.(plugins.AppLayerPlugin)
		if !isApp {
			continue
		}
		appLayerCount++

		base := app.BaseProtocol()
		if base == "" {
			t.Errorf("plugin %s (%s) implements AppLayerPlugin but BaseProtocol() is empty",
				p.Name(), p.Type())
			continue
		}
		if strings.EqualFold(base, p.Name()) {
			t.Errorf("plugin %s (%s) declares itself as its own BaseProtocol", p.Name(), p.Type())
			continue
		}
		if !protocolNames[strings.ToLower(base)] {
			t.Errorf("plugin %s (%s) declares BaseProtocol %q, which is not a registered non-app-layer plugin",
				p.Name(), p.Type(), base)
		}
	}

	if appLayerCount == 0 {
		t.Fatal("no AppLayerPlugin implementations found; the marker interface is not wired up")
	}
	t.Logf("%d application-layer plugins of %d registered", appLayerCount, len(all))
}

// TestAppLayerClassification pins the classification decisions that are easy to
// get wrong, in both directions. Speaking HTTP is not the criterion: IPP and
// Pulsar's binary protocol run over/alongside HTTP but are genuine protocols.
func TestAppLayerClassification(t *testing.T) {
	isAppLayer := make(map[string]bool)
	seen := make(map[string]bool)
	for _, p := range allRegisteredPlugins() {
		name := strings.ToLower(p.Name())
		seen[name] = true
		if _, ok := p.(plugins.AppLayerPlugin); ok {
			isAppLayer[name] = true
		}
	}

	// Products that run over a protocol nerva already detects generically.
	appLayer := []string{
		"oracle_ebs", "oracle_weblogic", "oracle_peoplesoft", "oracle_ords",
		"docker", "cups", "influxdb", "glassfish", "sonarqube", "qdrant",
		"pulsar-admin", "vmware-vsphere",
	}
	// Wire protocols, including ones that use HTTP purely as a transport.
	protocol := []string{
		"http", "https", "ipp", "ssh", "ftp", "redis", "redis-sentinel", "grpc",
		"pulsar", "oracle_timesten", "oracle_coherence", "oracle_nosql",
		"oracle_goldengate_manager",
	}

	for _, name := range appLayer {
		if !seen[name] {
			t.Errorf("test fixture stale: plugin %q is no longer registered", name)
			continue
		}
		if !isAppLayer[name] {
			t.Errorf("plugin %q should implement AppLayerPlugin but does not", name)
		}
	}
	for _, name := range protocol {
		if !seen[name] {
			t.Errorf("test fixture stale: plugin %q is no longer registered", name)
			continue
		}
		if isAppLayer[name] {
			t.Errorf("plugin %q is a wire protocol and must not implement AppLayerPlugin", name)
		}
	}
}

func TestWithoutAppLayer(t *testing.T) {
	full := sortedTCPPlugins
	filtered := withoutAppLayer(full)

	if len(filtered) >= len(full) {
		t.Fatalf("expected filtering to remove plugins: full=%d filtered=%d", len(full), len(filtered))
	}

	for _, p := range filtered {
		if _, isApp := p.(plugins.AppLayerPlugin); isApp {
			t.Errorf("app-layer plugin %s survived filtering", p.Name())
		}
	}

	// Order must be preserved so Priority() ordering still governs the scan.
	var fi int
	for _, p := range full {
		if _, isApp := p.(plugins.AppLayerPlugin); isApp {
			continue
		}
		if fi >= len(filtered) || filtered[fi] != p {
			t.Fatalf("filtering did not preserve order at index %d", fi)
		}
		fi++
	}
	if fi != len(filtered) {
		t.Fatalf("filtered list has %d entries, expected %d", len(filtered), fi)
	}

	// The generic plugins that app-layer ones fall back to must survive.
	names := make(map[string]bool)
	for _, p := range filtered {
		names[p.Name()] = true
	}
	for _, want := range []string{"http", "ipp", "ssh", "redis", "grpc"} {
		if !names[want] {
			t.Errorf("protocol plugin %q was removed by filtering", want)
		}
	}
}

func TestCandidateAccessorsHonorProtocolOnly(t *testing.T) {
	tests := []struct {
		name     string
		get      func(*Config) []plugins.Plugin
		full     []plugins.Plugin
		filtered []plugins.Plugin
	}{
		{"tcp", (*Config).tcpCandidates, sortedTCPPlugins, protocolTCPPlugins},
		{"tcptls", (*Config).tcpTLSCandidates, sortedTCPTLSPlugins, protocolTCPTLSPlugins},
		{"udp", (*Config).udpCandidates, sortedUDPPlugins, protocolUDPPlugins},
		{"sctp", (*Config).sctpCandidates, sortedSCTPPlugins, protocolSCTPPlugins},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.get(&Config{}); len(got) != len(tc.full) {
				t.Errorf("default config: got %d candidates, want %d", len(got), len(tc.full))
			}
			if got := tc.get(&Config{ProtocolOnly: true}); len(got) != len(tc.filtered) {
				t.Errorf("ProtocolOnly: got %d candidates, want %d", len(got), len(tc.filtered))
			}
			for _, p := range tc.get(&Config{ProtocolOnly: true}) {
				if _, isApp := p.(plugins.AppLayerPlugin); isApp {
					t.Errorf("ProtocolOnly returned app-layer plugin %s", p.Name())
				}
			}
		})
	}
}

// ebsPage is shaped to trigger the oracleebs plugin, which registers on TCP
// port 8000 at Priority -1 and therefore claims the port ahead of generic http.
const ebsPage = `<html><head><title>E-Business Suite Home Page</title></head>
<body>Oracle E-Business Suite <a href="/OA_HTML/AppsLogin">Login</a></body></html>`

// TestScanTargetsProtocolOnlyEndToEnd exercises both mechanisms together
// through the public API: app-layer plugin exclusion (so oracle_ebs never runs)
// and the skipped fingerprint phase.
//
// It needs the fixed port 8000 because plugin selection in fast mode is driven
// by PortPriority, and skips when that port is unavailable.
func TestScanTargetsProtocolOnlyEndToEnd(t *testing.T) {
	const port = 8000

	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Skipf("port %d unavailable, skipping end-to-end scan: %v", port, err)
	}

	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Server", "Oracle-Application-Server-11g")
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(ebsPage))
		}),
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })

	target := plugins.Target{
		Address: netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), port),
	}

	scanOnce := func(protocolOnly bool) plugins.Service {
		t.Helper()
		cfg := Config{
			DefaultTimeout: 5 * time.Second,
			FastMode:       true,
			Workers:        1,
			ProtocolOnly:   protocolOnly,
		}
		results, err := ScanTargets(context.Background(), []plugins.Target{target}, cfg)
		if err != nil {
			t.Fatalf("ScanTargets(protocolOnly=%v): %v", protocolOnly, err)
		}
		if len(results) != 1 {
			t.Fatalf("ScanTargets(protocolOnly=%v) returned %d services, want 1", protocolOnly, len(results))
		}
		return results[0]
	}

	// Default: the app-layer plugin claims the port and names the product.
	if got := scanOnce(false).Protocol; got != "oracle_ebs" {
		t.Fatalf("default scan reported protocol %q, want %q "+
			"(fixture no longer triggers the oracleebs plugin)", got, "oracle_ebs")
	}

	// Protocol-only: the app-layer plugin is excluded, generic http answers.
	svc := scanOnce(true)
	if svc.Protocol != plugins.ProtoHTTP {
		t.Errorf("protocol-only scan reported protocol %q, want %q", svc.Protocol, plugins.ProtoHTTP)
	}
	if svc.Version != "" {
		t.Errorf("protocol-only scan reported version %q, want empty", svc.Version)
	}

	var payload map[string]any
	if err := json.Unmarshal(svc.Raw, &payload); err != nil {
		t.Fatalf("unmarshalling metadata: %v", err)
	}
	for _, key := range []string{"title", "response_headers", "technologies", "cpes"} {
		if _, present := payload[key]; present {
			t.Errorf("protocol-only metadata contains application-layer key %q", key)
		}
	}
}
