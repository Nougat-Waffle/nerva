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

package http

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	wappalyzer "github.com/projectdiscovery/wappalyzergo"

	"github.com/praetorian-inc/nerva/pkg/plugins"
)

// fingerprintableBody carries enough signal for wappalyzer and several
// fingerprinters to latch onto, so the default-mode side of these tests has
// something to find.
const fingerprintableBody = `<html><head><title>Welcome Home</title>
<script src="/static/js/jquery-3.6.0.min.js"></script></head>
<body><div id="app">dashboard</div></body></html>`

// newCountingServer returns an httptest server that records how many requests
// it receives, so tests can assert that protocol-only makes exactly one.
func newCountingServer(t *testing.T) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	var count atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count.Add(1)
		w.Header().Set("Server", "nginx/1.24.0")
		w.Header().Set("X-Powered-By", "Express")
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(fingerprintableBody))
	}))
	t.Cleanup(srv.Close)
	return srv, &count
}

// targetFor builds a Target addressing the given test server.
func targetFor(t *testing.T, srv *httptest.Server, protocolOnly bool) plugins.Target {
	t.Helper()
	host, port, err := net.SplitHostPort(srv.Listener.Addr().String())
	if err != nil {
		t.Fatalf("splitting server address: %v", err)
	}
	addr, err := netip.ParseAddrPort(net.JoinHostPort(host, port))
	if err != nil {
		t.Fatalf("parsing server address: %v", err)
	}
	return plugins.Target{Address: addr, ProtocolOnly: protocolOnly}
}

func runHTTPPluginAgainst(t *testing.T, srv *httptest.Server, target plugins.Target) *plugins.Service {
	t.Helper()
	analyzer, err := wappalyzer.New()
	if err != nil {
		t.Fatalf("wappalyzer init: %v", err)
	}
	conn, err := net.Dial("tcp", srv.Listener.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	plugin := &HTTPPlugin{analyzer: analyzer}
	svc, err := plugin.Run(conn, 5*time.Second, target)
	if err != nil {
		t.Fatalf("plugin.Run: %v", err)
	}
	if svc == nil {
		t.Fatal("plugin.Run returned no service")
	}
	return svc
}

// TestProtocolOnlyMakesExactlyOneRequest is the core guarantee: protocol-only
// identification costs a single round trip, versus the fingerprinting phase's
// active endpoint probes.
func TestProtocolOnlyMakesExactlyOneRequest(t *testing.T) {
	srv, count := newCountingServer(t)
	runHTTPPluginAgainst(t, srv, targetFor(t, srv, true))

	if got := count.Load(); got != 1 {
		t.Errorf("protocol-only made %d requests, want exactly 1", got)
	}
}

func TestDefaultModeProbesBeyondRoot(t *testing.T) {
	srv, count := newCountingServer(t)
	runHTTPPluginAgainst(t, srv, targetFor(t, srv, false))

	if got := count.Load(); got <= 1 {
		t.Errorf("default mode made %d requests, want more than 1 (active fingerprinter probes)", got)
	}
}

// TestProtocolOnlyPayloadIsProtocolLevel asserts the emitted metadata carries
// the response line and nothing application-layer.
func TestProtocolOnlyPayloadIsProtocolLevel(t *testing.T) {
	srv, _ := newCountingServer(t)
	svc := runHTTPPluginAgainst(t, srv, targetFor(t, srv, true))

	if svc.Protocol != plugins.ProtoHTTP {
		t.Errorf("Protocol = %q, want %q", svc.Protocol, plugins.ProtoHTTP)
	}
	// The Server header is an application-layer detail.
	if svc.Version != "" {
		t.Errorf("Version = %q, want empty in protocol-only mode", svc.Version)
	}

	var payload map[string]any
	if err := json.Unmarshal(svc.Raw, &payload); err != nil {
		t.Fatalf("unmarshalling metadata: %v", err)
	}

	if payload["status"] != "200 OK" {
		t.Errorf("status = %v, want %q", payload["status"], "200 OK")
	}
	if payload["status_code"] != float64(200) {
		t.Errorf("status_code = %v, want 200", payload["status_code"])
	}
	for _, key := range []string{"title", "response_headers", "technologies", "cpes", "fingerprint_metadata"} {
		if v, present := payload[key]; present {
			t.Errorf("protocol-only metadata contains application-layer key %q = %v", key, v)
		}
	}
}

// TestDefaultModePayloadUnchanged guards against the protocol-only path
// altering normal output.
func TestDefaultModePayloadUnchanged(t *testing.T) {
	srv, _ := newCountingServer(t)
	svc := runHTTPPluginAgainst(t, srv, targetFor(t, srv, false))

	if svc.Protocol != plugins.ProtoHTTP {
		t.Errorf("Protocol = %q, want %q", svc.Protocol, plugins.ProtoHTTP)
	}
	if svc.Version != "nginx/1.24.0" {
		t.Errorf("Version = %q, want %q", svc.Version, "nginx/1.24.0")
	}

	var payload map[string]any
	if err := json.Unmarshal(svc.Raw, &payload); err != nil {
		t.Fatalf("unmarshalling metadata: %v", err)
	}
	if payload["title"] != "Welcome Home" {
		t.Errorf("title = %v, want %q", payload["title"], "Welcome Home")
	}
	if _, ok := payload["response_headers"]; !ok {
		t.Error("default mode metadata is missing response_headers")
	}
	if _, ok := payload["technologies"]; !ok {
		t.Error("default mode metadata is missing technologies")
	}
}

// TestProtocolOnlyDoesNotConsumeBody documents that the body is never consumed:
// a handler that would block forever on the body still completes, because
// protocol-only returns after the response headers.
func TestProtocolOnlyDoesNotConsumeBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		// Declare far more than we send; reading to completion would block
		// until the client timeout.
		w.Header().Set("Content-Length", "1000000")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html><title>truncated</title>"))
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		time.Sleep(2 * time.Second)
	}))
	t.Cleanup(srv.Close)

	done := make(chan *plugins.Service, 1)
	go func() {
		analyzer, err := wappalyzer.New()
		if err != nil {
			done <- nil
			return
		}
		conn, err := net.Dial("tcp", srv.Listener.Addr().String())
		if err != nil {
			done <- nil
			return
		}
		defer conn.Close()
		plugin := &HTTPPlugin{analyzer: analyzer}
		svc, _ := plugin.Run(conn, 30*time.Second, targetFor(t, srv, true))
		done <- svc
	}()

	select {
	case svc := <-done:
		if svc == nil {
			t.Fatal("plugin returned no service")
		}
		if svc.Protocol != plugins.ProtoHTTP {
			t.Errorf("Protocol = %q, want %q", svc.Protocol, plugins.ProtoHTTP)
		}
	case <-time.After(1500 * time.Millisecond):
		t.Fatal("protocol-only scan blocked reading the response body")
	}
}
