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
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"testing"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
)

// An HTTPS server answers a plaintext HTTP request on its port too: Go's sends
// "400 Bad Request: Client sent an HTTP request to an HTTPS server", as nginx
// sends "400 The plain HTTP request was sent to HTTPS port". The allowlist has
// to identify such a port as https, not as the plaintext http that answered.
func TestProtocolAllowlistIdentifiesTLSPortsAsTLS(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	httpsServer := httptest.NewTLSServer(handler)
	t.Cleanup(httpsServer.Close)
	httpServer := httptest.NewServer(handler)
	t.Cleanup(httpServer.Close)

	for _, test := range []struct {
		name     string
		url      string
		protocol string
		tls      bool
	}{
		{"https server", httpsServer.URL, plugins.ProtoHTTPS, true},
		{"http server", httpServer.URL, plugins.ProtoHTTP, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			serverURL, err := url.Parse(test.url)
			if err != nil {
				t.Fatalf("parsing %q: %v", test.url, err)
			}
			target := plugins.Target{Address: netip.MustParseAddrPort(serverURL.Host)}
			config := Config{
				DefaultTimeout: 5 * time.Second,
				Workers:        1,
				ProtocolOnly:   true,
				Protocols:      []string{plugins.ProtoHTTP, plugins.ProtoHTTPS},
			}

			results, err := ScanTargets(context.Background(), []plugins.Target{target}, config)
			if err != nil {
				t.Fatalf("ScanTargets: %v", err)
			}
			if len(results) != 1 {
				t.Fatalf("ScanTargets returned %d services, want 1", len(results))
			}
			if results[0].Protocol != test.protocol || results[0].TLS != test.tls {
				t.Errorf("got protocol %q with tls %v, want %q with tls %v",
					results[0].Protocol, results[0].TLS, test.protocol, test.tls)
			}
		})
	}
}
