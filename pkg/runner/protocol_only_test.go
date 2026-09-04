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

package runner

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestCheckConfig_ProtocolOnlyExclusivity(t *testing.T) {
	tests := []struct {
		name         string
		protocolOnly bool
		misconfigs   bool
		deep         bool
		wantErr      string
	}{
		{name: "protocol-only alone is valid", protocolOnly: true},
		{name: "misconfigs alone is valid", misconfigs: true},
		{name: "deep alone is valid", deep: true},
		{name: "misconfigs and deep together are valid", misconfigs: true, deep: true},
		{
			name:         "protocol-only rejects misconfigs",
			protocolOnly: true, misconfigs: true,
			wantErr: "--protocol-only cannot be combined with --misconfigs",
		},
		{
			name:         "protocol-only rejects deep",
			protocolOnly: true, deep: true,
			wantErr: "--protocol-only cannot be combined with --deep",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := cliConfig{
				protocolOnly: tc.protocolOnly,
				misconfigs:   tc.misconfigs,
				deep:         tc.deep,
			}
			err := checkConfig(&cfg)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("checkConfig() = %v, want nil", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("checkConfig() = nil, want error containing %q", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("checkConfig() = %q, want error containing %q", err, tc.wantErr)
			}
		})
	}
}

func TestCreateScanConfig_ProtocolOnly(t *testing.T) {
	if got := createScanConfig(cliConfig{protocolOnly: true}); !got.ProtocolOnly {
		t.Error("createScanConfig did not propagate protocolOnly to scan.Config")
	}
	if got := createScanConfig(cliConfig{}); got.ProtocolOnly {
		t.Error("createScanConfig set ProtocolOnly when the flag was not given")
	}
}

func TestStateRoundTrip_ProtocolOnly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")

	state := &ScanState{
		Version: CurrentStateVersion,
		Config:  StateConfig{TimeoutMs: 2000, ProtocolOnly: true},
		Targets: StateTargets{OriginalCount: 1, Pending: []string{"127.0.0.1:80"}},
	}
	if err := SaveState(path, state); err != nil {
		t.Fatalf("SaveState: %v", err)
	}

	loaded, err := LoadState(path)
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	if !loaded.Config.ProtocolOnly {
		t.Error("ProtocolOnly did not survive the state file round trip")
	}
}
