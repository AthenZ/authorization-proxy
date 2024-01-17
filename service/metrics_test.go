// Copyright 2023 LY Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package service

import (
	"testing"
)

func TestNewMetrics(t *testing.T) {
	tests := []struct {
		name string
	}{
		{
			name: "should return Metrics interface",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := NewMetrics()
			if _, ok := m.(Metrics); !ok {
				t.Errorf("NewMetrics() error: %v", m)
			}
		})
	}
}

func TestGetLatencyInstrumentation(t *testing.T) {
	type test struct {
		name string
	}
	tests := []test{
		func() test {
			return test{
				name: "check GetLatencyInstrumentation() return prometheus.Histogram",
			}
		}(),
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := NewMetrics()
			if m == nil {
				t.Error("NewMetrics() error")
			}
			latency := m.GetLatencyInstrumentation()
			if latency == nil {
				t.Errorf("GetLatencyInstrumentation() error: %v", latency)
			}
		})
	}
}
