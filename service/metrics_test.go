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
	"reflect"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

func TestNewMetrics(t *testing.T) {
	type test struct {
		name string
	}
	tests := []test{
		{
			name: "NewMetrics() returns Metrics with valid latency histogram",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NewMetrics()
			gotMetrics, ok := got.(*metrics)
			if !ok {
				t.Errorf("NewMetrics() return value is not of type *metrics")
			}
			if reflect.TypeOf(gotMetrics.latency) != reflect.TypeOf(prometheus.NewHistogram(prometheus.HistogramOpts{})) {
				t.Errorf("NewMetrics() latency field should be of type prometheus.Histogram")
			}
		})
	}
}

func TestGetLatencyInstrumentation(t *testing.T) {
	latency := prometheus.NewHistogram(prometheus.HistogramOpts{
		Name: "origin_latency",
		Help: "origin_latency",
	})
	m := &metrics{
		latency: latency,
	}
	type test struct {
		name string
		want prometheus.Histogram
	}
	tests := []test{
		func() test {
			return test{
				name: "GetLatencyInstrumentation() exactly return m.latency",
				want: latency,
			}
		}(),
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := m.GetLatencyInstrumentation()
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GetLatencyInstrumentation() = %v, want %v", got, tt.want)
			}
		})
	}
}
