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

	"github.com/kpango/glg"
	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
)

func TestNewMetrics(t *testing.T) {
	type test struct {
		name    string
		wantErr error
	}
	tests := []test{
		func() test {
			return test{
				name:    "NewMetrics() success",
				wantErr: nil,
			}
		}(),
		func() test {
			return test{
				name:    "NewMetrics() error",
				wantErr: errors.New("cannot register metrics: duplicate metrics collector registration attempted"),
			}
		}(),
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewMetrics()
			if tt.wantErr == nil && err != nil {
				t.Errorf("NewMetrics() unexpected error, got: %v, wantErr: %v", err, tt.wantErr)
				return
			}
			if tt.wantErr != nil {
				if err == nil {
					t.Errorf("want error: %v, got nil", tt.wantErr)
					return
				}
				if err.Error() != tt.wantErr.Error() {
					t.Errorf("NewMetrics() error, got: %v, want: %v", err, tt.wantErr)
					return
				}
			}
		})
	}
}

func TestObserve(t *testing.T) {
	type fields struct {
		m           *metrics
		observeName string
	}
	type test struct {
		name    string
		fields  fields
		wantErr error
	}
	tests := []test{
		func() test {
			return test{
				name: "Observe() success",
				fields: fields{
					m: &metrics{
						httpOriginLatency: prometheus.NewHistogram(prometheus.HistogramOpts{
							Name:    "http_origin_latency_in_seconds",
							Help:    "Origin latency in seconds",
							Buckets: prometheus.DefBuckets,
						}),
					},
					observeName: HttpOriginLatencyMetric,
				},
				wantErr: nil,
			}
		}(),
		func() test {
			return test{
				name: "Observe() error",
				fields: fields{
					m: &metrics{
						httpOriginLatency: prometheus.NewHistogram(prometheus.HistogramOpts{
							Name:    "http_origin_latency_in_seconds",
							Help:    "Origin latency in seconds",
							Buckets: prometheus.DefBuckets,
						}),
					},
					observeName: "dummy",
				},
				wantErr: glg.Errorf("unknown metric name: %s", "dummy"),
			}
		}(),
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.fields.m.Observe(tt.fields.observeName, 0.0)
			if tt.wantErr == nil && err != nil {
				t.Errorf("Observe() unexpected error, got: %v", err)
				return
			}
			if tt.wantErr != nil {
				if err == nil {
					t.Errorf("want error: %v, got nil", tt.wantErr)
					return
				}
				if err.Error() != tt.wantErr.Error() {
					t.Errorf("Observe() error, got: %v, want: %v", err, tt.wantErr)
					return
				}
			}
		})
	}
}

func TestCollect(t *testing.T) {
	type fields struct {
		m *metrics
	}
	type test struct {
		name   string
		fields fields
	}
	tests := []test{
		func() test {
			return test{
				name: "Collect() success",
				fields: fields{
					m: &metrics{
						principalCacheSizeFunc: func() int64 {
							return 100
						},
					},
				},
			}
		}(),
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ch := make(chan prometheus.Metric)
			tt.fields.m.Collect(ch)
			close(ch)
		})
	}
}

func TestDesc(t *testing.T) {
	type fields struct {
		m *metrics
	}
	type test struct {
		name   string
		fields fields
	}
	tests := []test{
		func() test {
			return test{
				name: "Desc() success",
				fields: fields{
					m: &metrics{
						principalCacheLenFunc: func() int {
							return 100
						},
					},
				},
			}
		}(),
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ch := make(chan *prometheus.Desc)
			tt.fields.m.Describe(ch)
			close(ch)
		})
	}
}
