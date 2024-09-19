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
	io_prometheus_client "github.com/prometheus/client_model/go"
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
				wantErr: errors.New("cannot register metrics http_origin_latency_in_seconds: duplicate metrics collector registration attempted"),
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
					observeName: HTTP_ORIGIN_LATENCY,
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
		m  *metrics
		ch chan prometheus.Metric
	}
	type test struct {
		name                   string
		fields                 fields
		wantPrincipalCacheSize float64
		wantPrincipalCacheLen  float64
	}
	tests := []test{
		func() test {
			wantPrincipalCacheSize := int64(10)
			wantPrincipalCacheLen := 20
			m1 := &metrics{
				principalCacheSizeFunc: func() int64 { return wantPrincipalCacheSize },
				principalCacheLenFunc:  func() int { return wantPrincipalCacheLen },
			}

			return test{
				name: "get cached_principal_bytes and cached_principal_entries",
				fields: fields{
					m:  m1,
					ch: make(chan prometheus.Metric, 2),
				},
				wantPrincipalCacheSize: float64(wantPrincipalCacheSize),
				wantPrincipalCacheLen:  float64(wantPrincipalCacheLen),
			}
		}(),
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			go func() {
				tt.fields.m.Collect(tt.fields.ch)
				close(tt.fields.ch)
			}()

			principalCacheSize := <-tt.fields.ch
			principalCacheLen := <-tt.fields.ch

			if principalCacheSize != nil {
				dtoMetric := &io_prometheus_client.Metric{}
				_ = principalCacheSize.Write(dtoMetric)

				actual := dtoMetric.GetGauge().GetValue()
				if actual != tt.wantPrincipalCacheSize {
					t.Errorf("principalCacheSize unexpected %f, got: %f", tt.wantPrincipalCacheSize, actual)
				}
			} else {
				t.Errorf("principalCacheSize unexpected %f, got: nil", tt.wantPrincipalCacheSize)
			}

			if principalCacheLen != nil {
				dtoMetric := &io_prometheus_client.Metric{}
				_ = principalCacheLen.Write(dtoMetric)

				actual := dtoMetric.GetGauge().GetValue()
				if actual != tt.wantPrincipalCacheLen {
					t.Errorf("prinPipalCacheLen unexpected %f, got: %f", tt.wantPrincipalCacheLen, actual)
				}
			} else {
				t.Errorf("prinPipalCacheLen unexpected %f, got: nil", tt.wantPrincipalCacheLen)
			}
		})
	}
}

func TestDescribe(t *testing.T) {
	type fields struct {
		m  *metrics
		ch chan *prometheus.Desc
	}
	type test struct {
		name                       string
		fields                     fields
		wantPrincipalCacheSizeName string
		wantPrincipalCacheLenName  string
	}
	tests := []test{
		func() test {
			wantPrincipalCacheSize := `Desc{fqName: "cached_principal_bytes", help: "Number of bytes cached", constLabels: {}, variableLabels: {}}`
			wantPrincipalCacheLen := `Desc{fqName: "cached_principal_entries", help: "Number of entries cached", constLabels: {}, variableLabels: {}}`
			m1 := &metrics{}

			return test{
				name: "get cached_principal_bytes and cached_principal_entries",
				fields: fields{
					m:  m1,
					ch: make(chan *prometheus.Desc, 2),
				},
				wantPrincipalCacheSizeName: wantPrincipalCacheSize,
				wantPrincipalCacheLenName:  wantPrincipalCacheLen,
			}
		}(),
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			go func() {
				tt.fields.m.Describe(tt.fields.ch)
				close(tt.fields.ch)
			}()

			principalCacheSizeName := <-tt.fields.ch
			principalCacheLenName := <-tt.fields.ch

			if principalCacheSizeName != nil {
				actual := principalCacheSizeName.String()
				if actual != tt.wantPrincipalCacheSizeName {
					t.Errorf("principalCacheSizeName unexpected %v, got: %v", tt.wantPrincipalCacheSizeName, actual)
				}
			} else {
				t.Errorf("principalCacheSizeName unexpected %v, got: nil", tt.wantPrincipalCacheSizeName)
			}

			if principalCacheLenName != nil {
				actual := principalCacheLenName.String()
				if actual != tt.wantPrincipalCacheLenName {
					t.Errorf("prinPipalCacheLenName unexpected %v, got: %v", tt.wantPrincipalCacheLenName, actual)
				}
			} else {
				t.Errorf("prinPipalCacheLenName unexpected %v, got: nil", tt.wantPrincipalCacheLenName)
			}
		})
	}
}
