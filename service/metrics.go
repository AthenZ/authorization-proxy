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
	"github.com/kpango/glg"
	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
)

const (
	HTTP_ORIGIN_LATENCY             = "http_origin_latency_in_seconds"
	HTTP_ORIGIN_LATENCY_HELP        = "Origin latency in seconds"
	CACHED_PRINCIPAL_BYTES_METRIC   = "cached_principal_bytes"
	CACHED_PRINCIPAL_BYTES_HELP     = "Number of bytes cached"
	CACHED_PRINCIPAL_ENTRIES_METRIC = "cached_principal_entries"
	CACHED_PRINCIPAL_ENTRIES_HELP   = "Number of entries cached"
)

type Metrics interface {
	Observe(string, float64) error
}

type metrics struct {
	httpOriginLatency      prometheus.Histogram
	principalCacheSizeFunc func() int64
	principalCacheLenFunc  func() int
}

// MetricsOption is option for NewMetrics
type MetricsOption func(*metrics)

// WithPrincipalCacheSizeFunc set principal cache size function
func WithPrincipalCacheSizeFunc(f func() int64) MetricsOption {
	return func(m *metrics) {
		m.principalCacheSizeFunc = f
	}
}

// WithPrincipalCacheLenFunc set principal cache length function
func WithPrincipalCacheLenFunc(f func() int) MetricsOption {
	return func(m *metrics) {
		m.principalCacheLenFunc = f
	}
}

func NewMetrics(opts ...MetricsOption) (Metrics, error) {
	m := &metrics{
		httpOriginLatency: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    HTTP_ORIGIN_LATENCY,
			Help:    HTTP_ORIGIN_LATENCY_HELP,
			Buckets: prometheus.DefBuckets,
		}),
	}

	for _, opt := range opts {
		opt(m)
	}

	err := prometheus.Register(m.httpOriginLatency)
	if err != nil {
		return nil, errors.Wrap(err, "cannot register metrics")
	}

	err = prometheus.Register(m)
	if err != nil {
		return nil, errors.Wrap(err, "cannot register metrics")
	}

	return m, nil
}

func (m *metrics) Observe(name string, value float64) error {
	switch name {
	case HTTP_ORIGIN_LATENCY:
		m.httpOriginLatency.Observe(value)
	default:
		return glg.Errorf("unknown metric name: %s", name)
	}
	return nil
}

// Collect is implementation of prometheus.Collector.Collect
func (m *metrics) Collect(ch chan<- prometheus.Metric) {
	// m.mutex.RLock()
	// defer m.mutex.RUnlock()

	// principal cache metrics
	var metric prometheus.Metric
	var err error
	metric, err = prometheus.NewConstMetric(
		prometheus.NewDesc(CACHED_PRINCIPAL_BYTES_METRIC, CACHED_PRINCIPAL_BYTES_HELP, nil, nil),
		prometheus.GaugeValue,
		float64(m.principalCacheSizeFunc()),
	)
	if err != nil {
		glg.Errorf("Failed to create metric: %s", err.Error())
	} else {
		ch <- metric
	}
	metric, err = prometheus.NewConstMetric(
		prometheus.NewDesc(CACHED_PRINCIPAL_ENTRIES_METRIC, CACHED_PRINCIPAL_ENTRIES_HELP, nil, nil),
		prometheus.GaugeValue,
		float64(m.principalCacheLenFunc()),
	)
	if err != nil {
		glg.Errorf("Failed to create metric: %s", err.Error())
	} else {
		ch <- metric
	}
}

// Describe is implementation of prometheus.Collector.Describe
func (m *metrics) Describe(ch chan<- *prometheus.Desc) {
	ch <- prometheus.NewDesc(CACHED_PRINCIPAL_BYTES_METRIC, CACHED_PRINCIPAL_BYTES_HELP, nil, nil)
	ch <- prometheus.NewDesc(CACHED_PRINCIPAL_ENTRIES_METRIC, CACHED_PRINCIPAL_ENTRIES_HELP, nil, nil)
}
