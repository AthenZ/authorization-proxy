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
	HTTP_ORIGIN_LATENCY = "http_origin_latency_in_seconds"
)

type Metrics interface {
	Observe(string, float64) error
}

type metrics struct {
	httpOriginLatency prometheus.Histogram
}

func NewMetrics() (Metrics, error) {
	m := &metrics{
		httpOriginLatency: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    HTTP_ORIGIN_LATENCY,
			Help:    "Origin latency in seconds",
			Buckets: prometheus.DefBuckets,
		}),
	}

	err := prometheus.Register(m.httpOriginLatency)
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
