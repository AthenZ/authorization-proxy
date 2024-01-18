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
	"github.com/prometheus/client_golang/prometheus"
)

type Metrics interface {
	GetLatencyInstrumentation() prometheus.Histogram
}

type metrics struct {
	latency prometheus.Histogram
}

func NewMetrics() Metrics {
	latency := prometheus.NewHistogram(prometheus.HistogramOpts{
		Name: "origin_latency",
		Help: "origin_latency",
	})
	err := prometheus.Register(latency)

	if err != nil {
		if registered, ok := err.(prometheus.AlreadyRegisteredError); ok {
			prometheus.Unregister(registered.ExistingCollector)
			prometheus.MustRegister(latency)
		} else {
			glg.Errorf("Failed to register collector: %v", err)
		}
	}
	m := &metrics{
		latency: latency,
	}
	return m
}

func (m *metrics) GetLatencyInstrumentation() prometheus.Histogram {
	return m.latency
}
