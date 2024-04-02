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

import "github.com/prometheus/client_golang/prometheus"

// MetricsMock is a mock of Metrics
type MetricsMock struct {
	ObserveFunc  func(string, float64) error
	CollectFunc  func(chan<- prometheus.Metric)
	DescribeFunc func(chan<- *prometheus.Desc)
}

// Observe is mock implementation of Metrics.Observe
func (mm *MetricsMock) Observe(name string, value float64) error {
	if mm.ObserveFunc != nil {
		return mm.ObserveFunc(name, value)
	}
	return nil
}

// Collect is mock implementation of Metrics.Collect
func (mm *MetricsMock) Collect(ch chan<- prometheus.Metric) {
	if mm.CollectFunc != nil {
		mm.CollectFunc(ch)
	}
}

// Describe is mock implementation of Metrics.Describe
func (mm *MetricsMock) Describe(ch chan<- *prometheus.Desc) {
	if mm.DescribeFunc != nil {
		mm.DescribeFunc(ch)
	}
}
