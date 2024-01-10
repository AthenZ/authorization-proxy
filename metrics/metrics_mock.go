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

package metrics

import (
	"context"

	"github.com/prometheus/client_golang/prometheus"
)

// MetricsMock is a mock of Metrics
type MetricsMock struct {
	ListenAndServeFunc            func(context.Context) <-chan []error
	GetLatencyInstrumentationFunc func() prometheus.Summary
}

// ListenAndServe is a mock implementation of Server.ListenAndServe
func (mm *MetricsMock) ListenAndServe(ctx context.Context) <-chan []error {
	return mm.ListenAndServeFunc(ctx)
}

func (mm *MetricsMock) GetLatencyInstrumentation() prometheus.Summary {
	return mm.GetLatencyInstrumentationFunc()
}
