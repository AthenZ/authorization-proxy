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
	"net/http"
	"sync"

	"github.com/AthenZ/authorization-proxy/v4/config"
	"github.com/kpango/glg"
	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type Metrics interface {
	ListenAndServe(context.Context) <-chan []error
	GetLatencyInstrumentation() prometheus.Summary
}

type metrics struct {
	srv        *http.Server
	latency    prometheus.Summary
	srvRunning bool

	cfg config.Metrics

	mu sync.RWMutex
}

func NewMetrics(cfg config.Metrics) (Metrics, error) {
	m := &metrics{}
	m.cfg = cfg

	if !m.metricsSrvEnable() {
		glg.Info("Metrics server is disabled with empty options: address[%d]", cfg.MetricsServerAddr)
		return m, nil
	}
	glg.Infof("Starting metrics exporter[%s]", m.cfg.MetricsServerAddr)
	latency := prometheus.NewSummary(prometheus.SummaryOpts{
		Name: "latency",
		Help: "latency",
	})
	prometheus.MustRegister(latency)
	path := "/metrics"
	mux := http.NewServeMux()
	mux.Handle(path, promhttp.Handler())

	srv := &http.Server{
		Addr:    m.cfg.MetricsServerAddr,
		Handler: mux,
	}

	m.srv = srv
	m.latency = latency
	return m, nil
}

func (m *metrics) ListenAndServe(ctx context.Context) <-chan []error {
	var (
		echan = make(chan []error, 1)
		sech  = make(chan error, 1)
	)
	wg := new(sync.WaitGroup)
	if m.metricsSrvEnable() {
		wg.Add(1)

		go func() {
			m.mu.Lock()
			m.srvRunning = true
			m.mu.Unlock()
			wg.Done()

			glg.Info("metrics server starting")
			select {
			case <-ctx.Done():
			case sech <- m.srv.ListenAndServe():
			}
			glg.Info("metrics server closed")

			m.mu.Lock()
			m.srvRunning = false
			m.mu.Unlock()
		}()

	}

	go func() {
		defer close(echan)
		wg.Wait()

		appendErr := func(errs []error, err error) []error {
			if err != nil {
				return append(errs, errors.Wrap(err, "metrics"))
			}
			return errs
		}
		shutdownMetricsServer := func(errs []error) []error {
			if m.srvRunning {
				glg.Info("metrics server will shutdown...")
				errs = appendErr(errs, m.srv.Shutdown(context.Background()))
			}
			return errs
		}
		errs := make([]error, 0, 1)

		handleErr := func(err error) {
			if err != nil {
				errs = append(errs, errors.Wrap(err, "close running metrics server and return any error"))
			}
			m.mu.RLock()
			errs = shutdownMetricsServer(errs)
			m.mu.RUnlock()
			echan <- errs
		}

		for {
			select {
			case <-ctx.Done():
				m.mu.RLock()
				errs = shutdownMetricsServer(errs)
				m.mu.RUnlock()
				echan <- appendErr(errs, ctx.Err())
				return

			case err := <-sech:
				handleErr(err)
				return
			}
		}
	}()

	return echan
}

func (m *metrics) GetLatencyInstrumentation() prometheus.Summary {
	return m.latency
}

func (m *metrics) metricsSrvEnable() bool {
	return m.cfg.MetricsServerAddr != ""
}
