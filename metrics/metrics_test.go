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
	"crypto/tls"
	"fmt"
	"net/http"
	"reflect"
	"testing"
	"time"

	"github.com/AthenZ/authorization-proxy/v4/config"
	"github.com/pkg/errors"
)

func TestNewNewMetrics(t *testing.T) {
	type args struct {
		cfg config.Metrics
	}
	type test struct {
		name      string
		args      args
		checkFunc func(Metrics) error
	}
	tests := []test{
		func() test {
			return test{
				name: "check metrics is disabled",
				args: args{
					cfg: config.Metrics{
						MetricsServerAddr: "",
					},
				},
				checkFunc: func(m Metrics) error {
					want := &metrics{
						cfg: config.Metrics{
							MetricsServerAddr: "",
						},
					}
					if !reflect.DeepEqual(m, want) {
						return errors.New("metrics server is not disabled")
					}
					return nil
				},
			}
		}(),
		func() test {
			cfg := config.Metrics{
				MetricsServerAddr: ":9793",
			}
			return test{
				name: "check metrics is enabled",
				args: args{
					cfg: cfg,
				},
				checkFunc: func(m Metrics) error {
					if m.(*metrics).srv.Addr != cfg.MetricsServerAddr {
						return errors.New("metrics server is not enabled")
					}
					return nil
				},
			}
		}(),
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := NewMetrics(tt.args.cfg)
			if err := tt.checkFunc(m); err != nil {
				t.Errorf("NewMetrics() error: %v", err)
			}
		})
	}
}

func Test_metrics_ListenAndServe(t *testing.T) {
	type fields struct {
		srv *http.Server

		cfg config.Metrics
	}
	type args struct {
		ctx context.Context
	}
	type test struct {
		name      string
		fields    fields
		args      args
		checkFunc func(*metrics, <-chan []error, error) error
		want      error
	}
	checkSrvRunning := func(addr string) error {
		res, err := http.DefaultClient.Get("http://127.0.0.1" + addr)
		if err != nil {
			return err
		}
		if res.StatusCode != 200 {
			return fmt.Errorf("Response status code invalid, %v", res.StatusCode)
		}
		return nil
	}
	tests := []test{
		func() test {
			ctx, cancelFunc := context.WithCancel(context.Background())
			MetricsServerAddr := ":9793"
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(200)
				fmt.Fprintln(w, "Hello, client")
			})
			return test{
				name: "Metrics server can start and stop",
				fields: fields{
					srv: func() *http.Server {
						srv := &http.Server{
							Addr:    MetricsServerAddr,
							Handler: handler,
						}
						srv.SetKeepAlivesEnabled(true)
						return srv
					}(),
					cfg: config.Metrics{
						MetricsServerAddr: MetricsServerAddr,
					},
				},
				args: args{
					ctx: ctx,
				},
				checkFunc: func(m *metrics, got <-chan []error, want error) error {
					time.Sleep(time.Millisecond * 1500)
					http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

					if err := checkSrvRunning(MetricsServerAddr); err != nil {
						fmt.Println(err)
						return fmt.Errorf("Metrics Server not running")
					}

					cancelFunc()
					time.Sleep(time.Millisecond * 250)

					if err := checkSrvRunning(MetricsServerAddr); err == nil {
						return fmt.Errorf("Metrics Server running")
					}

					return nil
				},
			}
		}(),
		func() test {
			ctx, cancelFunc := context.WithCancel(context.Background())
			MetricsServerAddr := ""
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(200)
				fmt.Fprintln(w, "Hello, client")
			})
			return test{
				name: "Metrics server disable",
				fields: fields{
					srv: &http.Server{
						Addr:    MetricsServerAddr,
						Handler: handler,
					},
					cfg: config.Metrics{},
				},
				args: args{
					ctx: ctx,
				},
				checkFunc: func(m *metrics, got <-chan []error, want error) error {
					time.Sleep(time.Millisecond * 150)
					http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

					if err := checkSrvRunning(MetricsServerAddr); err == nil {
						return fmt.Errorf("Metrics Server running")
					}

					cancelFunc()
					time.Sleep(time.Millisecond * 250)

					if err := checkSrvRunning(MetricsServerAddr); err == nil {
						return fmt.Errorf("Metrics Server running")
					}

					return nil
				},
			}
		}(),
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &metrics{
				srv: tt.fields.srv,
				cfg: tt.fields.cfg,
			}
			e := m.ListenAndServe(tt.args.ctx)
			if err := tt.checkFunc(m, e, tt.want); err != nil {
				t.Errorf("metrics.ListenAndServe() error: %v", err)
			}
		})
	}
}
