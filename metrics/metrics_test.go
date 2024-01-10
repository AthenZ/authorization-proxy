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
	"reflect"
	"testing"

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
				MetricsServerAddr: "localhost:9793",
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
