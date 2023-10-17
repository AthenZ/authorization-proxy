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

package handler

import (
	"reflect"
	"testing"

	"github.com/AthenZ/authorization-proxy/v4/config"
	"github.com/AthenZ/authorization-proxy/v4/service"
	"github.com/pkg/errors"
)

func TestWithProxyConfig(t *testing.T) {
	type args struct {
		cfg config.Proxy
	}
	type test struct {
		name      string
		args      args
		checkFunc func(GRPCOption) error
	}
	tests := []test{
		func() test {
			cfg := config.Proxy{
				Host: "http://test_server.com",
			}
			return test{
				name: "set success",
				args: args{
					cfg: cfg,
				},
				checkFunc: func(o GRPCOption) error {
					h := &GRPCHandler{}
					o(h)
					if !reflect.DeepEqual(h.proxyCfg, cfg) {
						return errors.New("config not match")
					}
					return nil
				},
			}
		}(),
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := WithProxyConfig(tt.args.cfg)
			if err := tt.checkFunc(got); err != nil {
				t.Errorf("WithProxyConfig() error = %v", err)
			}
		})
	}
}

func TestWithRoleTokenConfig(t *testing.T) {
	type args struct {
		cfg config.RoleToken
	}
	type test struct {
		name      string
		args      args
		checkFunc func(GRPCOption) error
	}
	tests := []test{
		func() test {
			cfg := config.RoleToken{
				Enable: true,
			}
			return test{
				name: "set success",
				args: args{
					cfg: cfg,
				},
				checkFunc: func(o GRPCOption) error {
					h := &GRPCHandler{}
					o(h)
					if !reflect.DeepEqual(h.roleCfg, cfg) {
						return errors.New("config not match")
					}
					return nil
				},
			}
		}(),
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := WithRoleTokenConfig(tt.args.cfg)
			if err := tt.checkFunc(got); err != nil {
				t.Errorf("WithRoleTokenConfig() error = %v", err)
			}
		})
	}
}

func TestWithAuthorizationd(t *testing.T) {
	type args struct {
		a service.Authorizationd
	}
	type test struct {
		name      string
		args      args
		checkFunc func(GRPCOption) error
	}
	tests := []test{
		func() test {
			a := &service.AuthorizerdMock{}
			return test{
				name: "set success",
				args: args{
					a: a,
				},
				checkFunc: func(o GRPCOption) error {
					h := &GRPCHandler{}
					o(h)
					if !reflect.DeepEqual(h.authorizationd, a) {
						return errors.New("authorizationd not match")
					}
					return nil
				},
			}
		}(),
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := WithAuthorizationd(tt.args.a)
			if err := tt.checkFunc(got); err != nil {
				t.Errorf("WithAuthorizationd() error = %v", err)
			}
		})
	}
}
