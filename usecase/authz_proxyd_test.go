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

package usecase

import (
	"context"
	"fmt"
	"reflect"
	"sort"
	"sync"
	"testing"
	"time"

	authorizerd "github.com/AthenZ/athenz-authorizer/v5"
	"github.com/AthenZ/authorization-proxy/v4/config"
	"github.com/AthenZ/authorization-proxy/v4/service"
	"github.com/pkg/errors"
)

func TestNew(t *testing.T) {
	type args struct {
		cfg config.Config
	}
	type test struct {
		name       string
		args       args
		checkFunc  func(AuthzProxyDaemon) error
		wantErr    bool
		wantErrStr string
	}
	tests := []test{
		func() test {
			cfg := config.Config{
				Athenz: config.Athenz{
					URL: "athenz.io",
				},
				Authorization: config.Authorization{
					AthenzDomains: []string{"dummyDom1", "dummyDom2"},
					PublicKey: config.PublicKey{
						SysAuthDomain:   "dummy.sys.auth",
						RefreshPeriod:   "10s",
						ETagExpiry:      "10s",
						ETagPurgePeriod: "10s",
					},
					Policy: config.Policy{
						ExpiryMargin:  "10s",
						RefreshPeriod: "10s",
						PurgePeriod:   "10s",
					},
					AccessToken: config.AccessToken{
						Enable: true,
					},
				},
				Server: config.Server{
					HealthCheck: config.HealthCheck{
						Endpoint: "/dummy",
					},
					TLS: config.TLS{
						Enable:            true,
						CertRefreshPeriod: "24h",
					},
				},
				Proxy: config.Proxy{
					BufferSize: 512,
				},
			}
			return test{
				name: "new success",
				args: args{
					cfg: cfg,
				},
				checkFunc: func(got AuthzProxyDaemon) error {
					if got == nil {
						return errors.New("got is nil")
					}
					if !reflect.DeepEqual(got.(*authzProxyDaemon).cfg, cfg) {
						return errors.New("got.cfg does not equal")
					}
					if got.(*authzProxyDaemon).athenz == nil {
						return errors.New("got.athenz is nil")
					}
					if got.(*authzProxyDaemon).server == nil {
						return errors.New("got.server is nil")
					}
					if got.(*authzProxyDaemon).tlsCertificateCache == nil {
						return errors.New("got.tlsCertificateCache is nil")
					}
					return nil
				},
			}
		}(),
		func() test {
			cfg := config.Config{
				Athenz: config.Athenz{
					URL: "athenz.io",
				},
				Authorization: config.Authorization{
					AthenzDomains: []string{"dummyDom1", "dummyDom2"},
					PublicKey: config.PublicKey{
						SysAuthDomain:   "dummy.sys.auth",
						RefreshPeriod:   "10s",
						ETagExpiry:      "10s",
						ETagPurgePeriod: "10s",
					},
					Policy: config.Policy{
						ExpiryMargin:  "10s",
						RefreshPeriod: "10s",
						PurgePeriod:   "10s",
					},
					AccessToken: config.AccessToken{
						Enable: true,
					},
				},
				Server: config.Server{
					HealthCheck: config.HealthCheck{
						Endpoint: "/dummy",
					},
					TLS: config.TLS{
						Enable:            true,
						CertRefreshPeriod: "0s",
					},
				},
				Proxy: config.Proxy{
					BufferSize: 512,
				},
			}
			return test{
				name: "CertRefreshPeriod is 0, tlsCertificateCache is nil.",
				args: args{
					cfg: cfg,
				},
				checkFunc: func(got AuthzProxyDaemon) error {
					if got == nil {
						return errors.New("got is nil")
					}
					if !reflect.DeepEqual(got.(*authzProxyDaemon).cfg, cfg) {
						return errors.New("got.cfg does not equal")
					}
					if got.(*authzProxyDaemon).athenz == nil {
						return errors.New("got.athenz is nil")
					}
					if got.(*authzProxyDaemon).server == nil {
						return errors.New("got.server is nil")
					}
					if got.(*authzProxyDaemon).tlsCertificateCache != nil {
						return errors.New("got.tlsCertificateCache is not nil")
					}
					return nil
				},
			}
		}(),
		func() test {
			cfg := config.Config{
				Athenz: config.Athenz{
					URL: "athenz.io",
				},
				Authorization: config.Authorization{
					AthenzDomains: []string{"dummyDom1", "dummyDom2"},
					PublicKey: config.PublicKey{
						SysAuthDomain:   "dummy.sys.auth",
						RefreshPeriod:   "10s",
						ETagExpiry:      "10s",
						ETagPurgePeriod: "10s",
					},
					Policy: config.Policy{
						ExpiryMargin:  "10s",
						RefreshPeriod: "10s",
						PurgePeriod:   "10s",
					},
					AccessToken: config.AccessToken{
						Enable: true,
					},
				},
				Server: config.Server{
					HealthCheck: config.HealthCheck{
						Endpoint: "/dummy",
					},
					TLS: config.TLS{
						Enable: true,
					},
				},
				Proxy: config.Proxy{
					BufferSize: 512,
				},
			}
			return test{
				name: "CertRefreshPeriod not set, tlsCertificateCache is nil.",
				args: args{
					cfg: cfg,
				},
				checkFunc: func(got AuthzProxyDaemon) error {
					if got == nil {
						return errors.New("got is nil")
					}
					if !reflect.DeepEqual(got.(*authzProxyDaemon).cfg, cfg) {
						return errors.New("got.cfg does not equal")
					}
					if got.(*authzProxyDaemon).athenz == nil {
						return errors.New("got.athenz is nil")
					}
					if got.(*authzProxyDaemon).server == nil {
						return errors.New("got.server is nil")
					}
					if got.(*authzProxyDaemon).tlsCertificateCache != nil {
						return errors.New("got.tlsCertificateCache is not nil")
					}
					return nil
				},
			}
		}(),
		func() test {
			cfg := config.Config{
				Athenz: config.Athenz{
					URL: "athenz.io",
				},
				Authorization: config.Authorization{
					AthenzDomains: []string{"dummyDom1", "dummyDom2"},
					PublicKey: config.PublicKey{
						SysAuthDomain:   "dummy.sys.auth",
						RefreshPeriod:   "10s",
						ETagExpiry:      "10s",
						ETagPurgePeriod: "10s",
					},
					Policy: config.Policy{
						ExpiryMargin:  "10s",
						RefreshPeriod: "10s",
						PurgePeriod:   "10s",
					},
					AccessToken: config.AccessToken{
						Enable: true,
					},
				},
				Server: config.Server{
					Metrics: config.Metrics{
						Port: 6085,
					},
				},
			}
			service.NewMetrics()
			return test{
				name: "return error if Metrics.Port is set but registration of metrics failed",
				args: args{
					cfg: cfg,
				},
				wantErr:    true,
				wantErrStr: "cannot NewMetrics(): cannot register metrics http_origin_latency_in_seconds: duplicate metrics collector registration attempted",
			}
		}(),
		{
			name: "new error",
			args: args{
				cfg: config.Config{
					Authorization: config.Authorization{
						PublicKey: config.PublicKey{
							RefreshPeriod: "dummy",
						},
					},
				},
			},
			wantErr:    true,
			wantErrStr: "cannot newAuthzD(cfg): error create pubkeyd: invalid refresh period: time: invalid duration \"dummy\"",
		}, {
			name: "return error when grpc TLS cert invalid",
			args: args{
				cfg: config.Config{
					Authorization: config.Authorization{
						RoleToken: config.RoleToken{
							Enable: true,
						},
					},
					Server: config.Server{
						TLS: config.TLS{
							Enable:   true,
							CertPath: "../test/data/invalid_dummyServer.crt",
							KeyPath:  "../test/data/invalid_dummyServer.key",
						},
					},
				},
			},
			wantErr:    true,
			wantErrStr: "cannot NewTLSConfigWithTLSCertificateCache(cfg.Server.TLS): tls.LoadX509KeyPair(cert, key): tls: failed to find any PEM data in certificate input",
		}, {
			name: "return error when CertRefreshPeriod invalid (failed to parse)",
			args: args{
				cfg: config.Config{
					Authorization: config.Authorization{
						RoleToken: config.RoleToken{
							Enable: true,
						},
					},
					Server: config.Server{
						TLS: config.TLS{
							Enable:            true,
							CertRefreshPeriod: "abcdefg",
						},
					},
				},
			},
			wantErr:    true,
			wantErrStr: "cannot NewTLSConfigWithTLSCertificateCache(cfg.Server.TLS): isValidDuration(cfg.CertRefreshPeriod): time: invalid duration \"abcdefg\"",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := New(tt.args.cfg)
			if (err != nil) != tt.wantErr {
				t.Errorf("New() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				if err == nil {
					t.Errorf("New() error = %v, wantErr %v", err, tt.wantErr)
					return
				}
				if err.Error() != tt.wantErrStr {
					t.Errorf("New() error = %v, wantErrStr = %v", err, tt.wantErrStr)
					return
				}
			}
			if tt.checkFunc != nil {
				if err = tt.checkFunc(got); err != nil {
					t.Errorf("New() error = %v", err)
					return
				}
			}
		})
	}
}

func Test_authzProxyDaemon_Init(t *testing.T) {
	type fields struct {
		athenz service.Authorizationd
	}
	type args struct {
		ctx context.Context
	}
	tests := []struct {
		name       string
		fields     fields
		args       args
		wantErrStr string
	}{
		{
			name: "init sccuess",
			fields: fields{
				athenz: &service.AuthorizerdMock{
					InitFunc: func(ctx context.Context) error {
						return nil
					},
				},
			},
			args:       args{ctx: context.Background()},
			wantErrStr: "",
		},
		{
			name: "init fail",
			fields: fields{
				athenz: &service.AuthorizerdMock{
					InitFunc: func(ctx context.Context) error {
						return errors.New("authorizerd error")
					},
				},
			},
			args:       args{ctx: context.Background()},
			wantErrStr: "authorizerd error",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := &authzProxyDaemon{
				athenz: tt.fields.athenz,
			}
			err := g.Init(tt.args.ctx)
			if (err == nil && tt.wantErrStr != "") || (err != nil && err.Error() != tt.wantErrStr) {
				t.Errorf("authzProxyDaemon.Init() error = %v, wantErr %v", err, tt.wantErrStr)
				return
			}
		})
	}
}

func Test_authzProxyDaemon_Start(t *testing.T) {
	type fields struct {
		cfg                 config.Config
		athenz              service.Authorizationd
		server              service.Server
		tlsCertificateCache *service.TLSCertificateCache
	}
	type args struct {
		ctx context.Context
	}
	type test struct {
		name      string
		fields    fields
		args      args
		wantErrs  []error
		checkFunc func(<-chan []error, []error) error
	}
	getLessErrorFunc := func(errs []error) func(i, j int) bool {
		return func(i, j int) bool {
			return errs[i].Error() < errs[j].Error()
		}
	}
	defaultConfig := config.TLS{
		Enable:            true,
		CertPath:          "../test/data/dummyServer.crt",
		KeyPath:           "../test/data/dummyServer.key",
		CertRefreshPeriod: "5s",
	}
	_, defaultTLSCache, _ := service.NewTLSConfigWithTLSCertificateCache(defaultConfig)
	tests := []test{
		func() test {
			ctx, cancel := context.WithCancel(context.Background())
			return test{
				name: "Daemon start success",
				fields: fields{
					cfg: config.Config{
						Server: config.Server{
							TLS: defaultConfig,
						},
					},
					athenz: &service.AuthorizerdMock{
						StartFunc: func(ctx context.Context) <-chan error {
							ech := make(chan error)
							go func() {
								defer close(ech)
								<-ctx.Done()
								ech <- ctx.Err()
							}()
							return ech
						},
					},
					server: &service.ServerMock{
						ListenAndServeFunc: func(ctx context.Context) <-chan []error {
							ech := make(chan []error)
							go func() {
								defer close(ech)
								<-ctx.Done()
								// simulate graceful shutdown
								time.Sleep(1 * time.Millisecond)

								ech <- []error{ctx.Err()}
							}()
							return ech
						},
					},
					tlsCertificateCache: defaultTLSCache,
				},
				args: args{
					ctx: ctx,
				},
				wantErrs: []error{},
				checkFunc: func(got <-chan []error, wantErrs []error) error {
					cancel()
					mux := &sync.Mutex{}

					gotErrs := make([][]error, 0)
					mux.Lock()
					go func() {
						defer mux.Unlock()
						err, ok := <-got
						if !ok {
							return
						}
						gotErrs = append(gotErrs, err)
					}()
					time.Sleep(time.Second)

					mux.Lock()
					defer mux.Unlock()

					// check only send errors once and the errors are expected ignoring order
					sort.Slice(gotErrs[0], getLessErrorFunc(gotErrs[0]))
					sort.Slice(wantErrs, getLessErrorFunc(wantErrs))
					gotErrsStr := fmt.Sprintf("%v", gotErrs[0])
					wantErrsStr := fmt.Sprintf("%v", wantErrs)
					if len(gotErrs) != 1 || !reflect.DeepEqual(gotErrsStr, wantErrsStr) {
						return errors.Errorf("Invalid err, got: %v, want: %v", gotErrsStr, wantErrsStr)
					}

					return nil
				},
			}
		}(),
		func() test {
			ctx, cancel := context.WithCancel(context.Background())
			dummyErr := errors.New("dummy")
			return test{
				name: "Server fails",
				fields: fields{
					athenz: &service.AuthorizerdMock{
						StartFunc: func(ctx context.Context) <-chan error {
							ech := make(chan error)
							go func() {
								defer close(ech)
								<-ctx.Done()
								ech <- ctx.Err()
							}()
							return ech
						},
					},
					server: &service.ServerMock{
						ListenAndServeFunc: func(ctx context.Context) <-chan []error {
							ech := make(chan []error)
							go func() {
								defer close(ech)
								ech <- []error{errors.WithMessage(dummyErr, "server fails")}
							}()
							return ech
						},
					},
				},
				args: args{
					ctx: ctx,
				},
				wantErrs: []error{
					errors.WithMessage(dummyErr, "server fails"),
				},
				checkFunc: func(got <-chan []error, wantErrs []error) error {
					mux := &sync.Mutex{}

					gotErrs := make([][]error, 0)
					mux.Lock()
					go func() {
						defer mux.Unlock()
						err, ok := <-got
						if !ok {
							return
						}
						gotErrs = append(gotErrs, err)
					}()
					time.Sleep(time.Second)

					mux.Lock()
					defer mux.Unlock()

					// check only send errors once and the errors are expected ignoring order
					sort.Slice(gotErrs[0], getLessErrorFunc(gotErrs[0]))
					sort.Slice(wantErrs, getLessErrorFunc(wantErrs))
					gotErrsStr := fmt.Sprintf("%v", gotErrs[0])
					wantErrsStr := fmt.Sprintf("%v", wantErrs)
					if len(gotErrs) != 1 || !reflect.DeepEqual(gotErrsStr, wantErrsStr) {
						return errors.Errorf("Invalid err, got: %v, want: %v", gotErrsStr, wantErrsStr)
					}

					cancel()
					return nil
				},
			}
		}(),
		func() test {
			ctx, cancel := context.WithCancel(context.Background())
			dummyErr := errors.New("dummy")
			return test{
				name: "Authorizer daemon fails, multiple times",
				fields: fields{
					athenz: &service.AuthorizerdMock{
						StartFunc: func(ctx context.Context) <-chan error {
							ech := make(chan error)
							go func() {
								defer close(ech)

								// simulate fails
								ech <- errors.WithMessage(dummyErr, "authorizer daemon fails")
								ech <- errors.WithMessage(dummyErr, "authorizer daemon fails")
								ech <- errors.WithMessage(dummyErr, "authorizer daemon fails")

								// return only if context cancel
								<-ctx.Done()
								ech <- ctx.Err()
							}()
							return ech
						},
					},
					server: &service.ServerMock{
						ListenAndServeFunc: func(ctx context.Context) <-chan []error {
							ech := make(chan []error)
							go func() {
								defer close(ech)
								<-ctx.Done()
								// simulate graceful shutdown
								time.Sleep(1 * time.Millisecond)

								ech <- []error{ctx.Err()}
							}()
							return ech
						},
					},
				},
				args: args{
					ctx: ctx,
				},
				wantErrs: []error{
					errors.WithMessage(errors.Cause(errors.WithMessage(dummyErr, "authorizer daemon fails")), "authorizerd: 3 times appeared"),
				},
				checkFunc: func(got <-chan []error, wantErrs []error) error {
					cancel()
					mux := &sync.Mutex{}

					gotErrs := make([][]error, 0)
					mux.Lock()
					go func() {
						defer mux.Unlock()
						err, ok := <-got
						if !ok {
							return
						}
						gotErrs = append(gotErrs, err)
					}()
					time.Sleep(time.Second)

					mux.Lock()
					defer mux.Unlock()

					// check only send errors once and the errors are expected ignoring order
					sort.Slice(gotErrs[0], getLessErrorFunc(gotErrs[0]))
					sort.Slice(wantErrs, getLessErrorFunc(wantErrs))
					gotErrsStr := fmt.Sprintf("%v", gotErrs[0])
					wantErrsStr := fmt.Sprintf("%v", wantErrs)
					if len(gotErrs) != 1 || !reflect.DeepEqual(gotErrsStr, wantErrsStr) {
						return errors.Errorf("Invalid err, got: %v, want: %v", gotErrsStr, wantErrsStr)
					}

					return nil
				},
			}
		}(),
		func() test {
			ctx, cancel := context.WithCancel(context.Background())
			return test{
				name: "Daemon start end successfully, server shutdown without error",
				fields: fields{
					cfg: config.Config{
						Server: config.Server{
							TLS: defaultConfig,
						},
					},
					athenz: &service.AuthorizerdMock{
						StartFunc: func(ctx context.Context) <-chan error {
							ech := make(chan error)
							go func() {
								defer close(ech)
								// return only if context cancel
								<-ctx.Done()
								ech <- ctx.Err()
							}()
							return ech
						},
					},
					server: &service.ServerMock{
						ListenAndServeFunc: func(ctx context.Context) <-chan []error {
							ech := make(chan []error)
							go func() {
								defer close(ech)
								<-ctx.Done()
								// simulate graceful shutdown
								time.Sleep(1 * time.Millisecond)

								ech <- []error{}
							}()
							return ech
						},
					},
					tlsCertificateCache: defaultTLSCache,
				},
				args: args{
					ctx: ctx,
				},
				wantErrs: []error{},
				checkFunc: func(got <-chan []error, wantErrs []error) error {
					cancel()
					mux := &sync.Mutex{}

					gotErrs := make([][]error, 0)
					mux.Lock()
					go func() {
						defer mux.Unlock()
						err, ok := <-got
						if !ok {
							return
						}
						gotErrs = append(gotErrs, err)
					}()
					time.Sleep(time.Second)

					mux.Lock()
					defer mux.Unlock()

					// check only send errors once and the errors are expected ignoring order
					sort.Slice(gotErrs[0], getLessErrorFunc(gotErrs[0]))
					sort.Slice(wantErrs, getLessErrorFunc(wantErrs))
					gotErrsStr := fmt.Sprintf("%v", gotErrs[0])
					wantErrsStr := fmt.Sprintf("%v", wantErrs)
					if len(gotErrs) != 1 || !reflect.DeepEqual(gotErrsStr, wantErrsStr) {
						return errors.Errorf("Invalid err, got: %v, want: %v", gotErrsStr, wantErrsStr)
					}

					return nil
				},
			}
		}(),
		func() test {
			ctx, cancel := context.WithCancel(context.Background())
			dummyErr := errors.New("dummy")
			return test{
				name: "Daemon start end successfully, server shutdown >1 errors",
				fields: fields{
					cfg: config.Config{
						Server: config.Server{
							TLS: defaultConfig,
						},
					},
					athenz: &service.AuthorizerdMock{
						StartFunc: func(ctx context.Context) <-chan error {
							ech := make(chan error)
							go func() {
								defer close(ech)
								// return only if context cancel
								<-ctx.Done()
								ech <- ctx.Err()
							}()
							return ech
						},
					},
					server: &service.ServerMock{
						ListenAndServeFunc: func(ctx context.Context) <-chan []error {
							ech := make(chan []error)
							go func() {
								defer close(ech)
								<-ctx.Done()
								// simulate graceful shutdown
								time.Sleep(1 * time.Millisecond)

								ech <- []error{dummyErr, ctx.Err()}
							}()
							return ech
						},
					},
					tlsCertificateCache: defaultTLSCache,
				},
				args: args{
					ctx: ctx,
				},
				wantErrs: []error{
					errors.Wrap(dummyErr, context.Canceled.Error()),
				},
				checkFunc: func(got <-chan []error, wantErrs []error) error {
					cancel()
					mux := &sync.Mutex{}

					gotErrs := make([][]error, 0)
					mux.Lock()
					go func() {
						defer mux.Unlock()
						err, ok := <-got
						if !ok {
							return
						}
						gotErrs = append(gotErrs, err)
					}()
					time.Sleep(time.Second)

					mux.Lock()
					defer mux.Unlock()

					// check only send errors once and the errors are expected ignoring order
					sort.Slice(gotErrs[0], getLessErrorFunc(gotErrs[0]))
					sort.Slice(wantErrs, getLessErrorFunc(wantErrs))
					gotErrsStr := fmt.Sprintf("%v", gotErrs[0])
					wantErrsStr := fmt.Sprintf("%v", wantErrs)
					if len(gotErrs) != 1 || !reflect.DeepEqual(gotErrsStr, wantErrsStr) {
						return errors.Errorf("Invalid err, got: %v, want: %v", gotErrsStr, wantErrsStr)
					}

					return nil
				},
			}
		}(),
		func() test {
			ctx, cancel := context.WithCancel(context.Background())
			dummyErr := errors.New("dummy")
			return test{
				name: "Cert refrsh daemon stops when tlsCertificateCache is nil",
				fields: fields{
					cfg: config.Config{
						Server: config.Server{
							TLS: config.TLS{
								Enable:            false,
								CertRefreshPeriod: "3h",
								CertPath:          "../test/data/dummyServer.crt",
								KeyPath:           "../test/data/dummyServer.key",
							},
						},
					},
					athenz: &service.AuthorizerdMock{
						StartFunc: func(ctx context.Context) <-chan error {
							ech := make(chan error)
							go func() {
								defer close(ech)
								<-ctx.Done()
								ech <- ctx.Err()
							}()
							return ech
						},
					},
					server: &service.ServerMock{
						ListenAndServeFunc: func(ctx context.Context) <-chan []error {
							ech := make(chan []error)
							go func() {
								defer close(ech)
								ech <- []error{errors.WithMessage(dummyErr, "server fails")}
							}()
							return ech
						},
					},
					tlsCertificateCache: nil,
				},
				args: args{
					ctx: ctx,
				},
				wantErrs: []error{
					errors.WithMessage(dummyErr, "server fails"),
				},
				checkFunc: func(got <-chan []error, wantErrs []error) error {
					mux := &sync.Mutex{}

					gotErrs := make([][]error, 0)
					mux.Lock()
					go func() {
						defer mux.Unlock()
						// this can be execute == through eg.Wait() == refresh daemon is not running
						err, ok := <-got
						if !ok {
							return
						}
						gotErrs = append(gotErrs, err)
					}()
					time.Sleep(time.Second)

					mux.Lock()
					defer mux.Unlock()

					// check only send errors once and the errors are expected ignoring order
					sort.Slice(gotErrs[0], getLessErrorFunc(gotErrs[0]))
					sort.Slice(wantErrs, getLessErrorFunc(wantErrs))
					gotErrsStr := fmt.Sprintf("%v", gotErrs[0])
					wantErrsStr := fmt.Sprintf("%v", wantErrs)
					if len(gotErrs) != 1 || !reflect.DeepEqual(gotErrsStr, wantErrsStr) {
						return errors.Errorf("Invalid err, got: %v, want: %v", gotErrsStr, wantErrsStr)
					}

					cancel()
					return nil
				},
			}
		}(),
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := &authzProxyDaemon{
				cfg:                 tt.fields.cfg,
				athenz:              tt.fields.athenz,
				server:              tt.fields.server,
				tlsCertificateCache: tt.fields.tlsCertificateCache,
			}
			got := g.Start(tt.args.ctx)
			if err := tt.checkFunc(got, tt.wantErrs); err != nil {
				t.Errorf("authzProxyDaemon.Start() error: %v", err)
			}
		})
	}
}

// this requires integration test
func Test_newAuthzD(t *testing.T) {
	type args struct {
		cfg config.Config
	}
	tests := []struct {
		name       string
		args       args
		want       bool
		wantErrStr string
	}{
		{
			name: "test new Authorization fail, Athenz.Timeout",
			args: args{
				cfg: config.Config{
					Athenz: config.Athenz{
						Timeout: "invalid",
					},
				},
			},
			want:       false,
			wantErrStr: `newAuthzD(): Athenz.Timeout: time: invalid duration "invalid"`,
		},
		{
			name: "test new Authorization fail, Athenz.CAPath",
			args: args{
				cfg: config.Config{
					Athenz: config.Athenz{
						CAPath: "../test/data/non_existing_ca.pem",
					},
				},
			},
			want:       false,
			wantErrStr: "newAuthzD(): Athenz.CAPath: x509.SystemCertPool(): open ../test/data/non_existing_ca.pem: no such file or directory",
		},
		{
			name: "test new Authorization fail, authorizerd.New",
			args: args{
				cfg: config.Config{
					Authorization: config.Authorization{
						PublicKey: config.PublicKey{
							RefreshPeriod: "invalid_period",
						},
					},
				},
			},
			want:       false,
			wantErrStr: `error create pubkeyd: invalid refresh period: time: invalid duration "invalid_period"`,
		},
		{
			name: "test new Authorization fail, invalid MappingRules",
			args: args{
				cfg: config.Config{
					Authorization: config.Authorization{
						Policy: config.Policy{
							MappingRules: map[string][]authorizerd.Rule{
								"": {
									authorizerd.Rule{
										Method:   "get",
										Path:     "/path",
										Action:   "action",
										Resource: "resource",
									},
								},
							},
						},
						RoleToken: config.RoleToken{
							Enable:         true,
							RoleAuthHeader: "Athenz-Role-Auth",
						},
					},
				},
			},
			want:       false,
			wantErrStr: "newAuthzD(): Failed to create a MappingRules: domain is empty",
		},
		{
			name: "test success new Authorization",
			args: args{
				cfg: config.Config{
					Athenz: config.Athenz{
						URL:     "athenz.io",
						Timeout: "30s",
						CAPath:  "../test/data/dummyCa.pem",
					},
					Authorization: config.Authorization{
						AthenzDomains: []string{"dummyDom1", "dummyDom2"},
						PublicKey: config.PublicKey{
							SysAuthDomain:   "dummy.sys.auth",
							RefreshPeriod:   "10s",
							ETagExpiry:      "10s",
							ETagPurgePeriod: "10s",
						},
						Policy: config.Policy{
							ExpiryMargin:  "10s",
							RefreshPeriod: "10s",
							PurgePeriod:   "10s",
						},
						RoleToken: config.RoleToken{
							Enable:         true,
							RoleAuthHeader: "Athenz-Role-Auth",
						},
					},
				},
			},
			want: true,
		},
		{
			name: "test success access token enable, verify thumbprint disable",
			args: args{
				cfg: config.Config{
					Authorization: config.Authorization{
						PublicKey: config.PublicKey{
							SysAuthDomain:   "10s",
							ETagExpiry:      "10s",
							ETagPurgePeriod: "10s",
						},
						Policy: config.Policy{
							ExpiryMargin:  "10s",
							RefreshPeriod: "10s",
							PurgePeriod:   "10s",
						},
						AccessToken: config.AccessToken{
							Enable:               true,
							VerifyCertThumbprint: false,
							CertBackdateDuration: "10s",
							CertOffsetDuration:   "10s",
						},
					},
					Athenz: config.Athenz{
						URL: "dummy-athenz-url",
					},
				},
			},
			want: true,
		},
		{
			name: "test success access token enable, verify client_id disable",
			args: args{
				cfg: config.Config{
					Authorization: config.Authorization{
						PublicKey: config.PublicKey{
							SysAuthDomain:   "10s",
							ETagExpiry:      "10s",
							ETagPurgePeriod: "10s",
						},
						Policy: config.Policy{
							ExpiryMargin:  "10s",
							RefreshPeriod: "10s",
							PurgePeriod:   "10s",
						},
						AccessToken: config.AccessToken{
							Enable:         true,
							VerifyClientID: false,
							AuthorizedClientIDs: map[string][]string{
								"dummyCN1": {
									"dummyClientID1",
									"dummyClientID2",
								},
							},
						},
					},
					Athenz: config.Athenz{
						URL: "dummy-athenz-url",
					},
				},
			},
			want: true,
		},
		{
			name: "test success policy disable",
			args: args{
				cfg: config.Config{
					Authorization: config.Authorization{
						PublicKey: config.PublicKey{
							SysAuthDomain:   "10s",
							ETagExpiry:      "10s",
							ETagPurgePeriod: "10s",
						},
						Policy: config.Policy{
							Disable: true,
						},
						RoleToken: config.RoleToken{
							Enable:         true,
							RoleAuthHeader: "Athenz-Role-Auth",
						},
					},
				},
			},
			want: true,
		},
		{
			name: "test success mappingRules set",
			args: args{
				cfg: config.Config{
					Authorization: config.Authorization{
						Policy: config.Policy{
							MappingRules: map[string][]authorizerd.Rule{
								"domain": {
									authorizerd.Rule{
										Method:   "get",
										Path:     "/path",
										Action:   "action",
										Resource: "resource",
									},
								},
							},
						},
						RoleToken: config.RoleToken{
							Enable:         true,
							RoleAuthHeader: "Athenz-Role-Auth",
						},
					},
				},
			},
			want: true,
		},
		{
			name: "test success ResourcePrefix set",
			args: args{
				cfg: config.Config{
					Authorization: config.Authorization{
						Policy: config.Policy{
							ResourcePrefix: "/public",
						},
						RoleToken: config.RoleToken{
							Enable:         true,
							RoleAuthHeader: "Athenz-Role-Auth",
						},
					},
				},
			},
			want: true,
		},
		{
			name: "test outputAuthorizedPrincipalName true",
			args: args{
				cfg: config.Config{
					Athenz: config.Athenz{
						URL:     "athenz.io",
						Timeout: "30s",
						CAPath:  "../test/data/dummyCa.pem",
					},
					Authorization: config.Authorization{
						AthenzDomains: []string{"dummyDom1", "dummyDom2"},
						PublicKey: config.PublicKey{
							SysAuthDomain:   "dummy.sys.auth",
							RefreshPeriod:   "10s",
							ETagExpiry:      "10s",
							ETagPurgePeriod: "10s",
						},
						Policy: config.Policy{
							ExpiryMargin:  "10s",
							RefreshPeriod: "10s",
							PurgePeriod:   "10s",
						},
						RoleToken: config.RoleToken{
							Enable:         true,
							RoleAuthHeader: "Athenz-Role-Auth",
						},
					},
					Log: config.Log{
						OutputAuthorizedPrincipalName: true,
					},
				},
			},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := newAuthzD(tt.args.cfg)

			if (err == nil && tt.wantErrStr != "") || (err != nil && err.Error() != tt.wantErrStr) {
				t.Errorf("newAuthzD() error = %v, wantErr %v", err, tt.wantErrStr)
				return
			}
			if (got != nil) != tt.want {
				t.Errorf("newAuthzD()= %v, want= %v", got, tt.want)
				return
			}
		})
	}
}
