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
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AthenZ/authorization-proxy/v4/config"
	"github.com/mwitkow/grpc-proxy/proxy"
	"github.com/pkg/errors"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/protobuf/types/known/emptypb"
)

func TestNewServer(t *testing.T) {
	type args struct {
		opts []Option
	}
	type test struct {
		name      string
		args      args
		want      Server
		wantErr   error
		checkFunc func(got, want Server, gotErr, wantErr error) error
	}
	tests := []test{
		{
			name: "Check health address",
			args: args{
				opts: []Option{
					WithServerConfig(config.Server{
						HealthCheck: config.HealthCheck{
							Port:     8080,
							Endpoint: "/healthz",
						},
					}),
					WithRestHandler(func() http.Handler {
						return nil
					}()),
				},
			},
			want: &server{
				hcsrv: &http.Server{
					Addr: fmt.Sprintf(":%d", 8080),
				},
			},
			checkFunc: func(got, want Server, gotErr, wantErr error) error {
				if !errors.Is(gotErr, wantErr) {
					return errors.Errorf("got error is not matched with want error, got: %s, want: %s", gotErr, wantErr)
				}
				if got.(*server).hcsrv.Addr != want.(*server).hcsrv.Addr {
					return fmt.Errorf("Healthz Addr not equals\tgot: %s\twant: %s", got.(*server).hcsrv.Addr, want.(*server).hcsrv.Addr)
				}
				return nil
			},
		},
		{
			name: "Check debug server address",
			args: args{
				opts: []Option{
					WithServerConfig(config.Server{
						HealthCheck: config.HealthCheck{
							Port:     8080,
							Endpoint: "/healthz",
						},
						Debug: config.Debug{
							Enable: true,
							Port:   8081,
						},
					}),
					WithDebugHandler(func() http.Handler {
						return nil
					}()),
				},
			},
			want: &server{
				dsrv: &http.Server{
					Addr: fmt.Sprintf(":%d", 8081),
				},
			},
			checkFunc: func(got, want Server, gotErr, wantErr error) error {
				if !errors.Is(gotErr, wantErr) {
					return errors.Errorf("got error is not matched with want error, got: %s, want: %s", gotErr, wantErr)
				}
				if got.(*server).dsrv.Addr != want.(*server).dsrv.Addr {
					return fmt.Errorf("Debug Addr not equals\tgot: %s\twant: %s", got.(*server).hcsrv.Addr, want.(*server).hcsrv.Addr)
				}
				return nil
			},
		},
		{
			name: "Check metrics address",
			args: args{
				opts: []Option{
					WithServerConfig(config.Server{
						HealthCheck: config.HealthCheck{
							Port:     8080,
							Endpoint: "/healthz",
						},
						Debug: config.Debug{
							Enable: true,
							Port:   8081,
						},
						Metrics: config.Metrics{
							Port: 8082,
						},
					}),
					WithRestHandler(func() http.Handler {
						return nil
					}()),
				},
			},
			want: &server{
				msrv: &http.Server{
					Addr: fmt.Sprintf(":%d", 8082),
				},
			},
			checkFunc: func(got, want Server, gotErr, wantErr error) error {
				if !errors.Is(gotErr, wantErr) {
					return errors.Errorf("got error is not matched with want error, got: %s, want: %s", gotErr, wantErr)
				}
				if got.(*server).msrv.Addr != want.(*server).msrv.Addr {
					return fmt.Errorf("Metrics Addr not equals\tgot: %s\twant: %s", got.(*server).msrv.Addr, want.(*server).msrv.Addr)
				}
				return nil
			},
		},
		{
			name: "Check HTTP server address",
			args: args{
				opts: []Option{
					WithServerConfig(config.Server{
						Port: 8081,
						HealthCheck: config.HealthCheck{
							Port:     8080,
							Endpoint: "/healthz",
						},
					}),
					WithRestHandler(func() http.Handler {
						return nil
					}()),
				},
			},
			want: &server{
				srv: &http.Server{
					Addr: fmt.Sprintf(":%d", 8081),
				},
			},
			checkFunc: func(got, want Server, gotErr, wantErr error) error {
				if !errors.Is(gotErr, wantErr) {
					return errors.Errorf("got error is not matched with want error, got: %s, want: %s", gotErr, wantErr)
				}
				if got.(*server).srv.Addr != want.(*server).srv.Addr {
					return fmt.Errorf("Server Addr not equals\tgot: %s\twant: %s", got.(*server).srv.Addr, want.(*server).srv.Addr)
				}
				return nil
			},
		},
		{
			name: "Check HTTPS server address and certificate",
			args: args{
				opts: []Option{
					WithServerConfig(config.Server{
						Port: 9999,
						TLS: config.TLS{
							Enable: true,
						},
						HealthCheck: config.HealthCheck{
							Port:     8080,
							Endpoint: "/healthz",
						},
					}),
					WithRestHandler(func() http.Handler {
						return nil
					}()),
					WithTLSConfig(func() *tls.Config {
						cfg, err := NewTLSConfig(config.TLS{
							Enable:   true,
							CertPath: "../test/data/dummyServer.crt",
							KeyPath:  "../test/data/dummyServer.key",
						})
						if err != nil {
							return nil
						}
						return cfg
					}()),
				},
			},
			want: &server{
				srv: &http.Server{
					Addr: fmt.Sprintf(":%d", 9999),
					TLSConfig: func() *tls.Config {
						cfg, err := NewTLSConfig(config.TLS{
							Enable:   true,
							CertPath: "../test/data/dummyServer.crt",
							KeyPath:  "../test/data/dummyServer.key",
						})
						if err != nil {
							return nil
						}
						return cfg
					}(),
				},
			},
			checkFunc: func(got, want Server, gotErr, wantErr error) error {
				if !errors.Is(gotErr, wantErr) {
					return errors.Errorf("got error is not matched with want error, got: %s, want: %s", gotErr, wantErr)
				}
				if got.(*server).srv.Addr != want.(*server).srv.Addr {
					return fmt.Errorf("Server Addr not equals\tgot: %s\twant: %s", got.(*server).srv.Addr, want.(*server).srv.Addr)
				}
				gotCert, _ := x509.ParseCertificate(got.(*server).srv.TLSConfig.Certificates[0].Certificate[0])
				wantCert, _ := x509.ParseCertificate(want.(*server).srv.TLSConfig.Certificates[0].Certificate[0])
				if gotCert.SerialNumber == nil || gotCert.SerialNumber.String() != wantCert.SerialNumber.String() {
					return fmt.Errorf("Certificate SerialNumber not equals\tgot: %s\twant: %s", gotCert.SerialNumber.String(), wantCert.SerialNumber.String())
				}
				return nil
			},
		},
		{
			name: "Check GRPC server not nil",
			args: args{
				opts: []Option{
					WithGRPCHandler(func(srv interface{}, stream grpc.ServerStream) error {
						return nil
					}),
				},
			},
			want: &server{
				grpcSrv: grpc.NewServer(
					grpc.CustomCodec(proxy.Codec()),
					grpc.UnknownServiceHandler(func(srv interface{}, stream grpc.ServerStream) error {
						return nil
					}),
				),
			},
			checkFunc: func(got, want Server, gotErr, wantErr error) error {
				if !errors.Is(gotErr, wantErr) {
					return errors.Errorf("got error is not matched with want error, got: %s, want: %s", gotErr, wantErr)
				}
				if reflect.DeepEqual(got.(*server).grpcSrv, want.(*server).grpcSrv) {
					return fmt.Errorf("not matched")
				}
				return nil
			},
		},
		{
			name: "Check GRPC TLS server not nil",
			args: args{
				opts: []Option{
					WithGRPCHandler(func(srv interface{}, stream grpc.ServerStream) error {
						return nil
					}),
					WithServerConfig(config.Server{
						Port: 9999,
						TLS: config.TLS{
							Enable:   true,
							CertPath: "../test/data/dummyServer.crt",
							KeyPath:  "../test/data/dummyServer.key",
						},
					}),
					WithTLSConfig(func() *tls.Config {
						cfg, err := NewTLSConfig(config.TLS{
							Enable:   true,
							CertPath: "../test/data/dummyServer.crt",
							KeyPath:  "../test/data/dummyServer.key",
						})
						if err != nil {
							return nil
						}
						return cfg
					}()),
				},
			},
			want: &server{
				grpcSrv: grpc.NewServer(
					grpc.CustomCodec(proxy.Codec()),
					grpc.UnknownServiceHandler(func(srv interface{}, stream grpc.ServerStream) error {
						return nil
					}),
					func() grpc.ServerOption {
						cfg, err := NewTLSConfig(config.TLS{
							Enable:   true,
							CertPath: "../test/data/dummyServer.crt",
							KeyPath:  "../test/data/dummyServer.key",
						})
						if err != nil {
							return nil
						}
						return grpc.Creds(credentials.NewTLS(cfg))
					}(),
				),
			},
			checkFunc: func(got, want Server, gotErr, wantErr error) error {
				if !errors.Is(gotErr, wantErr) {
					return errors.Errorf("got error is not matched with want error, got: %s, want: %s", gotErr, wantErr)
				}
				if reflect.DeepEqual(got.(*server).grpcSrv, want.(*server).grpcSrv) {
					return fmt.Errorf("not matched")
				}
				return nil
			},
		},
		{
			name: "Check TLS.Enable is true and tlsConfig is nil, return error",
			args: args{
				opts: []Option{
					WithServerConfig(config.Server{
						Port: 9999,
						TLS: config.TLS{
							Enable: true,
						},
					}),
				},
			},
			want:    nil,
			wantErr: errors.New("s.cfg.TLS.Enable is true, but s.tlsConfig is nil."),
			checkFunc: func(got, want Server, gotErr, wantErr error) error {
				if gotErr.Error() != wantErr.Error() {
					return errors.Errorf("got error is not matched with want error, got: %s, want: %s", gotErr, wantErr)
				}
				if got != nil {
					return fmt.Errorf("want: nil, got: %s", got)
				}
				return nil
			},
		},
	}
	for _, tt := range []struct {
		name string
		cfg  config.Server
		want [4]time.Duration
	}{
		{name: "unset preserves existing behavior"},
		{
			name: "explicit zero",
			cfg: config.Server{
				ReadHeaderTimeout: "0s", ReadTimeout: "0s", WriteTimeout: "0s", IdleTimeout: "0s",
			},
		},
		{
			name: "configured",
			cfg: config.Server{
				ReadHeaderTimeout: "500ms", ReadTimeout: "30s", WriteTimeout: "1m", IdleTimeout: "2m",
			},
			want: [4]time.Duration{500 * time.Millisecond, 30 * time.Second, time.Minute, 2 * time.Minute},
		},
		{
			name: "read timeout only leaves Go fallbacks intact",
			cfg:  config.Server{ReadTimeout: "30s"},
			want: [4]time.Duration{0, 30 * time.Second, 0, 0},
		},
	} {
		for _, mode := range []string{"http", "https", "grpc"} {
			cfg := tt.cfg
			cfg.HealthCheck = config.HealthCheck{Port: 8081, Endpoint: "/healthz"}
			cfg.Debug = config.Debug{Enable: true, Port: 8082}
			cfg.Metrics = config.Metrics{Port: 8083}
			cfg.TLS.Enable = mode == "https"
			opts := []Option{WithServerConfig(cfg), WithRestHandler(http.NotFoundHandler())}
			if mode == "https" {
				opts = append(opts, WithTLSConfig(&tls.Config{}))
			}
			if mode == "grpc" {
				opts = append(opts, WithGRPCHandler(func(interface{}, grpc.ServerStream) error { return nil }))
			}
			tests = append(tests, test{
				name: "HTTP timeouts/" + tt.name + "/" + mode,
				args: args{opts: opts},
				checkFunc: func(got, _ Server, gotErr, _ error) error {
					if gotErr != nil {
						return gotErr
					}
					s := got.(*server)
					servers := map[string]*http.Server{"health": s.hcsrv, "debug": s.dsrv, "metrics": s.msrv}
					if mode == "grpc" {
						if s.srv != nil || s.grpcSrv == nil {
							return fmt.Errorf("expected the main listener to remain a gRPC server")
						}
						defer s.grpcSrv.Stop()
					} else {
						servers["proxy"] = s.srv
						if mode == "https" && (s.srv == nil || s.srv.TLSConfig == nil) {
							return fmt.Errorf("TLS configuration was lost")
						}
					}
					for name, srv := range servers {
						if srv == nil {
							return fmt.Errorf("%s server is nil", name)
						}
						actual := [4]time.Duration{srv.ReadHeaderTimeout, srv.ReadTimeout, srv.WriteTimeout, srv.IdleTimeout}
						if actual != tt.want {
							return fmt.Errorf("%s timeouts = %v, want %v", name, actual, tt.want)
						}
					}
					return nil
				},
			})
		}
	}
	for _, field := range []string{"readHeaderTimeout", "readTimeout", "writeTimeout", "idleTimeout"} {
		for _, value := range []string{"invalid", "30", "-1s", "999999999999999999999h"} {
			var cfg config.Server
			switch field {
			case "readHeaderTimeout":
				cfg.ReadHeaderTimeout = value
			case "readTimeout":
				cfg.ReadTimeout = value
			case "writeTimeout":
				cfg.WriteTimeout = value
			case "idleTimeout":
				cfg.IdleTimeout = value
			}
			tests = append(tests, test{
				name: "HTTP timeout validation/" + field + "/" + value,
				args: args{opts: []Option{WithServerConfig(cfg)}},
				checkFunc: func(got, _ Server, gotErr, _ error) error {
					if gotErr == nil || !strings.Contains(gotErr.Error(), "server."+field) || got != nil {
						return fmt.Errorf("NewServer() = %v, %v; want an error naming server.%s", got, gotErr, field)
					}
					return nil
				},
			})
		}
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, gotErr := NewServer(tt.args.opts...)
			if err := tt.checkFunc(got, tt.want, gotErr, tt.wantErr); err != nil {
				t.Errorf("NewServer() = %v, want %v, err: %v", got, tt.want, err)
			}
		})
	}
}

func Test_server_ListenAndServe(t *testing.T) {
	type fields struct {
		grpcSrv     *grpc.Server
		grpcHandler grpc.StreamHandler
		srv         *http.Server
		hcsrv       *http.Server
		dsrv        *http.Server
		msrv        *http.Server
		cfg         config.Server
	}
	type args struct {
		ctx context.Context
	}
	type test struct {
		name       string
		fields     fields
		args       args
		beforeFunc func() error
		checkFunc  func(*server, <-chan []error, error) error
		afterFunc  func() error
		want       error
	}

	checkSrvRunning := func(addr string) error {
		res, err := http.DefaultClient.Get(addr)
		if err != nil {
			return err
		}
		if res.StatusCode != 200 {
			return fmt.Errorf("Response status code invalid, %v", res.StatusCode)
		}
		return nil
	}
	checkGRPCSrvRunning := func(addr string) error {
		conn, err := grpc.Dial(addr, grpc.WithCodec(proxy.Codec()), grpc.WithInsecure())
		if err != nil {
			return err
		}
		defer conn.Close()

		return conn.Invoke(context.Background(), "/method/", new(emptypb.Empty), new(emptypb.Empty))
	}

	tests := []test{
		func() test {
			ctx, cancelFunc := context.WithCancel(context.Background())

			keyKey := "dummy_key"
			key := "../test/data/dummyServer.key"
			certKey := "dummy_cert"
			cert := "../test/data/dummyServer.crt"

			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(200)
				fmt.Fprintln(w, "Hello, client")
			})

			apiSrvPort := 9998
			hcSrvPort := 9999
			dSrvPort := 10000
			mSrvPort := 10001
			apiSrvAddr := fmt.Sprintf("http://127.0.0.1:%v", apiSrvPort)
			hcSrvAddr := fmt.Sprintf("http://127.0.0.1:%v", hcSrvPort)
			dSrvAddr := fmt.Sprintf("http://127.0.0.1:%v", dSrvPort)
			mSrvAddr := fmt.Sprintf("http://127.0.0.1:%v", mSrvPort)

			return test{
				name: "Test servers can start and stop",
				fields: fields{
					srv: func() *http.Server {
						s := &http.Server{
							Addr:    fmt.Sprintf(":%d", apiSrvPort),
							Handler: handler,
						}
						s.SetKeepAlivesEnabled(true)
						return s
					}(),
					hcsrv: func() *http.Server {
						s := &http.Server{
							Addr:    fmt.Sprintf(":%d", hcSrvPort),
							Handler: handler,
						}
						s.SetKeepAlivesEnabled(true)
						return s
					}(),
					dsrv: func() *http.Server {
						s := &http.Server{
							Addr:    fmt.Sprintf(":%d", dSrvPort),
							Handler: handler,
						}
						s.SetKeepAlivesEnabled(true)
						return s
					}(),
					msrv: func() *http.Server {
						s := &http.Server{
							Addr:    fmt.Sprintf(":%d", mSrvPort),
							Handler: handler,
						}
						s.SetKeepAlivesEnabled(true)
						return s
					}(),

					cfg: config.Server{
						Port: apiSrvPort,
						TLS: config.TLS{
							Enable:   false,
							CertPath: certKey,
							KeyPath:  keyKey,
						},
						HealthCheck: config.HealthCheck{
							Port: hcSrvPort,
						},
						Debug: config.Debug{
							Enable: true,
						},
						Metrics: config.Metrics{
							Port: mSrvPort,
						},
					},
				},
				args: args{
					ctx: ctx,
				},
				beforeFunc: func() error {
					if err := os.Setenv(keyKey, key); err != nil {
						return err
					}
					if err := os.Setenv(certKey, cert); err != nil {
						return err
					}
					return nil
				},
				checkFunc: func(s *server, got <-chan []error, want error) error {
					time.Sleep(time.Millisecond * 150)
					http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

					if err := checkSrvRunning(apiSrvAddr); err != nil {
						return fmt.Errorf("Server not running")
					}
					if err := checkSrvRunning(hcSrvAddr); err != nil {
						return fmt.Errorf("Health Check server not running")
					}
					if err := checkSrvRunning(dSrvAddr); err != nil {
						return fmt.Errorf("Debug server not running")
					}
					if err := checkSrvRunning(mSrvAddr); err != nil {
						return fmt.Errorf("Metrics server not running")
					}

					cancelFunc()
					time.Sleep(time.Millisecond * 250)

					if err := checkSrvRunning(apiSrvAddr); err == nil {
						return fmt.Errorf("Server running")
					}
					if err := checkSrvRunning(hcSrvAddr); err == nil {
						return fmt.Errorf("Health Check server running")
					}
					if err := checkSrvRunning(dSrvAddr); err == nil {
						return fmt.Errorf("Debug server running")
					}
					if err := checkSrvRunning(mSrvAddr); err == nil {
						return fmt.Errorf("Metrics server running")
					}

					return nil
				},
				afterFunc: func() error {
					cancelFunc()
					if err := os.Unsetenv(keyKey); err != nil {
						return err
					}
					if err := os.Unsetenv(certKey); err != nil {
						return nil
					}
					return nil
				},
			}
		}(),
		func() test {
			ctx, cancelFunc := context.WithCancel(context.Background())

			keyKey := "dummy_key"
			key := "../test/data/dummyServer.key"
			certKey := "dummy_cert"
			cert := "../test/data/dummyServer.crt"

			grpcHandler := func(srv interface{}, stream grpc.ServerStream) error {
				return stream.SendMsg(new(emptypb.Empty))
			}

			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(200)
				fmt.Fprintln(w, "Hello, client")
			})

			apiSrvPort := 9998
			hcSrvPort := 9999
			dSrvPort := 10000
			mSrvPort := 10001
			grpcSrvAddr := fmt.Sprintf("127.0.0.1:%v", apiSrvPort)
			hcSrvAddr := fmt.Sprintf("http://127.0.0.1:%v", hcSrvPort)
			dSrvAddr := fmt.Sprintf("http://127.0.0.1:%v", dSrvPort)
			mSrvAddr := fmt.Sprintf("http://127.0.0.1:%v", mSrvPort)

			grpcSrv := grpc.NewServer(
				grpc.CustomCodec(proxy.Codec()),
				grpc.UnknownServiceHandler(grpcHandler),
			)

			return test{
				name: "Test grpc server can start and stop",
				fields: fields{
					grpcSrv:     grpcSrv,
					grpcHandler: grpcHandler,
					hcsrv: func() *http.Server {
						s := &http.Server{
							Addr:    fmt.Sprintf(":%d", hcSrvPort),
							Handler: handler,
						}
						s.SetKeepAlivesEnabled(true)
						return s
					}(),
					dsrv: func() *http.Server {
						s := &http.Server{
							Addr:    fmt.Sprintf(":%d", dSrvPort),
							Handler: handler,
						}
						s.SetKeepAlivesEnabled(true)
						return s
					}(),
					msrv: func() *http.Server {
						s := &http.Server{
							Addr:    fmt.Sprintf(":%d", mSrvPort),
							Handler: handler,
						}
						s.SetKeepAlivesEnabled(true)
						return s
					}(),

					cfg: config.Server{
						Port: apiSrvPort,
						TLS: config.TLS{
							Enable:   false,
							CertPath: certKey,
							KeyPath:  keyKey,
						},
						HealthCheck: config.HealthCheck{
							Port: hcSrvPort,
						},
						Debug: config.Debug{
							Enable: true,
						},
						Metrics: config.Metrics{
							Port: mSrvPort,
						},
					},
				},
				args: args{
					ctx: ctx,
				},
				beforeFunc: func() error {
					if err := os.Setenv(keyKey, key); err != nil {
						return err
					}
					if err := os.Setenv(certKey, cert); err != nil {
						return err
					}
					return nil
				},
				checkFunc: func(s *server, got <-chan []error, want error) error {
					time.Sleep(time.Millisecond * 150)
					http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

					if err := checkGRPCSrvRunning(grpcSrvAddr); err != nil {
						return fmt.Errorf("GRPC Server not running, err: %s", err)
					}
					if err := checkSrvRunning(hcSrvAddr); err != nil {
						return fmt.Errorf("Health Check server not running")
					}
					if err := checkSrvRunning(dSrvAddr); err != nil {
						return fmt.Errorf("Debug server not running")
					}
					if err := checkSrvRunning(mSrvAddr); err != nil {
						return fmt.Errorf("Metrics server not running")
					}

					cancelFunc()
					time.Sleep(time.Millisecond * 250)

					if err := checkGRPCSrvRunning(grpcSrvAddr); err == nil {
						return fmt.Errorf("GRPC Server running, err: %s", err)
					}
					if err := checkSrvRunning(hcSrvAddr); err == nil {
						return fmt.Errorf("Health Check server running")
					}
					if err := checkSrvRunning(dSrvAddr); err == nil {
						return fmt.Errorf("Debug server running")
					}
					if err := checkSrvRunning(mSrvAddr); err == nil {
						return fmt.Errorf("Metrics server running")
					}

					return nil
				},
				afterFunc: func() error {
					cancelFunc()
					if err := os.Unsetenv(keyKey); err != nil {
						return err
					}
					if err := os.Unsetenv(certKey); err != nil {
						return nil
					}
					return nil
				},
			}
		}(),
		func() test {
			tc, err := NewTLSConfig(config.TLS{
				Enable:   true,
				CertPath: "../test/data/dummyServer.crt",
				KeyPath:  "../test/data/dummyServer.key",
			})
			if err != nil {
				panic(err)
			}

			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(200)
				fmt.Fprintln(w, "Hello, client")
			})

			apiSrvPort := 9998
			hcSrvPort := 9999
			dSrvPort := 10000
			mSrvPort := 10001
			apiSrvAddr := fmt.Sprintf("https://127.0.0.1:%v", apiSrvPort)
			hcSrvAddr := fmt.Sprintf("http://127.0.0.1:%v", hcSrvPort)
			dSrvAddr := fmt.Sprintf("http://127.0.0.1:%v", dSrvPort)
			mSrvAddr := fmt.Sprintf("http://127.0.0.1:%v", mSrvPort)

			return test{
				name: "Test HC server stop when api server stop",
				fields: fields{
					srv: func() *http.Server {
						srv := &http.Server{
							Addr:      fmt.Sprintf(":%d", apiSrvPort),
							Handler:   handler,
							TLSConfig: tc,
						}

						srv.SetKeepAlivesEnabled(true)
						return srv
					}(),
					hcsrv: func() *http.Server {
						srv := &http.Server{
							Addr:    fmt.Sprintf(":%d", hcSrvPort),
							Handler: handler,
						}

						srv.SetKeepAlivesEnabled(true)
						return srv
					}(),
					dsrv: func() *http.Server {
						srv := &http.Server{
							Addr:    fmt.Sprintf(":%d", dSrvPort),
							Handler: handler,
						}

						srv.SetKeepAlivesEnabled(true)
						return srv
					}(),
					msrv: func() *http.Server {
						srv := &http.Server{
							Addr:    fmt.Sprintf(":%d", mSrvPort),
							Handler: handler,
						}

						srv.SetKeepAlivesEnabled(true)
						return srv
					}(),
					cfg: config.Server{
						Port: apiSrvPort,
						TLS: config.TLS{
							Enable: true,
						},
						HealthCheck: config.HealthCheck{
							Port: hcSrvPort,
						},
						Debug: config.Debug{
							Enable: true,
						},
						Metrics: config.Metrics{
							Port: mSrvPort,
						},
					},
				},
				args: args{
					ctx: context.Background(),
				},
				checkFunc: func(s *server, got <-chan []error, want error) error {
					time.Sleep(time.Millisecond * 150)
					http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

					if err := checkSrvRunning(apiSrvAddr); err != nil {
						return fmt.Errorf("Server not running")
					}
					if err := checkSrvRunning(hcSrvAddr); err != nil {
						return fmt.Errorf("Health Check server not running")
					}
					if err := checkSrvRunning(dSrvAddr); err != nil {
						return fmt.Errorf("Debug server not running")
					}
					if err := checkSrvRunning(mSrvAddr); err != nil {
						return fmt.Errorf("Metrics server not running")
					}

					s.srv.Close()
					time.Sleep(time.Millisecond * 150)

					if err := checkSrvRunning(apiSrvAddr); err == nil {
						return fmt.Errorf("Server running")
					}
					if err := checkSrvRunning(hcSrvAddr); err == nil {
						return fmt.Errorf("Health Check server running")
					}
					if err := checkSrvRunning(dSrvAddr); err == nil {
						return fmt.Errorf("Debug server running")
					}
					if err := checkSrvRunning(mSrvAddr); err == nil {
						return fmt.Errorf("Metrics server not running")
					}

					return nil
				},
			}
		}(),
		func() test {
			ctx, cancel := context.WithCancel(context.Background())

			key := "../test/data/dummyServer.key"
			cert := "../test/data/dummyServer.crt"

			grpcHandler := func(srv interface{}, stream grpc.ServerStream) error {
				return stream.SendMsg(new(emptypb.Empty))
			}

			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(200)
				fmt.Fprintln(w, "Hello, client")
			})

			apiSrvPort := 9998
			hcSrvPort := 9999
			dSrvPort := 10000
			mSrvPort := 10001
			grpcSrvAddr := fmt.Sprintf("127.0.0.1:%v", apiSrvPort)
			hcSrvAddr := fmt.Sprintf("http://127.0.0.1:%v", hcSrvPort)
			dSrvAddr := fmt.Sprintf("http://127.0.0.1:%v", dSrvPort)
			mSrvAddr := fmt.Sprintf("http://127.0.0.1:%v", mSrvPort)

			grpcSrv := grpc.NewServer(
				grpc.CustomCodec(proxy.Codec()),
				grpc.UnknownServiceHandler(grpcHandler),
			)

			return test{
				name: "Test HC server stop when GRPC server stop",
				fields: fields{
					grpcSrv:     grpcSrv,
					grpcHandler: grpcHandler,
					hcsrv: func() *http.Server {
						srv := &http.Server{
							Addr:    fmt.Sprintf(":%d", hcSrvPort),
							Handler: handler,
						}

						srv.SetKeepAlivesEnabled(true)
						return srv
					}(),
					dsrv: func() *http.Server {
						srv := &http.Server{
							Addr:    fmt.Sprintf(":%d", dSrvPort),
							Handler: handler,
						}

						srv.SetKeepAlivesEnabled(true)
						return srv
					}(),
					msrv: func() *http.Server {
						srv := &http.Server{
							Addr:    fmt.Sprintf(":%d", mSrvPort),
							Handler: handler,
						}

						srv.SetKeepAlivesEnabled(true)
						return srv
					}(),
					cfg: config.Server{
						Port: apiSrvPort,
						TLS: config.TLS{
							Enable:   false,
							CertPath: cert,
							KeyPath:  key,
						},
						HealthCheck: config.HealthCheck{
							Port: hcSrvPort,
						},
						Debug: config.Debug{
							Enable: true,
						},
						Metrics: config.Metrics{
							Port: mSrvPort,
						},
					},
				},
				args: args{
					ctx: ctx,
				},
				checkFunc: func(s *server, got <-chan []error, want error) error {
					time.Sleep(time.Millisecond * 150)
					http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

					if err := checkGRPCSrvRunning(grpcSrvAddr); err != nil {
						return fmt.Errorf("Server not running")
					}
					if err := checkSrvRunning(hcSrvAddr); err != nil {
						return fmt.Errorf("Health Check server not running")
					}
					if err := checkSrvRunning(dSrvAddr); err != nil {
						return fmt.Errorf("Debug server not running")
					}
					if err := checkSrvRunning(mSrvAddr); err != nil {
						return fmt.Errorf("Metrics server not running")
					}

					s.grpcSrv.Stop()
					time.Sleep(time.Millisecond * 150)

					if err := checkGRPCSrvRunning(grpcSrvAddr); err == nil {
						return fmt.Errorf("Server running")
					}
					if err := checkSrvRunning(hcSrvAddr); err == nil {
						return fmt.Errorf("Health Check server running")
					}
					if err := checkSrvRunning(dSrvAddr); err == nil {
						return fmt.Errorf("Debug server running")
					}
					if err := checkSrvRunning(mSrvAddr); err == nil {
						return fmt.Errorf("Metrics server not running")
					}

					return nil
				},
				afterFunc: func() error {
					cancel()
					return nil
				},
			}
		}(),

		func() test {
			tc, err := NewTLSConfig(config.TLS{
				Enable:   true,
				CertPath: "../test/data/dummyServer.crt",
				KeyPath:  "../test/data/dummyServer.key",
			})
			if err != nil {
				panic(err)
			}

			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(200)
				fmt.Fprintln(w, "Hello, client")
			})

			apiSrvPort := 9998
			hcSrvPort := 9999
			dSrvPort := 10000
			mSrvPort := 10001
			apiSrvAddr := fmt.Sprintf("https://127.0.0.1:%v", apiSrvPort)
			hcSrvAddr := fmt.Sprintf("http://127.0.0.1:%v", hcSrvPort)
			dSrvAddr := fmt.Sprintf("http://127.0.0.1:%v", dSrvPort)
			mSrvAddr := fmt.Sprintf("http://127.0.0.1:%v", mSrvPort)

			return test{
				name: "Test api server stop when HC server stop",
				fields: fields{
					srv: func() *http.Server {
						srv := &http.Server{
							Addr:      fmt.Sprintf(":%d", apiSrvPort),
							Handler:   handler,
							TLSConfig: tc,
						}

						srv.SetKeepAlivesEnabled(true)
						return srv
					}(),
					hcsrv: func() *http.Server {
						srv := &http.Server{
							Addr:    fmt.Sprintf(":%d", hcSrvPort),
							Handler: handler,
						}

						srv.SetKeepAlivesEnabled(true)
						return srv
					}(),
					dsrv: func() *http.Server {
						srv := &http.Server{
							Addr:    fmt.Sprintf(":%d", dSrvPort),
							Handler: handler,
						}

						srv.SetKeepAlivesEnabled(true)
						return srv
					}(),
					msrv: func() *http.Server {
						srv := &http.Server{
							Addr:    fmt.Sprintf(":%d", mSrvPort),
							Handler: handler,
						}

						srv.SetKeepAlivesEnabled(true)
						return srv
					}(),
					cfg: config.Server{
						Port: apiSrvPort,
						TLS: config.TLS{
							Enable: true,
						},
						HealthCheck: config.HealthCheck{
							Port: hcSrvPort,
						},
						Debug: config.Debug{
							Enable: true,
						},
						Metrics: config.Metrics{
							Port: mSrvPort,
						},
					},
				},
				args: args{
					ctx: context.Background(),
				},
				checkFunc: func(s *server, got <-chan []error, want error) error {
					time.Sleep(time.Millisecond * 150)
					http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

					if err := checkSrvRunning(apiSrvAddr); err != nil {
						return fmt.Errorf("Server not running")
					}
					if err := checkSrvRunning(hcSrvAddr); err != nil {
						return fmt.Errorf("Health Check server not running")
					}
					if err := checkSrvRunning(dSrvAddr); err != nil {
						return fmt.Errorf("Debug server not running")
					}
					if err := checkSrvRunning(mSrvAddr); err != nil {
						return fmt.Errorf("Metrics server not running")
					}

					s.hcsrv.Close()
					time.Sleep(time.Millisecond * 150)

					if err := checkSrvRunning(apiSrvAddr); err == nil {
						return fmt.Errorf("Server running")
					}
					if err := checkSrvRunning(hcSrvAddr); err == nil {
						return fmt.Errorf("Health Check server running")
					}
					if err := checkSrvRunning(dSrvAddr); err == nil {
						return fmt.Errorf("Debug server running")
					}
					if err := checkSrvRunning(mSrvAddr); err == nil {
						return fmt.Errorf("Metrics server not running")
					}

					return nil
				},
			}
		}(),
		func() test {
			tc, err := NewTLSConfig(config.TLS{
				Enable:   true,
				CertPath: "../test/data/dummyServer.crt",
				KeyPath:  "../test/data/dummyServer.key",
			})
			if err != nil {
				panic(err)
			}

			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(200)
				fmt.Fprintln(w, "Hello, client")
			})

			apiSrvPort := 9998
			hcSrvPort := 9999
			dSrvPort := 10000
			mSrvPort := 10001
			apiSrvAddr := fmt.Sprintf("https://127.0.0.1:%v", apiSrvPort)
			hcSrvAddr := fmt.Sprintf("http://127.0.0.1:%v", hcSrvPort)
			dSrvAddr := fmt.Sprintf("http://127.0.0.1:%v", dSrvPort)
			mSrvAddr := fmt.Sprintf("http://127.0.0.1:%v", mSrvPort)

			return test{
				name: "Test other servers stop when debug server stops",
				fields: fields{
					srv: func() *http.Server {
						srv := &http.Server{
							Addr:      fmt.Sprintf(":%d", apiSrvPort),
							Handler:   handler,
							TLSConfig: tc,
						}

						srv.SetKeepAlivesEnabled(true)
						return srv
					}(),
					hcsrv: func() *http.Server {
						srv := &http.Server{
							Addr:    fmt.Sprintf(":%d", hcSrvPort),
							Handler: handler,
						}

						srv.SetKeepAlivesEnabled(true)
						return srv
					}(),
					dsrv: func() *http.Server {
						srv := &http.Server{
							Addr:    fmt.Sprintf(":%d", dSrvPort),
							Handler: handler,
						}

						srv.SetKeepAlivesEnabled(true)
						return srv
					}(),
					msrv: func() *http.Server {
						srv := &http.Server{
							Addr:    fmt.Sprintf(":%d", mSrvPort),
							Handler: handler,
						}

						srv.SetKeepAlivesEnabled(true)
						return srv
					}(),
					cfg: config.Server{
						Port: apiSrvPort,
						TLS: config.TLS{
							Enable: true,
						},
						HealthCheck: config.HealthCheck{
							Port: hcSrvPort,
						},
						Debug: config.Debug{
							Enable: true,
						},
						Metrics: config.Metrics{
							Port: mSrvPort,
						},
					},
				},
				args: args{
					ctx: context.Background(),
				},
				checkFunc: func(s *server, got <-chan []error, want error) error {
					time.Sleep(time.Millisecond * 150)
					http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

					if err := checkSrvRunning(apiSrvAddr); err != nil {
						return fmt.Errorf("Server not running")
					}
					if err := checkSrvRunning(hcSrvAddr); err != nil {
						return fmt.Errorf("Health Check server not running")
					}
					if err := checkSrvRunning(dSrvAddr); err != nil {
						return fmt.Errorf("Debug server not running")
					}
					if err := checkSrvRunning(mSrvAddr); err != nil {
						return fmt.Errorf("Metrics server not running")
					}

					s.dsrv.Close()
					time.Sleep(time.Millisecond * 150)

					if err := checkSrvRunning(apiSrvAddr); err == nil {
						return fmt.Errorf("Server running")
					}
					if err := checkSrvRunning(hcSrvAddr); err == nil {
						return fmt.Errorf("Health Check server running")
					}
					if err := checkSrvRunning(dSrvAddr); err == nil {
						return fmt.Errorf("Debug server running")
					}
					if err := checkSrvRunning(mSrvAddr); err == nil {
						return fmt.Errorf("Metrics server not running")
					}

					return nil
				},
			}
		}(),
		func() test {
			ctx, cancelFunc := context.WithCancel(context.Background())
			tc, err := NewTLSConfig(config.TLS{
				Enable:   true,
				CertPath: "../test/data/dummyServer.crt",
				KeyPath:  "../test/data/dummyServer.key",
			})
			if err != nil {
				panic(err)
			}

			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(200)
				fmt.Fprintln(w, "Hello, client")
			})

			apiSrvPort := 9998
			hcSrvPort := 9999
			dSrvPort := 10000
			mSrvPort := 10001
			apiSrvAddr := fmt.Sprintf("https://127.0.0.1:%v", apiSrvPort)
			hcSrvAddr := fmt.Sprintf("http://127.0.0.1:%v", hcSrvPort)
			dSrvAddr := fmt.Sprintf("http://127.0.0.1:%v", dSrvPort)
			mSrvAddr := fmt.Sprintf("http://127.0.0.1:%v", mSrvPort)

			return test{
				name: "Test debug server disable",
				fields: fields{
					srv: func() *http.Server {
						srv := &http.Server{
							Addr:      fmt.Sprintf(":%d", apiSrvPort),
							Handler:   handler,
							TLSConfig: tc,
						}

						srv.SetKeepAlivesEnabled(true)
						return srv
					}(),
					hcsrv: func() *http.Server {
						srv := &http.Server{
							Addr:    fmt.Sprintf(":%d", hcSrvPort),
							Handler: handler,
						}

						srv.SetKeepAlivesEnabled(true)
						return srv
					}(),
					dsrv: func() *http.Server {
						srv := &http.Server{
							Addr:    fmt.Sprintf(":%d", dSrvPort),
							Handler: handler,
						}

						srv.SetKeepAlivesEnabled(true)
						return srv
					}(),
					msrv: func() *http.Server {
						srv := &http.Server{
							Addr:    fmt.Sprintf(":%d", mSrvPort),
							Handler: handler,
						}

						srv.SetKeepAlivesEnabled(true)
						return srv
					}(),
					cfg: config.Server{
						Port: apiSrvPort,
						TLS: config.TLS{
							Enable: true,
						},
						HealthCheck: config.HealthCheck{
							Port: hcSrvPort,
						},
					},
				},
				args: args{
					ctx: ctx,
				},
				checkFunc: func(s *server, got <-chan []error, want error) error {
					time.Sleep(time.Millisecond * 150)
					http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

					if err := checkSrvRunning(apiSrvAddr); err != nil {
						return fmt.Errorf("Server not running")
					}
					if err := checkSrvRunning(hcSrvAddr); err != nil {
						return fmt.Errorf("Health Check server not running")
					}
					if err := checkSrvRunning(dSrvAddr); err == nil {
						return fmt.Errorf("Debug server running")
					}
					if err := checkSrvRunning(mSrvAddr); err == nil {
						return fmt.Errorf("Metrics server running")
					}

					cancelFunc()
					time.Sleep(time.Millisecond * 150)

					if err := checkSrvRunning(apiSrvAddr); err == nil {
						return fmt.Errorf("Server running")
					}
					if err := checkSrvRunning(hcSrvAddr); err == nil {
						return fmt.Errorf("Health Check server running")
					}
					if err := checkSrvRunning(dSrvAddr); err == nil {
						return fmt.Errorf("Debug server running")
					}
					if err := checkSrvRunning(mSrvAddr); err == nil {
						return fmt.Errorf("Metrics server running")
					}

					return nil
				},
			}
		}(),
		func() test {
			ctx, cancelFunc := context.WithCancel(context.Background())
			tc, err := NewTLSConfig(config.TLS{
				Enable:   true,
				CertPath: "../test/data/dummyServer.crt",
				KeyPath:  "../test/data/dummyServer.key",
			})
			if err != nil {
				panic(err)
			}

			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(200)
				fmt.Fprintln(w, "Hello, client")
			})

			apiSrvPort := 9998
			hcSrvPort := 9999
			dSrvPort := 10000
			mSrvPort := 10001
			apiSrvAddr := fmt.Sprintf("https://127.0.0.1:%v", apiSrvPort)
			hcSrvAddr := fmt.Sprintf("http://127.0.0.1:%v", hcSrvPort)
			dSrvAddr := fmt.Sprintf("http://127.0.0.1:%v", dSrvPort)
			mSrvAddr := fmt.Sprintf("http://127.0.0.1:%v", mSrvPort)

			return test{
				name: "Test health check server disable",
				fields: fields{
					srv: func() *http.Server {
						srv := &http.Server{
							Addr:      fmt.Sprintf(":%d", apiSrvPort),
							Handler:   handler,
							TLSConfig: tc,
						}

						srv.SetKeepAlivesEnabled(true)
						return srv
					}(),
					hcsrv: func() *http.Server {
						srv := &http.Server{
							Addr:    fmt.Sprintf(":%d", hcSrvPort),
							Handler: handler,
						}

						srv.SetKeepAlivesEnabled(true)
						return srv
					}(),
					dsrv: func() *http.Server {
						srv := &http.Server{
							Addr:    fmt.Sprintf(":%d", dSrvPort),
							Handler: handler,
						}

						srv.SetKeepAlivesEnabled(true)
						return srv
					}(),
					msrv: func() *http.Server {
						srv := &http.Server{
							Addr:    fmt.Sprintf(":%d", mSrvPort),
							Handler: handler,
						}

						srv.SetKeepAlivesEnabled(true)
						return srv
					}(),
					cfg: config.Server{
						Port: apiSrvPort,
						TLS: config.TLS{
							Enable: true,
						},
						HealthCheck: config.HealthCheck{
							// Port:     hcSrvPort,
						},
						Debug: config.Debug{
							Enable: true,
						},
						Metrics: config.Metrics{
							Port: mSrvPort,
						},
					},
				},
				args: args{
					ctx: ctx,
				},
				checkFunc: func(s *server, got <-chan []error, want error) error {
					time.Sleep(time.Millisecond * 150)
					http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

					if err := checkSrvRunning(apiSrvAddr); err != nil {
						return fmt.Errorf("Server not running")
					}
					if err := checkSrvRunning(hcSrvAddr); err == nil {
						return fmt.Errorf("Health Check server running")
					}
					if err := checkSrvRunning(dSrvAddr); err != nil {
						return fmt.Errorf("Debug server not running")
					}
					if err := checkSrvRunning(mSrvAddr); err != nil {
						return fmt.Errorf("Metrics server not running")
					}

					cancelFunc()
					time.Sleep(time.Millisecond * 150)

					if err := checkSrvRunning(apiSrvAddr); err == nil {
						return fmt.Errorf("Server running")
					}
					if err := checkSrvRunning(hcSrvAddr); err == nil {
						return fmt.Errorf("Health Check server running")
					}
					if err := checkSrvRunning(dSrvAddr); err == nil {
						return fmt.Errorf("Debug server running")
					}
					if err := checkSrvRunning(mSrvAddr); err == nil {
						return fmt.Errorf("Metrics server not running")
					}

					return nil
				},
			}
		}(),
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.afterFunc != nil {
				defer func() {
					if err := tt.afterFunc(); err != nil {
						t.Errorf("afterFunc error, error: %v", err)
						return
					}
				}()
			}
			if tt.beforeFunc != nil {
				if err := tt.beforeFunc(); err != nil {
					t.Errorf("beforeFunc error, error: %v", err)
					return
				}
			}

			s := &server{
				srv:         tt.fields.srv,
				grpcSrv:     tt.fields.grpcSrv,
				grpcHandler: tt.fields.grpcHandler,
				hcsrv:       tt.fields.hcsrv,
				dsrv:        tt.fields.dsrv,
				msrv:        tt.fields.msrv,
				cfg:         tt.fields.cfg,
			}

			e := s.ListenAndServe(tt.args.ctx)
			if err := tt.checkFunc(s, e, tt.want); err != nil {
				t.Errorf("server.listenAndServe() Error = %v", err)
			}
		})
	}
}

func TestServerHTTPTimeoutConnections(t *testing.T) {
	for _, scenario := range []string{"incomplete headers", "read timeout fallback", "unfinished rejected body"} {
		t.Run(scenario, func(t *testing.T) {
			var calls atomic.Int32
			h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				w.WriteHeader(http.StatusUnauthorized)
			})
			cfg := config.Server{
				HealthCheck: config.HealthCheck{Port: 8081, Endpoint: "/healthz"},
				Debug:       config.Debug{Enable: true, Port: 8082},
				Metrics:     config.Metrics{Port: 8083},
			}
			if scenario == "incomplete headers" {
				cfg.ReadHeaderTimeout = "100ms"
			} else {
				cfg.ReadTimeout = "100ms"
			}
			created, err := NewServer(WithServerConfig(cfg), WithRestHandler(h), WithDebugHandler(h))
			if err != nil {
				t.Fatal(err)
			}
			s := created.(*server)
			for name, srv := range map[string]*http.Server{"proxy": s.srv, "health": s.hcsrv, "debug": s.dsrv, "metrics": s.msrv} {
				t.Run(name, func(t *testing.T) {
					ts := httptest.NewUnstartedServer(srv.Handler)
					ts.Config = srv
					ts.Start()
					t.Cleanup(ts.Close)
					conn, err := net.DialTimeout("tcp", ts.Listener.Addr().String(), 5*time.Second)
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() { conn.Close() })
					if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
						t.Fatal(err)
					}
					request := "GET / HTTP/1.1\r\nHost: localhost\r\n"
					if scenario == "unfinished rejected body" {
						// No body is sent. The server must bound post-handler body draining.
						request = "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 8\r\n\r\n"
					}
					if _, err := fmt.Fprint(conn, request); err != nil {
						t.Fatal(err)
					}
					if _, err := io.ReadAll(conn); err != nil {
						t.Fatalf("server did not close the incomplete request within its timeout: %v", err)
					}
				})
			}
			if scenario != "unfinished rejected body" && calls.Load() != 0 {
				t.Fatal("an incomplete header reached the request handler")
			}
		})
	}
}

func Test_server_mShutdown(t *testing.T) {
	type fields struct {
		srv        *http.Server
		srvRunning bool
		msrv       *http.Server
		mRunning   bool
		cfg        config.Server
		sdd        time.Duration
		sdt        time.Duration
	}
	type args struct {
		ctx context.Context
	}
	type test struct {
		name       string
		fields     fields
		args       args
		beforeFunc func() error
		checkFunc  func(*server, error, error) error
		afterFunc  func() error
		want       error
	}
	tests := []test{
		func() test {
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(200)
			})
			msrv := httptest.NewServer(handler)

			return test{
				name: "mShutdown works",
				fields: fields{
					msrv: msrv.Config,
					sdt:  time.Minute,
				},
				args: args{
					ctx: context.Background(),
				},
				checkFunc: func(s *server, got, want error) error {
					return got
				},
				afterFunc: func() error {
					msrv.Close()
					return nil
				},
			}
		}(),
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.afterFunc != nil {
				defer func() {
					if err := tt.afterFunc(); err != nil {
						t.Errorf("afterFunc error, error: %v", err)
						return
					}
				}()
			}
			if tt.beforeFunc != nil {
				if err := tt.beforeFunc(); err != nil {
					t.Errorf("beforeFunc error, error: %v", err)
					return
				}
			}

			s := &server{
				srv:        tt.fields.srv,
				srvRunning: tt.fields.srvRunning,
				msrv:       tt.fields.msrv,
				mRunning:   tt.fields.mRunning,
				cfg:        tt.fields.cfg,
				sdd:        tt.fields.sdd,
				sdt:        tt.fields.sdt,
			}
			e := s.mShutdown(tt.args.ctx)
			if err := tt.checkFunc(s, e, tt.want); err != nil {
				t.Errorf("server.listenAndServe() Error = %v", err)
			}
		})
	}
}

func Test_server_hcShutdown(t *testing.T) {
	type fields struct {
		srv        *http.Server
		srvRunning bool
		hcsrv      *http.Server
		hcRunning  bool
		cfg        config.Server
		sdd        time.Duration
		sdt        time.Duration
	}
	type args struct {
		ctx context.Context
	}
	type test struct {
		name       string
		fields     fields
		args       args
		beforeFunc func() error
		checkFunc  func(*server, error, error) error
		afterFunc  func() error
		want       error
	}
	tests := []test{
		func() test {
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(200)
			})
			hcsrv := httptest.NewServer(handler)

			return test{
				name: "hcShutdown works",
				fields: fields{
					hcsrv: hcsrv.Config,
					sdt:   time.Minute,
				},
				args: args{
					ctx: context.Background(),
				},
				checkFunc: func(s *server, got, want error) error {
					return got
				},
				afterFunc: func() error {
					hcsrv.Close()
					return nil
				},
			}
		}(),
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.afterFunc != nil {
				defer func() {
					if err := tt.afterFunc(); err != nil {
						t.Errorf("afterFunc error, error: %v", err)
						return
					}
				}()
			}
			if tt.beforeFunc != nil {
				if err := tt.beforeFunc(); err != nil {
					t.Errorf("beforeFunc error, error: %v", err)
					return
				}
			}

			s := &server{
				srv:        tt.fields.srv,
				srvRunning: tt.fields.srvRunning,
				hcsrv:      tt.fields.hcsrv,
				hcRunning:  tt.fields.hcRunning,
				cfg:        tt.fields.cfg,
				sdd:        tt.fields.sdd,
				sdt:        tt.fields.sdt,
			}
			e := s.hcShutdown(tt.args.ctx)
			if err := tt.checkFunc(s, e, tt.want); err != nil {
				t.Errorf("server.listenAndServe() Error = %v", err)
			}
		})
	}
}

func Test_server_apiShutdown(t *testing.T) {
	type fields struct {
		srv        *http.Server
		srvRunning bool
		hcsrv      *http.Server
		hcRunning  bool
		cfg        config.Server
		sdd        time.Duration
		sdt        time.Duration
	}
	type args struct {
		ctx context.Context
	}
	type test struct {
		name       string
		fields     fields
		args       args
		beforeFunc func() error
		checkFunc  func(*server, error, error) error
		afterFunc  func() error
		want       error
	}
	tests := []test{
		func() test {
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(200)
			})
			apisrv := httptest.NewServer(handler)

			return test{
				name: "apiShutdown works",
				fields: fields{
					srv: apisrv.Config,
					sdt: time.Minute,
				},
				args: args{
					ctx: context.Background(),
				},
				checkFunc: func(s *server, got, want error) error {
					return got
				},
				afterFunc: func() error {
					apisrv.Close()
					return nil
				},
			}
		}(),
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.afterFunc != nil {
				defer func() {
					if err := tt.afterFunc(); err != nil {
						t.Errorf("afterFunc error, error: %v", err)
						return
					}
				}()
			}
			if tt.beforeFunc != nil {
				if err := tt.beforeFunc(); err != nil {
					t.Errorf("beforeFunc error, error: %v", err)
					return
				}
			}

			s := &server{
				srv:        tt.fields.srv,
				srvRunning: tt.fields.srvRunning,
				hcsrv:      tt.fields.hcsrv,
				hcRunning:  tt.fields.hcRunning,
				cfg:        tt.fields.cfg,
				sdd:        tt.fields.sdd,
				sdt:        tt.fields.sdt,
			}
			e := s.apiShutdown(tt.args.ctx)
			if err := tt.checkFunc(s, e, tt.want); err != nil {
				t.Errorf("server.listenAndServe() Error = %v", err)
			}
		})
	}
}

func Test_server_grpcShutdown(t *testing.T) {
	type fields struct {
		srvRunning bool
		grpcSrv    *grpc.Server
		grpcCloser io.Closer
		hcsrv      *http.Server
		hcRunning  bool
		cfg        config.Server
		sdd        time.Duration
		sdt        time.Duration
	}
	type args struct{}
	type test struct {
		name       string
		fields     fields
		args       args
		beforeFunc func() error
		checkFunc  func(*server) error
		afterFunc  func() error
	}

	checkGRPCSrvRunning := func(addr string) error {
		conn, err := grpc.Dial(addr, grpc.WithCodec(proxy.Codec()), grpc.WithInsecure())
		if err != nil {
			return err
		}
		defer conn.Close()

		return conn.Invoke(context.Background(), "/method/", new(emptypb.Empty), new(emptypb.Empty))
	}

	tests := []test{
		func() test {
			apiSrvPort := 9998
			grpcHandler := func(srv interface{}, stream grpc.ServerStream) error {
				return stream.SendMsg(new(emptypb.Empty))
			}
			grpcSrvAddr := fmt.Sprintf("127.0.0.1:%v", apiSrvPort)

			grpcSrv := grpc.NewServer(
				grpc.CustomCodec(proxy.Codec()),
				grpc.UnknownServiceHandler(grpcHandler),
			)
			var mux sync.Mutex
			running := true

			return test{
				name: "grpcShutdown works",
				fields: fields{
					grpcSrv:    grpcSrv,
					grpcCloser: ioutil.NopCloser(nil),
				},
				beforeFunc: func() error {
					l, err := net.Listen("tcp", ":9998")
					if err != nil {
						return err
					}
					go func() {
						grpcSrv.Serve(l)

						mux.Lock()
						running = false
						mux.Unlock()
					}()
					return nil
				},
				checkFunc: func(s *server) error {
					if err := checkGRPCSrvRunning(grpcSrvAddr); err == nil {
						return errors.New("server running")
					}

					mux.Lock()
					defer mux.Unlock()
					if running {
						return errors.New("server running")
					}
					return nil
				},
				afterFunc: func() error {
					return nil
				},
			}
		}(),
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.afterFunc != nil {
				defer func() {
					if err := tt.afterFunc(); err != nil {
						t.Errorf("afterFunc error, error: %v", err)
						return
					}
				}()
			}
			if tt.beforeFunc != nil {
				if err := tt.beforeFunc(); err != nil {
					t.Errorf("beforeFunc error, error: %v", err)
					return
				}
			}

			s := &server{
				grpcSrv:    tt.fields.grpcSrv,
				grpcCloser: tt.fields.grpcCloser,
				srvRunning: tt.fields.srvRunning,
				hcsrv:      tt.fields.hcsrv,
				hcRunning:  tt.fields.hcRunning,
				cfg:        tt.fields.cfg,
				sdd:        tt.fields.sdd,
				sdt:        tt.fields.sdt,
			}
			s.grpcShutdown()
			if err := tt.checkFunc(s); err != nil {
				t.Errorf("server.listenAndServe() Error = %v", err)
			}
		})
	}
}

func Test_server_createMetricsServiceMux(t *testing.T) {
	type args struct {
		pattern string
	}
	type test struct {
		name       string
		args       args
		beforeFunc func() error
		checkFunc  func(*http.ServeMux) error
		afterFunc  func() error
	}
	tests := []test{
		func() test {
			return test{
				name: "Test create server mux",
				args: args{
					pattern: "/metrics",
				},
				checkFunc: func(got *http.ServeMux) error {
					if got == nil {
						return fmt.Errorf("serveMux is empty")
					}
					return nil
				},
			}
		}(),
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.afterFunc != nil {
				defer func() {
					if err := tt.afterFunc(); err != nil {
						t.Errorf("afterFunc error, error: %v", err)
						return
					}
				}()
			}
			if tt.beforeFunc != nil {
				if err := tt.beforeFunc(); err != nil {
					t.Errorf("beforeFunc error, error: %v", err)
					return
				}
			}

			got := createMetricsServiceMux(tt.args.pattern)
			if err := tt.checkFunc(got); err != nil {
				t.Errorf("server.listenAndServeAPI() Error = %v", err)
			}
		})
	}
}

func Test_server_createHealthCheckServiceMux(t *testing.T) {
	type args struct {
		pattern string
	}
	type test struct {
		name       string
		args       args
		beforeFunc func() error
		checkFunc  func(*http.ServeMux) error
		afterFunc  func() error
	}
	tests := []test{
		func() test {
			return test{
				name: "Test create server mux",
				args: args{
					pattern: "/healthz",
				},
				checkFunc: func(got *http.ServeMux) error {
					if got == nil {
						return fmt.Errorf("serveMux is empty")
					}
					return nil
				},
			}
		}(),
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.afterFunc != nil {
				defer func() {
					if err := tt.afterFunc(); err != nil {
						t.Errorf("afterFunc error, error: %v", err)
						return
					}
				}()
			}
			if tt.beforeFunc != nil {
				if err := tt.beforeFunc(); err != nil {
					t.Errorf("beforeFunc error, error: %v", err)
					return
				}
			}

			got := createHealthCheckServiceMux(tt.args.pattern)
			if err := tt.checkFunc(got); err != nil {
				t.Errorf("server.listenAndServeAPI() Error = %v", err)
			}
		})
	}
}

func Test_server_handleHealthCheckRequest(t *testing.T) {
	type args struct {
		rw http.ResponseWriter
		r  *http.Request
	}
	type test struct {
		name       string
		args       args
		beforeFunc func() error
		checkFunc  func() error
		afterFunc  func() error
	}
	tests := []test{
		func() test {
			rw := httptest.NewRecorder()

			return test{
				name: "Test handle HTTP GET request health check request",
				args: args{
					rw: rw,
					r:  httptest.NewRequest(http.MethodGet, "/", nil),
				},
				checkFunc: func() error {
					result := rw.Result()
					if header := result.StatusCode; header != http.StatusOK {
						return fmt.Errorf("Header is not correct, got: %v", header)
					}
					if contentType := rw.Header().Get("Content-Type"); contentType != "text/plain;charset=UTF-8" {
						return fmt.Errorf("Content type is not correct, got: %v", contentType)
					}
					return nil
				},
			}
		}(),
		func() test {
			rw := &ResponseWriterMock{
				header: http.Header{},
				writeFunc: func(buf []byte) (int, error) {
					return len(buf), fmt.Errorf("Test error")
				},
			}

			return test{
				name: "Test handle response error",
				args: args{
					rw: rw,
					r:  httptest.NewRequest(http.MethodGet, "/", nil),
				},
				checkFunc: func() error {
					// Confirm if the above does not terminate
					return nil
				},
			}
		}(),
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.afterFunc != nil {
				defer func() {
					if err := tt.afterFunc(); err != nil {
						t.Errorf("afterFunc error, error: %v", err)
						return
					}
				}()
			}
			if tt.beforeFunc != nil {
				if err := tt.beforeFunc(); err != nil {
					t.Errorf("beforeFunc error, error: %v", err)
					return
				}
			}

			handleHealthCheckRequest(tt.args.rw, tt.args.r)
			if err := tt.checkFunc(); err != nil {
				t.Errorf("error: %v", err)
			}
		})
	}
}

func Test_server_listenAndServeAPI(t *testing.T) {
	type fields struct {
		srv   *http.Server
		hcsrv *http.Server
		cfg   config.Server
	}
	type test struct {
		name       string
		fields     fields
		beforeFunc func() error
		checkFunc  func(*server, error) error
		afterFunc  func() error
		want       error
	}
	tests := []test{
		{
			name: "Test HTTP server startup",
			fields: fields{
				srv: &http.Server{
					Handler: func() http.Handler {
						return nil
					}(),
					Addr: fmt.Sprintf(":%d", 9999),
				},
				cfg: config.Server{
					Port: 9999,
					TLS: config.TLS{
						Enable: false,
					},
				},
			},
			checkFunc: func(s *server, want error) error {
				// listenAndServeAPI function is blocking, so we need to set timer to shutdown the process
				go func() {
					time.Sleep(time.Second * 1)
					if err := s.srv.Shutdown(context.Background()); err != nil {
						panic(err)
					}
				}()

				got := s.listenAndServeAPI()

				if got != want {
					return fmt.Errorf("got:\t%v\nwant:\t%v", got, want)
				}
				return nil
			},
			want: http.ErrServerClosed,
		},
		func() test {
			tc, err := NewTLSConfig(config.TLS{
				Enable:   true,
				CertPath: "../test/data/dummyServer.crt",
				KeyPath:  "../test/data/dummyServer.key",
			})
			if err != nil {
				panic(err)
			}
			return test{
				name: "Test HTTPS server startup",
				fields: fields{
					srv: &http.Server{
						Handler: func() http.Handler {
							return nil
						}(),
						Addr:      fmt.Sprintf(":%d", 9999),
						TLSConfig: tc,
					},
					cfg: config.Server{
						Port: 9999,
						TLS: config.TLS{
							Enable: true,
						},
					},
				},
				checkFunc: func(s *server, want error) error {
					// listenAndServeAPI function is blocking, so we need to set timer to shutdown the process
					go func() {
						time.Sleep(time.Second * 1)
						if err := s.srv.Shutdown(context.Background()); err != nil {
							panic(err)
						}
					}()

					got := s.listenAndServeAPI()

					if got != want {
						return fmt.Errorf("got:\t%v\nwant:\t%v", got, want)
					}
					return nil
				},
				want: http.ErrServerClosed,
			}
		}(),
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.afterFunc != nil {
				defer func() {
					if err := tt.afterFunc(); err != nil {
						t.Errorf("afterFunc error, error: %v", err)
						return
					}
				}()
			}
			if tt.beforeFunc != nil {
				if err := tt.beforeFunc(); err != nil {
					t.Errorf("beforeFunc error, error: %v", err)
					return
				}
			}

			if err := tt.checkFunc(&server{
				srv:   tt.fields.srv,
				hcsrv: tt.fields.hcsrv,
				cfg:   tt.fields.cfg,
			}, tt.want); err != nil {
				t.Errorf("server.listenAndServeAPI() Error = %v", err)
			}
		})
	}
}

func Test_server_listenAndServeGRPCAPI(t *testing.T) {
	type fields struct {
		grpcSrv *grpc.Server
		hcsrv   *http.Server
		cfg     config.Server
	}
	type test struct {
		name       string
		fields     fields
		beforeFunc func() error
		checkFunc  func(*server, error) error
		afterFunc  func() error
		want       error
	}
	tests := []test{
		func() test {
			key := "../test/data/dummyServer.key"
			cert := "../test/data/dummyServer.crt"

			grpcHandler := func(srv interface{}, stream grpc.ServerStream) error {
				return stream.SendMsg(new(emptypb.Empty))
			}

			return test{
				name: "Test GRPC server startup",
				fields: fields{
					grpcSrv: grpc.NewServer(
						grpc.CustomCodec(proxy.Codec()),
						grpc.UnknownServiceHandler(grpcHandler),
					),
					cfg: config.Server{
						Port: 9999,
						TLS: config.TLS{
							Enable:   true,
							CertPath: cert,
							KeyPath:  key,
						},
					},
				},
				checkFunc: func(s *server, want error) error {
					// listenAndServeAPI function is blocking, so we need to set timer to shutdown the process
					go func() {
						time.Sleep(time.Second * 1)
						s.grpcSrv.Stop()
					}()

					got := s.listenAndServeGRPCAPI()

					if got != want {
						return fmt.Errorf("got:\t%v\nwant:\t%v", got, want)
					}
					return nil
				},
				want: nil,
			}
		}(),
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.afterFunc != nil {
				defer func() {
					if err := tt.afterFunc(); err != nil {
						t.Errorf("afterFunc error, error: %v", err)
						return
					}
				}()
			}
			if tt.beforeFunc != nil {
				if err := tt.beforeFunc(); err != nil {
					t.Errorf("beforeFunc error, error: %v", err)
					return
				}
			}

			if err := tt.checkFunc(&server{
				grpcSrv: tt.fields.grpcSrv,
				hcsrv:   tt.fields.hcsrv,
				cfg:     tt.fields.cfg,
			}, tt.want); err != nil {
				t.Errorf("server.listenAndServeGRPCAPI() Error = %v", err)
			}
		})
	}
}
