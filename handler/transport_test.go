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
	"crypto/tls"
	"errors"
	"io"
	"net/http"
	"reflect"
	"testing"

	authorizerd "github.com/AthenZ/athenz-authorizer/v5"
	"github.com/AthenZ/athenz-authorizer/v5/policy"
	"github.com/AthenZ/authorization-proxy/v4/config"
	"github.com/AthenZ/authorization-proxy/v4/service"
)

type readCloseCounter struct {
	CloseCount int
	ReadErr    error
}

func (r *readCloseCounter) Read(b []byte) (int, error) {
	return 0, r.ReadErr
}

func (r *readCloseCounter) Close() error {
	r.CloseCount++
	return nil
}

func Test_transport_RoundTrip(t *testing.T) {
	wrapAssertion := func(s string) *policy.Assertion {
		a, err := policy.NewAssertion("", ":"+s, "")
		if err != nil {
			panic(err)
		}
		return a
	}
	type fields struct {
		RoundTripper         http.RoundTripper
		prov                 service.Authorizationd
		cfg                  config.Proxy
		noAuthPaths          []*policy.Assertion
		insecureCipherSuites []*tls.CipherSuite
		metrics              service.Metrics
	}
	type args struct {
		r    *http.Request
		body *readCloseCounter
	}
	tests := []struct {
		name           string
		fields         fields
		args           args
		want           *http.Response
		wantErr        bool
		wantCloseCount int
	}{
		{
			name: "verify role token failed",
			fields: fields{
				RoundTripper: nil,
				prov: &service.AuthorizerdMock{
					VerifyFunc: func(r *http.Request, act, res string) (authorizerd.Principal, error) {
						return nil, errors.New("dummy error")
					},
				},
				cfg: config.Proxy{},
			},
			args: args{
				r: func() *http.Request {
					r, _ := http.NewRequest("GET", "http://athenz.io", nil)
					return r
				}(),
				body: &readCloseCounter{
					ReadErr: errors.New("readCloseCounter.Read not implemented"),
				},
			},
			wantErr:        true,
			wantCloseCount: 1,
		},
		{
			name: "verify role token success",
			fields: fields{
				RoundTripper: &RoundTripperMock{
					RoundTripFunc: func(req *http.Request) (*http.Response, error) {
						return &http.Response{
							StatusCode: 999,
						}, nil
					},
				},
				prov: &service.AuthorizerdMock{
					VerifyFunc: func(r *http.Request, act, res string) (authorizerd.Principal, error) {
						return &PrincipalMock{
							NameFunc: func() string {
								return ""
							},
							RolesFunc: func() []string {
								return []string{}
							},
							DomainFunc: func() string {
								return ""
							},
							IssueTimeFunc: func() int64 {
								return 0
							},
							ExpiryTimeFunc: func() int64 {
								return 0
							},
						}, nil
					},
				},
				cfg: config.Proxy{},
			},
			args: args{
				r: func() *http.Request {
					r, _ := http.NewRequest("GET", "http://athenz.io", nil)
					return r
				}(),
				body: &readCloseCounter{
					ReadErr: errors.New("readCloseCounter.Read not implemented"),
				},
			},
			want: &http.Response{
				StatusCode: 999,
			},
			wantErr:        false,
			wantCloseCount: 0,
		},
		{
			name: "verify role token success (empty bypass URLs)",
			fields: fields{
				RoundTripper: &RoundTripperMock{
					RoundTripFunc: func(req *http.Request) (*http.Response, error) {
						return &http.Response{
							StatusCode: 999,
						}, nil
					},
				},
				prov: &service.AuthorizerdMock{
					VerifyFunc: func(r *http.Request, act, res string) (authorizerd.Principal, error) {
						return &PrincipalMock{
							NameFunc: func() string {
								return ""
							},
							RolesFunc: func() []string {
								return []string{}
							},
							DomainFunc: func() string {
								return ""
							},
							IssueTimeFunc: func() int64 {
								return 0
							},
							ExpiryTimeFunc: func() int64 {
								return 0
							},
						}, nil
					},
				},
				cfg: config.Proxy{
					OriginHealthCheckPaths: []string{},
				},
			},
			args: args{
				r: func() *http.Request {
					r, _ := http.NewRequest("GET", "http://athenz.io", nil)
					return r
				}(),
				body: &readCloseCounter{
					ReadErr: errors.New("readCloseCounter.Read not implemented"),
				},
			},
			want: &http.Response{
				StatusCode: 999,
			},
			wantErr:        false,
			wantCloseCount: 0,
		},
		{
			name: "OriginHealthCheckPaths match, bypass role token verification",
			fields: fields{
				RoundTripper: &RoundTripperMock{
					RoundTripFunc: func(req *http.Request) (*http.Response, error) {
						return &http.Response{
							StatusCode: 200,
						}, nil
					},
				},
				prov: &service.AuthorizerdMock{
					VerifyFunc: func(r *http.Request, act, res string) (authorizerd.Principal, error) {
						return nil, errors.New("role token error")
					},
				},
				cfg: config.Proxy{
					OriginHealthCheckPaths: []string{
						"/healthz",
					},
				},
			},
			args: args{
				r: func() *http.Request {
					r, _ := http.NewRequest("GET", "http://athenz.io/healthz", nil)
					return r
				}(),
				body: &readCloseCounter{
					ReadErr: errors.New("readCloseCounter.Read not implemented"),
				},
			},
			want: &http.Response{
				StatusCode: 200,
			},
			wantErr:        false,
			wantCloseCount: 0,
		},
		{
			name: "OriginHealthCheckPaths ANY match, bypass role token verification",
			fields: fields{
				RoundTripper: &RoundTripperMock{
					RoundTripFunc: func(req *http.Request) (*http.Response, error) {
						return &http.Response{
							StatusCode: 200,
						}, nil
					},
				},
				prov: &service.AuthorizerdMock{
					VerifyFunc: func(r *http.Request, act, res string) (authorizerd.Principal, error) {
						return nil, errors.New("role token error")
					},
				},
				cfg: config.Proxy{
					OriginHealthCheckPaths: []string{
						"/healthz",
						"/healthz/",
					},
				},
			},
			args: args{
				r: func() *http.Request {
					r, _ := http.NewRequest("GET", "http://athenz.io/healthz/", nil)
					return r
				}(),
				body: &readCloseCounter{
					ReadErr: errors.New("readCloseCounter.Read not implemented"),
				},
			},
			want: &http.Response{
				StatusCode: 200,
			},
			wantErr:        false,
			wantCloseCount: 0,
		},
		{
			name: "OriginHealthCheckPaths NONE match, verify role token",
			fields: fields{
				RoundTripper: nil,
				prov: &service.AuthorizerdMock{
					VerifyFunc: func(r *http.Request, act, res string) (authorizerd.Principal, error) {
						return nil, errors.New("role token error")
					},
				},
				cfg: config.Proxy{
					OriginHealthCheckPaths: []string{
						"/healthz",
					},
				},
			},
			args: args{
				r: func() *http.Request {
					r, _ := http.NewRequest("GET", "http://athenz.io/healthz/", nil)
					return r
				}(),
				body: &readCloseCounter{
					ReadErr: errors.New("readCloseCounter.Read not implemented"),
				},
			},
			wantErr:        true,
			wantCloseCount: 1,
		},
		{
			name: "OriginHealthCheckPaths NOT set, verify role token",
			fields: fields{
				RoundTripper: nil,
				prov: &service.AuthorizerdMock{
					VerifyFunc: func(r *http.Request, act, res string) (authorizerd.Principal, error) {
						return nil, errors.New("role token error")
					},
				},
				cfg: config.Proxy{},
			},
			args: args{
				r: func() *http.Request {
					r, _ := http.NewRequest("GET", "http://athenz.io/healthz", nil)
					return r
				}(),
				body: &readCloseCounter{
					ReadErr: errors.New("readCloseCounter.Read not implemented"),
				},
			},
			wantErr:        true,
			wantCloseCount: 1,
		},
		{
			name: "NoAuthPaths match, bypass role token verification",
			fields: fields{
				RoundTripper: &RoundTripperMock{
					RoundTripFunc: func(req *http.Request) (*http.Response, error) {
						return &http.Response{
							StatusCode: 200,
						}, nil
					},
				},
				prov: &service.AuthorizerdMock{
					VerifyFunc: func(r *http.Request, act, res string) (authorizerd.Principal, error) {
						return nil, errors.New("role token error")
					},
				},
				cfg: config.Proxy{},
				noAuthPaths: []*policy.Assertion{
					wrapAssertion("/no-auth"),
				},
			},
			args: args{
				r: func() *http.Request {
					r, _ := http.NewRequest("GET", "http://athenz.io/no-auth", nil)
					return r
				}(),
				body: &readCloseCounter{
					ReadErr: errors.New("readCloseCounter.Read not implemented"),
				},
			},
			want: &http.Response{
				StatusCode: 200,
			},
			wantErr:        false,
			wantCloseCount: 0,
		},
		{
			name: "NoAuthPaths NONE match, verify role token",
			fields: fields{
				RoundTripper: nil,
				prov: &service.AuthorizerdMock{
					VerifyFunc: func(r *http.Request, act, res string) (authorizerd.Principal, error) {
						return nil, errors.New("role token error")
					},
				},
				cfg: config.Proxy{},
				noAuthPaths: []*policy.Assertion{
					wrapAssertion("/no-auth"),
				},
			},
			args: args{
				r: func() *http.Request {
					r, _ := http.NewRequest("GET", "http://athenz.io/no-auth/", nil)
					return r
				}(),
				body: &readCloseCounter{
					ReadErr: errors.New("readCloseCounter.Read not implemented"),
				},
			},
			wantErr:        true,
			wantCloseCount: 1,
		},
		{
			name: "NoAuthPaths NOT set, verify role token",
			fields: fields{
				RoundTripper: nil,
				prov: &service.AuthorizerdMock{
					VerifyFunc: func(r *http.Request, act, res string) (authorizerd.Principal, error) {
						return nil, errors.New("role token error")
					},
				},
				cfg: config.Proxy{},
			},
			args: args{
				r: func() *http.Request {
					r, _ := http.NewRequest("GET", "http://athenz.io/no-auth", nil)
					return r
				}(),
				body: &readCloseCounter{
					ReadErr: errors.New("readCloseCounter.Read not implemented"),
				},
			},
			wantErr:        true,
			wantCloseCount: 1,
		},
		{
			name: "allowed insecure cipher suites success",
			fields: fields{
				RoundTripper: &RoundTripperMock{
					RoundTripFunc: func(req *http.Request) (*http.Response, error) {
						return &http.Response{
							StatusCode: 200,
						}, nil
					},
				},
				prov: &service.AuthorizerdMock{
					VerifyFunc: func(r *http.Request, act, res string) (authorizerd.Principal, error) {
						return &PrincipalMock{
							NameFunc: func() string {
								return "testPrincipal"
							},
							RolesFunc: func() []string {
								return []string{"testRole1", "testRole2"}
							},
							DomainFunc: func() string {
								return "testDomain"
							},
							IssueTimeFunc: func() int64 {
								return 0
							},
							ExpiryTimeFunc: func() int64 {
								return 0
							},
						}, nil
					},
				},
				cfg:                  config.Proxy{},
				insecureCipherSuites: tls.InsecureCipherSuites(),
			},
			args: args{
				r: func() *http.Request {
					r, _ := http.NewRequest("GET", "http://athenz.io", nil)
					r.TLS = &tls.ConnectionState{
						CipherSuite: tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
					}
					return r
				}(),
				body: &readCloseCounter{
					ReadErr: errors.New("readCloseCounter.Read not implemented"),
				},
			},
			want: &http.Response{
				StatusCode: 200,
			},
			wantErr:        false,
			wantCloseCount: 0,
		},
		{
			name: "skipped t.metrics.Observe(), if request is not forwarded",
			fields: fields{
				RoundTripper: &RoundTripperMock{
					RoundTripFunc: func(req *http.Request) (*http.Response, error) {
						return &http.Response{
							StatusCode: 200,
						}, nil
					},
				},
				prov: &service.AuthorizerdMock{
					VerifyFunc: func(r *http.Request, act, res string) (authorizerd.Principal, error) {
						return nil, errors.New("dummy error")
					},
				},
				cfg: config.Proxy{},
				metrics: &service.MetricsMock{
					ObserveFunc: func(name string, value float64) error {
						panic("t.metrics.Observe() should not be called")
					},
				},
			},
			args: args{
				r: func() *http.Request {
					r, _ := http.NewRequest("GET", "http://athenz.io", nil)
					return r
				}(),
			},
			want:           nil,
			wantErr:        true,
			wantCloseCount: 0,
		},
		{
			name: "called t.metrics.Observe(), if request is forwarded",
			fields: fields{
				RoundTripper: &RoundTripperMock{
					RoundTripFunc: func(req *http.Request) (*http.Response, error) {
						return &http.Response{
							StatusCode: 200,
						}, nil
					},
				},
				prov: &service.AuthorizerdMock{
					VerifyFunc: func(r *http.Request, act, res string) (authorizerd.Principal, error) {
						return &PrincipalMock{
							NameFunc: func() string {
								return "testPrincipal"
							},
							RolesFunc: func() []string {
								return []string{"testRole1", "testRole2"}
							},
							DomainFunc: func() string {
								return "testDomain"
							},
							IssueTimeFunc: func() int64 {
								return 0
							},
							ExpiryTimeFunc: func() int64 {
								return 0
							},
						}, nil
					},
				},
				cfg: config.Proxy{},
				metrics: &service.MetricsMock{
					ObserveFunc: func(name string, value float64) error {
						return nil
					},
				},
			},
			args: args{
				r: func() *http.Request {
					r, _ := http.NewRequest("GET", "http://athenz.io", nil)
					return r
				}(),
			},
			want: &http.Response{
				StatusCode: 200,
			},
			wantErr:        false,
			wantCloseCount: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tr := &transport{
				RoundTripper:         tt.fields.RoundTripper,
				prov:                 tt.fields.prov,
				cfg:                  tt.fields.cfg,
				noAuthPaths:          tt.fields.noAuthPaths,
				insecureCipherSuites: tt.fields.insecureCipherSuites,
				metrics:              tt.fields.metrics,
			}
			if tt.args.body != nil {
				tt.args.r.Body = tt.args.body
			}
			got, err := tr.RoundTrip(tt.args.r)
			if (err != nil) != tt.wantErr {
				t.Errorf("transport.RoundTrip() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("transport.RoundTrip() = %v, want %v", got, tt.want)
			}
			if tt.args.body != nil {
				if tt.args.body.CloseCount != tt.wantCloseCount {
					t.Errorf("Body was closed %d times, expected %d", tt.args.body.CloseCount, tt.wantCloseCount)
				}
			}
		})
	}
}

func Test_transport_RoundTrip_WildcardBypass(t *testing.T) {
	wrapAssertion := func(s string) *policy.Assertion {
		a, err := policy.NewAssertion("", ":"+s, "")
		if err != nil {
			panic(err)
		}
		return a
	}
	wrapRequest := func(method, url string, body io.Reader) *http.Request {
		r, err := http.NewRequest(method, url, body)
		if err != nil {
			panic(err)
		}
		return r
	}
	type fields struct {
		RoundTripper http.RoundTripper
		prov         service.Authorizationd
		cfg          config.Proxy
		noAuthPaths  []*policy.Assertion
	}
	type args struct {
		r    *http.Request
		body *readCloseCounter
	}
	tests := []struct {
		name           string
		fields         fields
		argss          []args
		want           *http.Response
		wantErr        bool
		wantCloseCount int
	}{
		{
			name: "NoAuthPaths '*' match, bypass role token verification",
			fields: fields{
				RoundTripper: &RoundTripperMock{
					RoundTripFunc: func(req *http.Request) (*http.Response, error) {
						return &http.Response{
							StatusCode: 200,
						}, nil
					},
				},
				prov: &service.AuthorizerdMock{
					VerifyFunc: func(r *http.Request, act, res string) (authorizerd.Principal, error) {
						return nil, errors.New("role token error")
					},
				},
				cfg: config.Proxy{},
				noAuthPaths: []*policy.Assertion{
					wrapAssertion("/no-auth*"),
				},
			},
			argss: []args{
				{
					r: wrapRequest("GET", "http://athenz.io/no-auth", nil),
					body: &readCloseCounter{
						ReadErr: errors.New("readCloseCounter.Read not implemented"),
					},
				},
				{
					r: wrapRequest("GET", "http://athenz.io/no-authhhhhh", nil),
					body: &readCloseCounter{
						ReadErr: errors.New("readCloseCounter.Read not implemented"),
					},
				},
				{
					r: wrapRequest("GET", "http://athenz.io/no-auth/", nil),
					body: &readCloseCounter{
						ReadErr: errors.New("readCloseCounter.Read not implemented"),
					},
				},
				{
					r: wrapRequest("GET", "http://athenz.io/no-auth/abc", nil),
					body: &readCloseCounter{
						ReadErr: errors.New("readCloseCounter.Read not implemented"),
					},
				},
				{
					r: wrapRequest("GET", "http://athenz.io/no-auth/abc/483", nil),
					body: &readCloseCounter{
						ReadErr: errors.New("readCloseCounter.Read not implemented"),
					},
				},
			},
			want: &http.Response{
				StatusCode: 200,
			},
			wantErr:        false,
			wantCloseCount: 0,
		},
		{
			name: "NoAuthPaths '?' match, bypass role token verification",
			fields: fields{
				RoundTripper: &RoundTripperMock{
					RoundTripFunc: func(req *http.Request) (*http.Response, error) {
						return &http.Response{
							StatusCode: 200,
						}, nil
					},
				},
				prov: &service.AuthorizerdMock{
					VerifyFunc: func(r *http.Request, act, res string) (authorizerd.Principal, error) {
						return nil, errors.New("role token error")
					},
				},
				cfg: config.Proxy{},
				noAuthPaths: []*policy.Assertion{
					wrapAssertion("/no-auth/a??c"),
				},
			},
			argss: []args{
				{
					r: wrapRequest("GET", "http://athenz.io/no-auth/aaac", nil),
					body: &readCloseCounter{
						ReadErr: errors.New("readCloseCounter.Read not implemented"),
					},
				},
				{
					r: wrapRequest("GET", "http://athenz.io/no-auth/accc", nil),
					body: &readCloseCounter{
						ReadErr: errors.New("readCloseCounter.Read not implemented"),
					},
				},
				{
					r: wrapRequest("GET", "http://athenz.io/no-auth/abbc", nil),
					body: &readCloseCounter{
						ReadErr: errors.New("readCloseCounter.Read not implemented"),
					},
				},
			},
			want: &http.Response{
				StatusCode: 200,
			},
			wantErr:        false,
			wantCloseCount: 0,
		},
		{
			name: "NoAuthPaths '?' NOT match, verify role token",
			fields: fields{
				RoundTripper: nil,
				prov: &service.AuthorizerdMock{
					VerifyFunc: func(r *http.Request, act, res string) (authorizerd.Principal, error) {
						return nil, errors.New("role token error")
					},
				},
				cfg: config.Proxy{},
				noAuthPaths: []*policy.Assertion{
					wrapAssertion("/no-auth/a??c"),
				},
			},
			argss: []args{
				{
					r: wrapRequest("GET", "http://athenz.io/no-auth/aaaa", nil),
					body: &readCloseCounter{
						ReadErr: errors.New("readCloseCounter.Read not implemented"),
					},
				},
				{
					r: wrapRequest("GET", "http://athenz.io/no-auth/cccc", nil),
					body: &readCloseCounter{
						ReadErr: errors.New("readCloseCounter.Read not implemented"),
					},
				},
				{
					r: wrapRequest("GET", "http://athenz.io/no-auth/abbbc", nil),
					body: &readCloseCounter{
						ReadErr: errors.New("readCloseCounter.Read not implemented"),
					},
				},
				{
					r: wrapRequest("GET", "http://athenz.io/no-auth/123456", nil),
					body: &readCloseCounter{
						ReadErr: errors.New("readCloseCounter.Read not implemented"),
					},
				},
			},
			wantErr:        true,
			wantCloseCount: 1,
		},
		{
			name: "NoAuthPaths empty string NOT match, verify role token",
			fields: fields{
				RoundTripper: nil,
				prov: &service.AuthorizerdMock{
					VerifyFunc: func(r *http.Request, act, res string) (authorizerd.Principal, error) {
						return nil, errors.New("role token error")
					},
				},
				cfg: config.Proxy{},
				noAuthPaths: []*policy.Assertion{
					wrapAssertion(""),
				},
			},
			argss: []args{
				{
					r: wrapRequest("GET", "http://athenz.io", nil),
					body: &readCloseCounter{
						ReadErr: errors.New("readCloseCounter.Read not implemented"),
					},
				},
				{
					r: wrapRequest("GET", "http://athenz.io/", nil),
					body: &readCloseCounter{
						ReadErr: errors.New("readCloseCounter.Read not implemented"),
					},
				},
			},
			wantErr:        true,
			wantCloseCount: 1,
		},
		{
			name: "NoAuthPaths NO escape, verify role token",
			fields: fields{
				RoundTripper: &RoundTripperMock{
					RoundTripFunc: func(req *http.Request) (*http.Response, error) {
						return &http.Response{
							StatusCode: 200,
						}, nil
					},
				},
				prov: &service.AuthorizerdMock{
					VerifyFunc: func(r *http.Request, act, res string) (authorizerd.Principal, error) {
						return nil, errors.New("role token error")
					},
				},
				cfg: config.Proxy{},
				noAuthPaths: []*policy.Assertion{
					wrapAssertion("/no-auth/wildcard/\\*"),
					wrapAssertion("/no-auth/single/\\?"),
					wrapAssertion("/no-auth/escape/\\\\"),
				},
			},
			argss: []args{
				{
					r: wrapRequest("GET", "http://athenz.io/no-auth/wildcard/*", nil),
					body: &readCloseCounter{
						ReadErr: errors.New("readCloseCounter.Read not implemented"),
					},
				},
				{
					r: wrapRequest("GET", "http://athenz.io/no-auth/single/?", nil),
					body: &readCloseCounter{
						ReadErr: errors.New("readCloseCounter.Read not implemented"),
					},
				},
				{
					r: wrapRequest("GET", "http://athenz.io/no-auth/escape/\\", nil),
					body: &readCloseCounter{
						ReadErr: errors.New("readCloseCounter.Read not implemented"),
					},
				},
			},
			wantErr:        true,
			wantCloseCount: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tr := &transport{
				RoundTripper: tt.fields.RoundTripper,
				prov:         tt.fields.prov,
				cfg:          tt.fields.cfg,
				noAuthPaths:  tt.fields.noAuthPaths,
			}
			for _, args := range tt.argss {
				if args.body != nil {
					args.r.Body = args.body
				}
				got, err := tr.RoundTrip(args.r)
				if (err != nil) != tt.wantErr {
					t.Errorf("transport.RoundTrip() error = %v, wantErr %v", err, tt.wantErr)
					return
				}
				if !reflect.DeepEqual(got, tt.want) {
					t.Errorf("transport.RoundTrip() = %v, want %v", got, tt.want)
				}
				if args.body != nil {
					if args.body.CloseCount != tt.wantCloseCount {
						t.Errorf("Body was closed %d times, expected %d", args.body.CloseCount, tt.wantCloseCount)
					}
				}
			}
		})
	}
}
