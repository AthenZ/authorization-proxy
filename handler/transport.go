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
	"net/http"
	"strconv"
	"strings"
	"time"

	authorizerd "github.com/AthenZ/athenz-authorizer/v5"
	"github.com/AthenZ/athenz-authorizer/v5/policy"
	"github.com/AthenZ/authorization-proxy/v4/config"
	"github.com/AthenZ/authorization-proxy/v4/service"

	"github.com/kpango/glg"
	"github.com/pkg/errors"
)

type transport struct {
	http.RoundTripper

	prov        service.Authorizationd
	cfg         config.Proxy
	noAuthPaths []*policy.Assertion
	// List to check for deprecated cipher suites
	insecureCipherSuites []*tls.CipherSuite
	metrics              service.Metrics
}

// Based on the following.
// https://github.com/golang/oauth2/blob/bf48bf16ab8d622ce64ec6ce98d2c98f916b6303/transport.go
func (t *transport) RoundTrip(r *http.Request) (*http.Response, error) {
	var startTime time.Time

	if t.metrics != nil {
		defer func() {
			if !startTime.IsZero() {
				endTime := time.Since(startTime)
				err := t.metrics.Observe(service.HTTP_ORIGIN_LATENCY, float64(endTime.Seconds()))
				if err != nil {
					glg.Errorf("cannot observe origin latency: %v", err)
				}
			}
		}()
	}
	// bypass authoriztion
	if len(r.URL.Path) != 0 { // prevent bypassing empty path on default config
		for _, urlPath := range t.cfg.OriginHealthCheckPaths {
			if urlPath == r.URL.Path {
				glg.Info("Authorization checking skipped on: " + r.URL.Path)
				r.TLS = nil
				startTime = time.Now()
				return t.RoundTripper.RoundTrip(r)
			}
		}
		for _, ass := range t.noAuthPaths {
			if ass.ResourceRegexp.MatchString(strings.ToLower(r.URL.Path)) {
				glg.Infof("Authorization checking skipped by %s on: %s", ass.ResourceRegexpString, r.URL.Path)
				r.TLS = nil
				startTime = time.Now()
				return t.RoundTripper.RoundTrip(r)
			}
		}
	}

	reqBodyClosed := false
	if r.Body != nil {
		defer func() {
			if !reqBodyClosed {
				r.Body.Close()
			}
		}()
	}

	p, err := t.prov.Authorize(r, r.Method, r.URL.Path)
	if err != nil {
		return nil, errors.Wrap(err, ErrMsgUnverified)
	}

	if r.TLS != nil {
		for _, cipherSuite := range t.insecureCipherSuites {
			if cipherSuite.ID == r.TLS.CipherSuite {
				glg.Warnf("A connection was made with a deprecated cipher suite. Client IP adress: %s, Domain: %s, Role: [%s], Principal: %s, Cipher Suite: %s", r.RemoteAddr, p.Domain(), strings.Join(p.Roles(), ","), p.Name(), cipherSuite.Name)
				break
			}
		}
	}

	req2 := cloneRequest(r) // per RoundTripper contract

	req2.Header.Set("X-Athenz-Principal", p.Name())
	req2.Header.Set("X-Athenz-Role", strings.Join(p.Roles(), ","))
	req2.Header.Set("X-Athenz-Domain", p.Domain())
	req2.Header.Set("X-Athenz-Issued-At", strconv.FormatInt(p.IssueTime(), 10))
	req2.Header.Set("X-Athenz-Expires-At", strconv.FormatInt(p.ExpiryTime(), 10))

	if c, ok := p.(authorizerd.OAuthAccessToken); ok {
		req2.Header.Set("X-Athenz-Client-ID", c.ClientID())
	}

	req2.TLS = nil
	// req.Body is assumed to be closed by the base RoundTripper.
	reqBodyClosed = true
	startTime = time.Now()
	return t.RoundTripper.RoundTrip(req2)
}

// cloneRequest returns a clone of the provided *http.Request.
// The clone is a shallow copy of the struct and its Header map.
func cloneRequest(r *http.Request) *http.Request {
	// shallow copy of the struct
	r2 := new(http.Request)
	*r2 = *r
	// deep copy of the Header
	r2.Header = make(http.Header, len(r.Header))
	for k, s := range r.Header {
		r2.Header[k] = append([]string(nil), s...)
	}
	return r2
}
