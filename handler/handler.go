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
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httputil"
	"strings"
	"time"

	"github.com/AthenZ/athenz-authorizer/v5/policy"
	"github.com/AthenZ/authorization-proxy/v4/config"
	"github.com/AthenZ/authorization-proxy/v4/service"
	"github.com/kpango/glg"
	"github.com/pkg/errors"
)

// defaultMaxIdleConnsPerHost is the default value for transport MaxIdleConnsPerHost
const defaultMaxIdleConnsPerHost = 100

// Func represents the a handle function type
type Func func(http.ResponseWriter, *http.Request) error

// New creates a handler for handling different HTTP requests based on the given services. It also contains a reverse proxy for handling proxy request.
func New(cfg config.Proxy, bp httputil.BufferPool, prov service.Authorizationd, metrics service.Metrics) http.Handler {
	scheme := "http"
	if cfg.Scheme != "" {
		scheme = cfg.Scheme
	}

	host := fmt.Sprintf("%s:%d", cfg.Host, cfg.Port)

	var modifyResponse func(res *http.Response) error = nil
	if cfg.OriginLog.StatusCode.Enable {
		modifyResponse = func(res *http.Response) error {
			for _, statusCode := range cfg.OriginLog.StatusCode.Exclude {
				if statusCode == res.StatusCode {
					return nil
				}
			}
			glg.Infof("Origin request: %s %s, Response: status code: %d", res.Request.Method, res.Request.URL, res.StatusCode)
			return nil
		}
	}

	return &httputil.ReverseProxy{
		BufferPool: bp,
		Director: func(r *http.Request) {
			u := *r.URL
			u.Scheme = scheme
			u.Host = host
			req, err := http.NewRequest(r.Method, u.String(), r.Body)
			if err != nil {
				glg.Error(errors.Wrap(err, "NewRequest returned error"))
				r.URL.Scheme = scheme
				return
			}
			req.Header = r.Header
			req.RemoteAddr = r.RemoteAddr
			req.TLS = r.TLS
			if cfg.PreserveHost {
				req.Host = r.Host
				glg.Debugf("proxy.PreserveHost enabled, forward host header: %s\n", req.Host)
			}
			if cfg.ForceContentLength {
				req.ContentLength = r.ContentLength
				req.TransferEncoding = r.TransferEncoding
				glg.Debugf("proxy.ForceContentLength enabled, forward content-length header: %d\n", req.ContentLength)
			}

			*r = *req
		},
		ModifyResponse: modifyResponse,
		Transport: &transport{
			prov:                 prov,
			RoundTripper:         updateDialContext(transportFromCfg(cfg.Transport), cfg.Transport.DialContext.Timeout),
			cfg:                  cfg,
			noAuthPaths:          mapPathToAssertion(cfg.NoAuthPaths),
			insecureCipherSuites: tls.InsecureCipherSuites(),
			metrics:              metrics,
		},
		ErrorHandler: handleError,
	}
}

func updateDialContext(t *http.Transport, dialTimeout time.Duration) *http.Transport {
	if dialTimeout != time.Duration(0) {
		t.DialContext = (&net.Dialer{
			Timeout: dialTimeout,
		}).DialContext
	}
	glg.Debugf("proxy transport: %+v\n", t)
	return t
}

func transportFromCfg(cfg config.Transport) *http.Transport {
	isZero := func(v interface{}) bool {
		switch v.(type) {
		case int:
			return v == 0
		case int64:
			return v == 0
		case time.Duration:
			return v == time.Duration(0)
		case bool:
			return v == false
		default:
			glg.Fatal("Undefined type on proxy transport config")
			return false
		}
	}

	t := &http.Transport{}
	if !isZero(cfg.TLSHandshakeTimeout) {
		t.TLSHandshakeTimeout = cfg.TLSHandshakeTimeout
	}
	if !isZero(cfg.DisableKeepAlives) {
		t.DisableKeepAlives = cfg.DisableKeepAlives
	}
	if !isZero(cfg.DisableCompression) {
		t.DisableCompression = cfg.DisableCompression
	}
	if !isZero(cfg.MaxIdleConns) {
		t.MaxIdleConns = cfg.MaxIdleConns
	}
	t.MaxIdleConnsPerHost = defaultMaxIdleConnsPerHost
	if !isZero(cfg.MaxIdleConnsPerHost) {
		t.MaxIdleConnsPerHost = cfg.MaxIdleConnsPerHost
	}
	if !isZero(cfg.MaxConnsPerHost) {
		t.MaxConnsPerHost = cfg.MaxConnsPerHost
	}
	if !isZero(cfg.IdleConnTimeout) {
		t.IdleConnTimeout = cfg.IdleConnTimeout
	}
	if !isZero(cfg.ResponseHeaderTimeout) {
		t.ResponseHeaderTimeout = cfg.ResponseHeaderTimeout
	}
	if !isZero(cfg.ExpectContinueTimeout) {
		t.ExpectContinueTimeout = cfg.ExpectContinueTimeout
	}
	if !isZero(cfg.MaxResponseHeaderBytes) {
		t.MaxResponseHeaderBytes = cfg.MaxResponseHeaderBytes
	}
	if !isZero(cfg.WriteBufferSize) {
		t.WriteBufferSize = cfg.WriteBufferSize
	}
	if !isZero(cfg.ReadBufferSize) {
		t.ReadBufferSize = cfg.ReadBufferSize
	}
	if !isZero(cfg.ForceAttemptHTTP2) {
		t.ForceAttemptHTTP2 = cfg.ForceAttemptHTTP2
	}

	return t
}

func mapPathToAssertion(paths []string) []*policy.Assertion {
	as := make([]*policy.Assertion, len(paths))
	for i, p := range paths {
		var err error
		as[i], err = policy.NewAssertion("", ":"+p, "")
		if err != nil {
			// NewAssertion() escapes all regex characters and should NOT return ANY errors.
			glg.Errorf("Invalid proxy.noAuthPaths: %s", p)
			panic(ErrInvalidProxyConfig)
		}
	}
	return as
}

func handleError(rw http.ResponseWriter, r *http.Request, err error) {
	if r != nil && r.Body != nil {
		io.Copy(ioutil.Discard, r.Body)
		r.Body.Close()
	}
	status := http.StatusUnauthorized
	if !strings.Contains(err.Error(), ErrMsgUnverified) {
		glg.Warn("handleError: " + err.Error())
		status = http.StatusBadGateway
	}
	// request context canceled
	if errors.Cause(err) == context.Canceled {
		status = http.StatusRequestTimeout
	}
	rw.WriteHeader(status)
}

// trimBearer removes a leading "Bearer " or "bearer " (7 bytes)
// with zero allocations. ASCII-only, single fast path, minimal branching.
func trimBearer(tok string) string {
	// Require at least 7 bytes: "Bearer "
	if len(tok) < 7 ||
		// Normalize only the first byte case via ASCII bit trick.
		// 'B' (0x42) and 'b' (0x62) share lowercasing by (b|0x20) == 'b' (0x62).
		(tok[0]|0x20) != 'b' {
		return tok
	}

	// Compare the remaining 6 bytes via string slice == const.
	// This becomes a single runtime.memequal call (no allocation).
	if tok[1:7] == "earer " {
		return tok[7:]
	}
	return tok
}

// wildcardMatch reports whether str matches pattern with wildcards.
// Supported meta:
//   - '*' matches any sequence of bytes (including empty)
//   - '?' matches any single byte
//   - '\' escapes the next byte (e.g., \*, \?, \\)
//
// Matching is byte-wise (not rune-wise) for maximum speed and zero allocations.
// Strategy:
//  1. Hot fast-paths for the most common/simple patterns
//  2. Specialized splitter when the pattern has '*' only (no '?' nor '\')
//  3. General single-pass matcher with last-star backtracking and literal-run batching
func wildcardMatch(p, s string) bool {
	qne := strings.IndexByte(p, '?') < 0   // question not exists
	bsne := strings.IndexByte(p, '\\') < 0 // backslash not exists
	// Fast path: no meta -> plain equality
	if strings.IndexByte(p, '*') < 0 &&
		qne &&
		bsne {
		return s == p
	}
	// Fast path: only '*' (no '?' nor '\') -> split-less subsequence match
	if qne && bsne {
		return matchOnlyStars(s, p)
	}
	// General matcher: literal-run batching + last-'*' backtracking
	return matchGeneral(s, p)
}

// matchOnlyStars handles patterns that may contain '*' but no '?' nor '\'.
// It performs ordered-subsequence matching without allocations (no Split).
func matchOnlyStars(s, p string) bool {
	if p == "*" {
		return true
	}
	n := len(p)
	leadStar := n > 0 && p[0] == '*'
	tailStar := n > 0 && p[n-1] == '*'

	i, pos, first := 0, 0, true
	for pos < n {
		// find next '*'
		k := strings.IndexByte(p[pos:], '*')
		if k < 0 {
			seg := p[pos:]
			if seg == "" {
				return tailStar // empty tail
			}
			if !tailStar {
				// must be suffix at or after i
				if len(seg) > len(s)-i {
					return false
				}
				return strings.HasSuffix(s[i:], seg)
			}
			return strings.Contains(s[i:], seg)
		}
		// segment between stars
		seg := p[pos : pos+k]
		if seg != "" {
			if first && !leadStar {
				if !strings.HasPrefix(s[i:], seg) {
					return false
				}
				i += len(seg)
			} else {
				idx := strings.Index(s[i:], seg)
				if idx < 0 {
					return false
				}
				i += idx + len(seg)
			}
		}
		first = false
		pos += k + 1 // jump over '*'
		// skip consecutive '*'
		for pos < n && p[pos] == '*' {
			pos++
		}
	}
	// pattern ended on stars
	return true
}

// matchGeneral: single pass with literal-run batching + last-star backtrack.
func matchGeneral(s, p string) bool {
	si, pi := 0, 0
	sn, pn := len(s), len(p)
	star, match := -1, 0

	for {
		// Batch literal run until next meta
		if pi < pn {
			next := indexAnyBytes(p[pi:], '*', '?', '\\')
			if next < 0 {
				lit := p[pi:]
				need := len(lit)
				if si+need != sn {
					// try to grow previous '*'
					if star >= 0 && si < sn {
						match++
						si = match
						pi = star + 1
						continue
					}
					return false
				}
				return strings.HasPrefix(s[si:], lit)
			}
			if next > 0 {
				lit := p[pi : pi+next]
				need := len(lit)
				if si+need > sn || !strings.HasPrefix(s[si:], lit) {
					if star >= 0 && si < sn {
						match++
						si = match
						pi = star + 1
						continue
					}
					return false
				}
				si += need
				pi += next
				if si == sn && pi == pn {
					return true
				}
			}
		}

		// Pattern exhausted -> only previous '*' can help
		if pi >= pn {
			if star >= 0 && si < sn {
				match++
				si = match
				pi = star + 1
				continue
			}
			return si >= sn
		}

		// Meta handling
		switch p[pi] {
		case '*':
			// compress consecutive '*'
			for pi < pn && p[pi] == '*' {
				pi++
			}
			star = pi - 1
			match = si
			if pi >= pn {
				return true // '*' at end matches the rest
			}
		case '?':
			if si >= sn {
				if star >= 0 {
					match++
					si = match
					pi = star + 1
					continue
				}
				return false
			}
			si++
			pi++
		case '\\':
			pi++
			if pi >= pn {
				return false // dangling '\'
			}
			if si >= sn || s[si] != p[pi] {
				if star >= 0 && si < sn {
					match++
					si = match
					pi = star + 1
					continue
				}
				return false
			}
			si++
			pi++
		default:
			// unreachable: literals are eaten by the batch above
			pi++
		}
	}
}

// indexAnyBytes returns the index of the first occurrence in s of any byte in chars.
// If none found, returns -1. This works for arbitrary-length chars.
func indexAnyBytes(s string, chars ...byte) int {
	if len(chars) == 0 {
		return -1
	}
	min := -1
	for _, c := range chars {
		if idx := strings.IndexByte(s, c); idx >= 0 && (min < 0 || idx < min) {
			min = idx
		}
	}
	return min
}
