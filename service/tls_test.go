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
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"reflect"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AthenZ/authorization-proxy/v4/config"
)

func TestNewTLSConfig(t *testing.T) {
	type args struct {
		CertPath string
		KeyPath  string
		CAPath   string
		cfg      config.TLS
	}
	defaultArgs := args{
		cfg: config.TLS{
			CertPath:            "../test/data/dummyServer.crt",
			KeyPath:             "../test/data/dummyServer.key",
			CAPath:              "../test/data/dummyCa.pem",
			DisableCipherSuites: nil,
		},
	}

	tests := []struct {
		name       string
		args       args
		want       *tls.Config
		beforeFunc func(args args)
		checkFunc  func(*tls.Config, *tls.Config) error
		afterFunc  func(args args)
		wantErr    bool
	}{
		{
			name: "return value MinVersion test.",
			args: defaultArgs,
			want: &tls.Config{
				MinVersion: tls.VersionTLS12,
				CurvePreferences: []tls.CurveID{
					tls.CurveP521,
					tls.CurveP384,
					tls.CurveP256,
					tls.X25519,
				},
				SessionTicketsDisabled: true,
				Certificates: func() []tls.Certificate {
					cert, _ := tls.LoadX509KeyPair(defaultArgs.cfg.CertPath, defaultArgs.cfg.KeyPath)
					return []tls.Certificate{cert}
				}(),
				ClientAuth: tls.RequireAndVerifyClientCert,
			},
			checkFunc: func(got, want *tls.Config) error {
				if got.MinVersion != want.MinVersion {
					return fmt.Errorf("MinVersion not Matched :\tgot %d\twant %d", got.MinVersion, want.MinVersion)
				}
				return nil
			},
		},
		{
			name: "return value CurvePreferences test.",
			args: defaultArgs,
			want: &tls.Config{
				MinVersion: tls.VersionTLS12,
				CurvePreferences: []tls.CurveID{
					tls.CurveP521,
					tls.CurveP384,
					tls.CurveP256,
					tls.X25519,
				},
				SessionTicketsDisabled: true,
				Certificates: func() []tls.Certificate {
					cert, _ := tls.LoadX509KeyPair(defaultArgs.cfg.CertPath, defaultArgs.cfg.KeyPath)
					return []tls.Certificate{cert}
				}(),
				ClientAuth: tls.RequireAndVerifyClientCert,
			},
			checkFunc: func(got, want *tls.Config) error {
				if len(got.CurvePreferences) != len(want.CurvePreferences) {
					return fmt.Errorf("CurvePreferences not Matched length:\tgot %d\twant %d", len(got.CurvePreferences), len(want.CurvePreferences))
				}
				for _, actualValue := range got.CurvePreferences {
					var match bool
					for _, expectedValue := range want.CurvePreferences {
						if actualValue == expectedValue {
							match = true
							break
						}
					}

					if !match {
						return fmt.Errorf("CurvePreferences not Find :\twant %d", want.MinVersion)
					}
				}
				return nil
			},
		},
		{
			name: "return value SessionTicketsDisabled test.",
			args: defaultArgs,
			want: &tls.Config{
				MinVersion: tls.VersionTLS12,
				CurvePreferences: []tls.CurveID{
					tls.CurveP521,
					tls.CurveP384,
					tls.CurveP256,
					tls.X25519,
				},
				SessionTicketsDisabled: true,
				Certificates: func() []tls.Certificate {
					cert, _ := tls.LoadX509KeyPair(defaultArgs.cfg.CertPath, defaultArgs.cfg.KeyPath)
					return []tls.Certificate{cert}
				}(),
				ClientAuth: tls.RequireAndVerifyClientCert,
			},
			checkFunc: func(got, want *tls.Config) error {
				if got.SessionTicketsDisabled != want.SessionTicketsDisabled {
					return fmt.Errorf("SessionTicketsDisabled not matched :\tgot %v\twant %v", got.SessionTicketsDisabled, want.SessionTicketsDisabled)
				}
				return nil
			},
		},
		{
			name: "return value Certificates test.",
			args: defaultArgs,
			want: &tls.Config{
				MinVersion: tls.VersionTLS12,
				CurvePreferences: []tls.CurveID{
					tls.CurveP521,
					tls.CurveP384,
					tls.CurveP256,
					tls.X25519,
				},
				SessionTicketsDisabled: true,
				Certificates: func() []tls.Certificate {
					cert, _ := tls.LoadX509KeyPair(defaultArgs.cfg.CertPath, defaultArgs.cfg.KeyPath)
					return []tls.Certificate{cert}
				}(),
				ClientAuth: tls.RequireAndVerifyClientCert,
			},
			checkFunc: func(got, want *tls.Config) error {
				for _, wantVal := range want.Certificates {
					notExist := false
					for _, gotVal := range got.Certificates {
						if gotVal.PrivateKey == wantVal.PrivateKey {
							notExist = true
							break
						}
					}
					if notExist {
						return fmt.Errorf("Certificates PrivateKey not Matched :\twant %s", wantVal.PrivateKey)
					}
				}
				return nil
			},
		},
		{
			name: "if certRefreshPeriod set, return TLSConfig.Certificates",
			args: args{
				cfg: config.TLS{
					CertPath:          "../test/data/dummyServer.crt",
					KeyPath:           "../test/data/dummyServer.key",
					CAPath:            "../test/data/dummyCa.pem",
					CertRefreshPeriod: "12345s",
				},
			},
			want: &tls.Config{
				MinVersion: tls.VersionTLS12,
				CurvePreferences: []tls.CurveID{
					tls.CurveP521,
					tls.CurveP384,
					tls.CurveP256,
					tls.X25519,
				},
				SessionTicketsDisabled: true,
				Certificates: func() []tls.Certificate {
					cert, _ := tls.LoadX509KeyPair(defaultArgs.cfg.CertPath, defaultArgs.cfg.KeyPath)
					return []tls.Certificate{cert}
				}(),
				ClientAuth: tls.RequireAndVerifyClientCert,
			},
			checkFunc: func(got, want *tls.Config) error {
				// config.TLS.certRefreshPeriod is not set, GetCertificate is nil
				if got.GetCertificate != nil {
					return fmt.Errorf("GetCertificate is not nil")
				}
				// config.TLS.certRefreshPeriod is not set, TLSConfig.Certificates is set
				gotCert, _ := x509.ParseCertificate(got.Certificates[0].Certificate[0])
				wantCert, _ := x509.ParseCertificate(want.Certificates[0].Certificate[0])
				if gotCert.SerialNumber.String() != wantCert.SerialNumber.String() {
					return fmt.Errorf("Certificate SerialNumber not Matched\tgot: %s\twant: %s", gotCert.SerialNumber, wantCert.SerialNumber)
				}
				return nil
			},
		},
		{
			name: "return value ClientAuth test.",
			args: defaultArgs,
			want: &tls.Config{
				MinVersion: tls.VersionTLS12,
				CurvePreferences: []tls.CurveID{
					tls.CurveP521,
					tls.CurveP384,
					tls.CurveP256,
					tls.X25519,
				},
				SessionTicketsDisabled: true,
				Certificates: func() []tls.Certificate {
					cert, _ := tls.LoadX509KeyPair(defaultArgs.cfg.CertPath, defaultArgs.cfg.KeyPath)
					return []tls.Certificate{cert}
				}(),
				ClientAuth: tls.RequireAndVerifyClientCert,
			},
			checkFunc: func(got, want *tls.Config) error {
				if got.ClientAuth != want.ClientAuth {
					return fmt.Errorf("ClientAuth not Matched :\tgot %d \twant %d", got.ClientAuth, want.ClientAuth)
				}
				return nil
			},
		},
		{
			name: "cert file not found return value Certificates test.",
			args: args{
				cfg: config.TLS{
					CertPath: "",
				},
			},
			want: &tls.Config{
				MinVersion: tls.VersionTLS12,
				CurvePreferences: []tls.CurveID{
					tls.CurveP521,
					tls.CurveP384,
					tls.CurveP256,
					tls.X25519,
				},
				SessionTicketsDisabled: true,
				Certificates:           nil,
				ClientAuth:             tls.RequireAndVerifyClientCert,
			},
			checkFunc: func(got, want *tls.Config) error {
				if got.Certificates != nil {
					return fmt.Errorf("Certificates not nil")
				}
				return nil
			},
		},
		{
			name: "cert file not found return value ClientAuth test.",
			args: args{
				cfg: config.TLS{
					CertPath: "",
				},
			},
			want: &tls.Config{
				MinVersion: tls.VersionTLS12,
				CurvePreferences: []tls.CurveID{
					tls.CurveP521,
					tls.CurveP384,
					tls.CurveP256,
					tls.X25519,
				},
				SessionTicketsDisabled: true,
				Certificates:           nil,
				ClientAuth:             tls.RequireAndVerifyClientCert,
			},
			checkFunc: func(got, want *tls.Config) error {
				if got.Certificates != nil {
					return fmt.Errorf("Certificates not nil")
				}
				return nil
			},
		},
		{
			name: "CA file not found return value ClientAuth test.",
			args: args{
				cfg: config.TLS{
					CertPath: "",
					CAPath:   "",
				},
			},

			want: &tls.Config{
				MinVersion: tls.VersionTLS12,
				CurvePreferences: []tls.CurveID{
					tls.CurveP521,
					tls.CurveP384,
					tls.CurveP256,
					tls.X25519,
				},
				SessionTicketsDisabled: true,
				Certificates: func() []tls.Certificate {
					cert, _ := tls.LoadX509KeyPair(defaultArgs.cfg.CertPath, defaultArgs.cfg.KeyPath)
					return []tls.Certificate{cert}
				}(),
				ClientAuth: tls.RequireAndVerifyClientCert,
			},
			checkFunc: func(got, want *tls.Config) error {
				if got.ClientAuth != 0 {
					return fmt.Errorf("ClientAuth is :\t%d", got.ClientAuth)
				}
				return nil
			},
		},
		{
			name: "certificate with trailing dot in SAN should load successfully",
			args: args{
				cfg: config.TLS{
					CertPath: "../test/data/trailing_dot_server.crt",
					KeyPath:  "../test/data/trailing_dot_server.key",
				},
			},
			want:    &tls.Config{MinVersion: tls.VersionTLS12},
			wantErr: false,
			checkFunc: func(got, want *tls.Config) error {
				return nil
			},
		},
		{
			name: "certificate with leading dot in SAN should load successfully",
			args: args{
				cfg: config.TLS{
					CertPath: "../test/data/leading_dot_server.crt",
					KeyPath:  "../test/data/leading_dot_server.key",
				},
			},
			want:    &tls.Config{MinVersion: tls.VersionTLS12},
			wantErr: false,
			checkFunc: func(got, want *tls.Config) error {
				return nil
			},
		},
		{
			name: "certificate with empty label in SAN should load successfully",
			args: args{
				cfg: config.TLS{
					CertPath: "../test/data/empty_label_server.crt",
					KeyPath:  "../test/data/empty_label_server.key",
				},
			},
			want:    &tls.Config{MinVersion: tls.VersionTLS12},
			wantErr: false,
			checkFunc: func(got, want *tls.Config) error {
				return nil
			},
		},
		{
			name: "certificate with long label in SAN should load successfully",
			args: args{
				cfg: config.TLS{
					CertPath: "../test/data/long_label_server.crt",
					KeyPath:  "../test/data/long_label_server.key",
				},
			},
			want:    &tls.Config{MinVersion: tls.VersionTLS12},
			wantErr: false,
			checkFunc: func(got, want *tls.Config) error {
				return nil
			},
		},
		{
			name: "certificate with malformed email in SAN should load successfully",
			args: args{
				cfg: config.TLS{
					CertPath: "../test/data/malformed_email_server.crt",
					KeyPath:  "../test/data/malformed_email_server.key",
				},
			},
			want:    &tls.Config{MinVersion: tls.VersionTLS12},
			wantErr: false,
			checkFunc: func(got, want *tls.Config) error {
				return nil
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.beforeFunc != nil {
				tt.beforeFunc(tt.args)
			}

			got, err := NewTLSConfig(tt.args.cfg)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewTLSConfig() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.checkFunc != nil {
				err = tt.checkFunc(got, tt.want)
				if err != nil {
					t.Errorf("NewTLSConfig() error = %v", err)
					return
				}
			}

			if tt.afterFunc != nil {
				tt.afterFunc(tt.args)
			}
		})
	}
}

func TestNewTLSConfigWithTLSCertificateCache(t *testing.T) {
	type args struct {
		CertPath string
		KeyPath  string
		CAPath   string
		cfg      config.TLS
	}
	defaultArgs := args{
		cfg: config.TLS{
			CertPath: "../test/data/dummyServer.crt",
			KeyPath:  "../test/data/dummyServer.key",
			CAPath:   "../test/data/dummyCa.pem",
		},
	}
	var defaultServerCert atomic.Value
	defaultServerCertData, err := tls.LoadX509KeyPair(defaultArgs.cfg.CertPath, defaultArgs.cfg.KeyPath)
	if err != nil {
		t.Errorf("LoadX509KeyPair failed: %s", err)
		return
	}
	defaultServerCert.Store(&defaultServerCertData)
	defaultServerCerttHash, err := hash(defaultArgs.cfg.CertPath)
	if err != nil {
		t.Errorf("hash failed: %s", err)
		return
	}
	defaultServerCerttKeyHash, _ := hash(defaultArgs.cfg.KeyPath)
	if err != nil {
		t.Errorf("hash failed: %s", err)
		return
	}

	tests := []struct {
		name       string
		args       args
		wantConfig *tls.Config
		wantCache  *TLSCertificateCache
		beforeFunc func(args args)
		checkFunc  func(*tls.Config, *TLSCertificateCache, *tls.Config, *TLSCertificateCache) error
		afterFunc  func(args args)
		wantErr    error
	}{
		{
			name: "return value MinVersion test.",
			args: defaultArgs,
			wantConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
				CurvePreferences: []tls.CurveID{
					tls.CurveP521,
					tls.CurveP384,
					tls.CurveP256,
					tls.X25519,
				},
				SessionTicketsDisabled: true,
				Certificates: func() []tls.Certificate {
					cert, _ := tls.LoadX509KeyPair(defaultArgs.cfg.CertPath, defaultArgs.cfg.KeyPath)
					return []tls.Certificate{cert}
				}(),
				ClientAuth:     tls.RequireAndVerifyClientCert,
				GetCertificate: nil,
			},
			wantCache: nil,
			checkFunc: func(gotConfig *tls.Config, gotCache *TLSCertificateCache, wantConfig *tls.Config, wantCache *TLSCertificateCache) error {
				if gotConfig.MinVersion != wantConfig.MinVersion {
					return fmt.Errorf("MinVersion not Matched :\tgot %d\twant %d", gotConfig.MinVersion, wantConfig.MinVersion)
				}
				// config.TLS.certRefreshPeriod is not set, TLSCertificateCache is nil
				if gotCache != wantCache {
					return fmt.Errorf("TLSCertificateCache is not nil\tgot: %v", gotCache)
				}
				// config.TLS.certRefreshPeriod is not set, GetCertificate is nil
				if gotConfig.GetCertificate != nil {
					return fmt.Errorf("GetCertificate is not nil")
				}
				// config.TLS.certRefreshPeriod is not set, TLSConfig.Certificates is set
				gotCert, _ := x509.ParseCertificate(gotConfig.Certificates[0].Certificate[0])
				wantCert, _ := x509.ParseCertificate(wantConfig.Certificates[0].Certificate[0])
				if gotCert.SerialNumber.String() != wantCert.SerialNumber.String() {
					return fmt.Errorf("Certificate SerialNumber not Matched\tgot: %s\twant: %s", gotCert.SerialNumber, wantCert.SerialNumber)
				}
				return nil
			},
		},
		{
			name: "return value CurvePreferences test.",
			args: defaultArgs,
			wantConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
				CurvePreferences: []tls.CurveID{
					tls.CurveP521,
					tls.CurveP384,
					tls.CurveP256,
					tls.X25519,
				},
				SessionTicketsDisabled: true,
				Certificates: func() []tls.Certificate {
					cert, _ := tls.LoadX509KeyPair(defaultArgs.cfg.CertPath, defaultArgs.cfg.KeyPath)
					return []tls.Certificate{cert}
				}(),
				ClientAuth: tls.RequireAndVerifyClientCert,
			},
			wantCache: nil,
			checkFunc: func(gotConfig *tls.Config, gotCache *TLSCertificateCache, wantConfig *tls.Config, wantCache *TLSCertificateCache) error {
				if len(gotConfig.CurvePreferences) != len(wantConfig.CurvePreferences) {
					return fmt.Errorf("CurvePreferences not Matched length:\tgot %d\twant %d", len(gotConfig.CurvePreferences), len(wantConfig.CurvePreferences))
				}
				for _, actualValue := range gotConfig.CurvePreferences {
					var match bool
					for _, expectedValue := range wantConfig.CurvePreferences {
						if actualValue == expectedValue {
							match = true
							break
						}
					}

					if !match {
						return fmt.Errorf("CurvePreferences not Find :\twant %d", wantConfig.MinVersion)
					}
				}
				// config.TLS.certRefreshPeriod is not set, TLSCertificateCache is nil
				if gotCache != wantCache {
					return fmt.Errorf("TLSCertificateCache is not nil\tgot: %v", gotCache)
				}
				// config.TLS.certRefreshPeriod is not set, GetCertificate is nil
				if gotConfig.GetCertificate != nil {
					return fmt.Errorf("GetCertificate is not nil")
				}
				// config.TLS.certRefreshPeriod is not set, TLSConfig.Certificates is set
				gotCert, _ := x509.ParseCertificate(gotConfig.Certificates[0].Certificate[0])
				wantCert, _ := x509.ParseCertificate(wantConfig.Certificates[0].Certificate[0])
				if gotCert.SerialNumber.String() != wantCert.SerialNumber.String() {
					return fmt.Errorf("Certificate SerialNumber not Matched\tgot: %s\twant: %s", gotCert.SerialNumber, wantCert.SerialNumber)
				}
				return nil
			},
		},
		{
			name: "return value SessionTicketsDisabled test.",
			args: defaultArgs,
			wantConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
				CurvePreferences: []tls.CurveID{
					tls.CurveP521,
					tls.CurveP384,
					tls.CurveP256,
					tls.X25519,
				},
				SessionTicketsDisabled: true,
				Certificates: func() []tls.Certificate {
					cert, _ := tls.LoadX509KeyPair(defaultArgs.cfg.CertPath, defaultArgs.cfg.KeyPath)
					return []tls.Certificate{cert}
				}(),
				ClientAuth: tls.RequireAndVerifyClientCert,
			},
			wantCache: nil,
			checkFunc: func(gotConfig *tls.Config, gotCache *TLSCertificateCache, wantConfig *tls.Config, wantCache *TLSCertificateCache) error {
				if gotConfig.SessionTicketsDisabled != wantConfig.SessionTicketsDisabled {
					return fmt.Errorf("SessionTicketsDisabled not matched :\tgot %v\twant %v", gotConfig.SessionTicketsDisabled, wantConfig.SessionTicketsDisabled)
				}
				// config.TLS.certRefreshPeriod is not set, TLSCertificateCache is nil
				if gotCache != wantCache {
					return fmt.Errorf("TLSCertificateCache is not nil\tgot: %v", gotCache)
				}
				// config.TLS.certRefreshPeriod is not set, GetCertificate is nil
				if gotConfig.GetCertificate != nil {
					return fmt.Errorf("GetCertificate is not nil")
				}
				// config.TLS.certRefreshPeriod is not set, TLSConfig.Certificates is set
				gotCert, _ := x509.ParseCertificate(gotConfig.Certificates[0].Certificate[0])
				wantCert, _ := x509.ParseCertificate(wantConfig.Certificates[0].Certificate[0])
				if gotCert.SerialNumber.String() != wantCert.SerialNumber.String() {
					return fmt.Errorf("Certificate SerialNumber not Matched\tgot: %s\twant: %s", gotCert.SerialNumber, wantCert.SerialNumber)
				}
				return nil
			},
		},
		{
			name: "return value Certificates test.",
			args: defaultArgs,
			wantConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
				CurvePreferences: []tls.CurveID{
					tls.CurveP521,
					tls.CurveP384,
					tls.CurveP256,
					tls.X25519,
				},
				SessionTicketsDisabled: true,
				Certificates: func() []tls.Certificate {
					cert, _ := tls.LoadX509KeyPair(defaultArgs.cfg.CertPath, defaultArgs.cfg.KeyPath)
					return []tls.Certificate{cert}
				}(),
				ClientAuth: tls.RequireAndVerifyClientCert,
			},
			wantCache: nil,
			checkFunc: func(gotConfig *tls.Config, gotCache *TLSCertificateCache, wantConfig *tls.Config, wantCache *TLSCertificateCache) error {
				for _, wantVal := range wantConfig.Certificates {
					notExist := false
					for _, gotVal := range gotConfig.Certificates {
						if gotVal.PrivateKey == wantVal.PrivateKey {
							notExist = true
							break
						}
					}
					if notExist {
						return fmt.Errorf("Certificates PrivateKey not Matched :\twant %s", wantVal.PrivateKey)
					}
				}
				// config.TLS.certRefreshPeriod is not set, TLSCertificateCache is nil
				if gotCache != wantCache {
					return fmt.Errorf("TLSCertificateCache is not nil\tgot: %v", gotCache)
				}
				// config.TLS.certRefreshPeriod is not set, GetCertificate is nil
				if gotConfig.GetCertificate != nil {
					return fmt.Errorf("GetCertificate is not nil")
				}
				// config.TLS.certRefreshPeriod is not set, TLSConfig.Certificates is set
				gotCert, _ := x509.ParseCertificate(gotConfig.Certificates[0].Certificate[0])
				wantCert, _ := x509.ParseCertificate(wantConfig.Certificates[0].Certificate[0])
				if gotCert.SerialNumber.String() != wantCert.SerialNumber.String() {
					return fmt.Errorf("Certificate SerialNumber not Matched\tgot: %s\twant: %s", gotCert.SerialNumber, wantCert.SerialNumber)
				}
				return nil
			},
		},
		{
			name: "return value ClientAuth test.",
			args: defaultArgs,
			wantConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
				CurvePreferences: []tls.CurveID{
					tls.CurveP521,
					tls.CurveP384,
					tls.CurveP256,
					tls.X25519,
				},
				SessionTicketsDisabled: true,
				Certificates: func() []tls.Certificate {
					cert, _ := tls.LoadX509KeyPair(defaultArgs.cfg.CertPath, defaultArgs.cfg.KeyPath)
					return []tls.Certificate{cert}
				}(),
				ClientAuth: tls.RequireAndVerifyClientCert,
			},
			wantCache: nil,
			checkFunc: func(gotConfig *tls.Config, gotCache *TLSCertificateCache, wantConfig *tls.Config, wantCache *TLSCertificateCache) error {
				if gotConfig.ClientAuth != wantConfig.ClientAuth {
					return fmt.Errorf("ClientAuth not Matched :\tgot %d \twant %d", gotConfig.ClientAuth, wantConfig.ClientAuth)
				}
				// config.TLS.certRefreshPeriod is not set, TLSCertificateCache is nil
				if gotCache != wantCache {
					return fmt.Errorf("TLSCertificateCache is not nil\tgot: %v", gotCache)
				}
				// config.TLS.certRefreshPeriod is not set, GetCertificate is nil
				if gotConfig.GetCertificate != nil {
					return fmt.Errorf("GetCertificate is not nil")
				}
				// config.TLS.certRefreshPeriod is not set, TLSConfig.Certificates is set
				gotCert, _ := x509.ParseCertificate(gotConfig.Certificates[0].Certificate[0])
				wantCert, _ := x509.ParseCertificate(wantConfig.Certificates[0].Certificate[0])
				if gotCert.SerialNumber.String() != wantCert.SerialNumber.String() {
					return fmt.Errorf("Certificate SerialNumber not Matched\tgot: %s\twant: %s", gotCert.SerialNumber, wantCert.SerialNumber)
				}
				return nil
			},
		},
		{
			name: "return value certRefreshPeriod test.",
			args: args{
				cfg: config.TLS{
					CertPath:          "../test/data/dummyServer.crt",
					KeyPath:           "../test/data/dummyServer.key",
					CAPath:            "../test/data/dummyCa.pem",
					CertRefreshPeriod: "12345s",
				},
			},
			wantConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
				CurvePreferences: []tls.CurveID{
					tls.CurveP521,
					tls.CurveP384,
					tls.CurveP256,
					tls.X25519,
				},
				SessionTicketsDisabled: true,
				Certificates: func() []tls.Certificate {
					cert, _ := tls.LoadX509KeyPair(defaultArgs.cfg.CertPath, defaultArgs.cfg.KeyPath)
					return []tls.Certificate{cert}
				}(),
				ClientAuth: tls.RequireAndVerifyClientCert,
			},
			wantCache: &TLSCertificateCache{
				serverCert:        defaultServerCert,
				serverCertHash:    defaultServerCerttHash,
				serverCertKeyHash: defaultServerCerttKeyHash,
				serverCertPath:    defaultArgs.cfg.CertPath,
				serverCertKeyPath: defaultArgs.cfg.KeyPath,
				certRefreshPeriod: 12345 * time.Second,
			},
			checkFunc: func(gotConfig *tls.Config, gotCache *TLSCertificateCache, wantConfig *tls.Config, wantCache *TLSCertificateCache) error {
				if gotConfig.ClientAuth != wantConfig.ClientAuth {
					return fmt.Errorf("ClientAuth not Matched :\tgot %d \twant %d", gotConfig.ClientAuth, wantConfig.ClientAuth)
				}
				// config.TLS.certRefreshPeriod is set, TLSCertificateCache is set
				gotCert, _ := x509.ParseCertificate(gotCache.serverCert.Load().(*tls.Certificate).Certificate[0])
				wantCert, _ := x509.ParseCertificate(wantCache.serverCert.Load().(*tls.Certificate).Certificate[0])
				if gotCert.SerialNumber.String() != wantCert.SerialNumber.String() {
					return fmt.Errorf("Certificate SerialNumber not Matched\tgot: %s\twant: %s", gotCert.SerialNumber, wantCert.SerialNumber)
				}
				// config.TLS.certRefreshPeriod is set, GetCertificate is set
				if gotConfig.GetCertificate == nil {
					return fmt.Errorf("GetCertificate nil")
				}
				// config.TLS.certRefreshPeriod is set, TLSConfig.Certificates is nil
				if gotConfig.Certificates != nil {
					return fmt.Errorf("Certificates not nil\tgot: %v", gotConfig.Certificates)
				}
				if gotCache.certRefreshPeriod != wantCache.certRefreshPeriod {
					return fmt.Errorf("certRefreshPeriod not Matched\tgot: %s\twant: %s", gotCache.certRefreshPeriod, wantCache.certRefreshPeriod)
				}
				return nil
			},
		},
		{
			name: "cert file not found return value Certificates test.",
			args: args{
				cfg: config.TLS{
					CertPath: "",
				},
			},
			wantConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
				CurvePreferences: []tls.CurveID{
					tls.CurveP521,
					tls.CurveP384,
					tls.CurveP256,
					tls.X25519,
				},
				SessionTicketsDisabled: true,
				Certificates:           nil,
				ClientAuth:             tls.RequireAndVerifyClientCert,
			},
			wantCache: nil,
			checkFunc: func(gotConfig *tls.Config, gotCache *TLSCertificateCache, wantConfig *tls.Config, wantCache *TLSCertificateCache) error {
				if gotConfig.Certificates != nil {
					return fmt.Errorf("Certificates not nil")
				}
				return nil
			},
		},
		{
			name: "cert file not found return value ClientAuth test.",
			args: args{
				cfg: config.TLS{
					CertPath: "",
				},
			},
			wantConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
				CurvePreferences: []tls.CurveID{
					tls.CurveP521,
					tls.CurveP384,
					tls.CurveP256,
					tls.X25519,
				},
				SessionTicketsDisabled: true,
				Certificates:           nil,
				ClientAuth:             tls.RequireAndVerifyClientCert,
			},
			wantCache: nil,
			checkFunc: func(gotConfig *tls.Config, gotCache *TLSCertificateCache, wantConfig *tls.Config, wantCache *TLSCertificateCache) error {
				if gotConfig.Certificates != nil {
					return fmt.Errorf("Certificates not nil")
				}
				return nil
			},
		},
		{
			name: "CA file not found return value ClientAuth test.",
			args: args{
				cfg: config.TLS{
					CertPath: "",
					CAPath:   "",
				},
			},

			wantConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
				CurvePreferences: []tls.CurveID{
					tls.CurveP521,
					tls.CurveP384,
					tls.CurveP256,
					tls.X25519,
				},
				SessionTicketsDisabled: true,
				Certificates: func() []tls.Certificate {
					cert, _ := tls.LoadX509KeyPair(defaultArgs.cfg.CertPath, defaultArgs.cfg.KeyPath)
					return []tls.Certificate{cert}
				}(),
				ClientAuth: tls.RequireAndVerifyClientCert,
			},
			wantCache: nil,
			checkFunc: func(gotConfig *tls.Config, gotCache *TLSCertificateCache, wantConfig *tls.Config, wantCache *TLSCertificateCache) error {
				if gotConfig.ClientAuth != 0 {
					return fmt.Errorf("ClientAuth is :\t%d", gotConfig.ClientAuth)
				}
				return nil
			},
		},
		{
			name: "cert file invalid return error test.",
			args: args{
				cfg: config.TLS{
					CertPath: "../test/data/invalid_dummyServer.crt",
					KeyPath:  "../test/data/invalid_dummyServer.key",
				},
			},

			wantConfig: nil,
			wantCache:  nil,
			wantErr:    errors.New("tls.LoadX509KeyPair(cert, key): tls: failed to find any PEM data in certificate input"),
			checkFunc: func(gotConfig *tls.Config, gotCache *TLSCertificateCache, wantConfig *tls.Config, wantCache *TLSCertificateCache) error {
				if gotConfig != nil {
					return fmt.Errorf("gotConfig not nil :\tgot %d \twant %d", &gotConfig, &wantConfig)
				}
				if gotCache != nil {
					return fmt.Errorf("gotConfig not nil :\tgot %d \twant %d", &gotCache, &wantCache)
				}
				return nil
			},
		},
		{
			name: "CertRefreshPeriod  invalid return error test.",
			args: args{
				cfg: config.TLS{
					CertPath:          "../test/data/dummyServer.crt",
					KeyPath:           "../test/data/dummyServer.key",
					CAPath:            "../test/data/dummyCa.pem",
					CertRefreshPeriod: "invalid duration",
				},
			},
			wantConfig: nil,
			wantCache:  nil,
			wantErr:    errors.New("isValidDuration(cfg.CertRefreshPeriod): time: invalid duration \"invalid duration\""),
			checkFunc: func(gotConfig *tls.Config, gotCache *TLSCertificateCache, wantConfig *tls.Config, wantCache *TLSCertificateCache) error {
				if gotConfig != nil {
					return fmt.Errorf("gotConfig not nil :\tgot %d \twant %d", &gotConfig, &wantCache)
				}
				if gotCache != nil {
					return fmt.Errorf("gotConfig not nil :\tgot %d \twant %d", &gotCache, &wantCache)
				}
				return nil
			},
		},
		{
			name: "certificate with trailing dot in SAN should load successfully",
			args: args{
				cfg: config.TLS{
					CertPath: "../test/data/trailing_dot_server.crt",
					KeyPath:  "../test/data/trailing_dot_server.key",
				},
			},
			wantConfig: &tls.Config{MinVersion: tls.VersionTLS12},
			wantCache:  nil,
			wantErr:    nil,
			checkFunc: func(gotConfig *tls.Config, gotCache *TLSCertificateCache, wantConfig *tls.Config, wantCache *TLSCertificateCache) error {
				return nil
			},
		},
		{
			name: "certificate with leading dot in SAN should load successfully",
			args: args{
				cfg: config.TLS{
					CertPath: "../test/data/leading_dot_server.crt",
					KeyPath:  "../test/data/leading_dot_server.key",
				},
			},
			wantConfig: &tls.Config{MinVersion: tls.VersionTLS12},
			wantCache:  nil,
			wantErr:    nil,
			checkFunc: func(gotConfig *tls.Config, gotCache *TLSCertificateCache, wantConfig *tls.Config, wantCache *TLSCertificateCache) error {
				return nil
			},
		},
		{
			name: "certificate with empty label in SAN should load successfully",
			args: args{
				cfg: config.TLS{
					CertPath: "../test/data/empty_label_server.crt",
					KeyPath:  "../test/data/empty_label_server.key",
				},
			},
			wantConfig: &tls.Config{MinVersion: tls.VersionTLS12},
			wantCache:  nil,
			wantErr:    nil,
			checkFunc: func(gotConfig *tls.Config, gotCache *TLSCertificateCache, wantConfig *tls.Config, wantCache *TLSCertificateCache) error {
				return nil
			},
		},
		{
			name: "certificate with long label in SAN should load successfully",
			args: args{
				cfg: config.TLS{
					CertPath: "../test/data/long_label_server.crt",
					KeyPath:  "../test/data/long_label_server.key",
				},
			},
			wantConfig: &tls.Config{MinVersion: tls.VersionTLS12},
			wantCache:  nil,
			wantErr:    nil,
			checkFunc: func(gotConfig *tls.Config, gotCache *TLSCertificateCache, wantConfig *tls.Config, wantCache *TLSCertificateCache) error {
				return nil
			},
		},
		{
			name: "certificate with malformed email in SAN should load successfully",
			args: args{
				cfg: config.TLS{
					CertPath: "../test/data/malformed_email_server.crt",
					KeyPath:  "../test/data/malformed_email_server.key",
				},
			},
			wantConfig: &tls.Config{MinVersion: tls.VersionTLS12},
			wantCache:  nil,
			wantErr:    nil,
			checkFunc: func(gotConfig *tls.Config, gotCache *TLSCertificateCache, wantConfig *tls.Config, wantCache *TLSCertificateCache) error {
				return nil
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.beforeFunc != nil {
				tt.beforeFunc(tt.args)
			}

			gotConfig, gotCache, err := NewTLSConfigWithTLSCertificateCache(tt.args.cfg)
			if tt.wantErr == nil && err != nil {
				t.Errorf("NewTLSConfigWithTLSCertificateCache() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr != nil {
				if tt.wantErr.Error() != err.Error() {
					t.Errorf("NewTLSConfigWithTLSCertificateCache() error = %v, wantErr %v", err, tt.wantErr)
					return
				}
			}

			if tt.checkFunc != nil {
				err = tt.checkFunc(gotConfig, gotCache, tt.wantConfig, tt.wantCache)
				if err != nil {
					t.Errorf("NewTLSConfigWithTLSCertificateCache() error = %v", err)
					return
				}
			}

			if tt.afterFunc != nil {
				tt.afterFunc(tt.args)
			}
		})
	}
}

func TestNewX509CertPool(t *testing.T) {
	type args struct {
		path string
	}

	tests := []struct {
		name      string
		args      args
		want      *x509.CertPool
		checkFunc func(*x509.CertPool, *x509.CertPool) error
		wantErr   bool
	}{
		// TODO: Add test cases.
		{
			name: "Check err if file is not exists",
			args: args{
				path: "",
			},
			want: &x509.CertPool{},
			checkFunc: func(*x509.CertPool, *x509.CertPool) error {
				return nil
			},
			wantErr: true,
		},
		{
			name: "Check Append CA is correct",
			args: args{
				path: "../test/data/dummyCa.pem",
			},
			want: func() *x509.CertPool {
				wantPool := x509.NewCertPool()
				c, err := ioutil.ReadFile("../test/data/dummyCa.pem")
				if err != nil {
					panic(err)
				}
				if !wantPool.AppendCertsFromPEM(c) {
					panic(errors.New("Error appending certs from PEM"))
				}
				return wantPool
			}(),
			checkFunc: func(want *x509.CertPool, got *x509.CertPool) error {
				for _, wantCert := range want.Subjects() {
					exists := false
					for _, gotCert := range got.Subjects() {
						if strings.EqualFold(string(wantCert), string(gotCert)) {
							exists = true
						}
					}
					if !exists {
						return fmt.Errorf("Error\twant\t%s\t not found", string(wantCert))
					}
				}
				return nil
			},
			wantErr: false,
		},
		{
			name: "certificate with trailing dot in SAN should load successfully",
			args: args{
				path: "../test/data/trailing_dot_server.crt",
			},
			want:    &x509.CertPool{},
			wantErr: false,
		},
		{
			name: "certificate with leading dot in SAN should load successfully",
			args: args{
				path: "../test/data/leading_dot_server.crt",
			},
			want:    &x509.CertPool{},
			wantErr: false,
		},
		{
			name: "certificate with empty label in SAN should load successfully",
			args: args{
				path: "../test/data/empty_label_server.crt",
			},
			want:    &x509.CertPool{},
			wantErr: false,
		},
		{
			name: "certificate with long label in SAN should load successfully",
			args: args{
				path: "../test/data/long_label_server.crt",
			},
			want:    &x509.CertPool{},
			wantErr: false,
		},
		{
			name: "certificate with malformed email in SAN should load successfully",
			args: args{
				path: "../test/data/malformed_email_server.crt",
			},
			want:    &x509.CertPool{},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewX509CertPool(tt.args.path)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewX509CertPool() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.checkFunc != nil {
				err = tt.checkFunc(tt.want, got)
				if err != nil {
					t.Errorf("TestNewX509CertPool error = %s", err)
				}
			}
		})
	}
}

func TestTLSCertificateCache_getCertificate(t *testing.T) {
	type fields struct {
		serverCert        atomic.Value
		serverCertHash    []byte
		serverCertKeyHash []byte
		serverCertPath    string
		serverCertKeyPath string
		serverCertMutex   sync.Mutex
		certRefreshPeriod time.Duration
	}
	type args struct {
		h *tls.ClientHelloInfo
	}
	var defaultServerCert atomic.Value
	defaultServerCertData, err := tls.LoadX509KeyPair("../test/data/dummyServer.crt", "../test/data/dummyServer.key")
	if err != nil {
		t.Errorf("LoadX509KeyPair failed: %s", err)
		return
	}
	defaultServerCert.Store(&defaultServerCertData)
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    *tls.Certificate
		wantErr bool
	}{
		{
			name: "Check return serverCert",
			fields: fields{
				serverCert: defaultServerCert,
			},
			args: args{
				h: &tls.ClientHelloInfo{},
			},
			want: defaultServerCert.Load().(*tls.Certificate),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tcc := &TLSCertificateCache{
				serverCert:        tt.fields.serverCert,
				serverCertHash:    tt.fields.serverCertHash,
				serverCertKeyHash: tt.fields.serverCertKeyHash,
				serverCertPath:    tt.fields.serverCertPath,
				serverCertKeyPath: tt.fields.serverCertKeyPath,
				serverCertMutex:   tt.fields.serverCertMutex,
				certRefreshPeriod: tt.fields.certRefreshPeriod,
			}
			got, err := tcc.getCertificate(tt.args.h)
			if (err != nil) != tt.wantErr {
				t.Errorf("TLSCertificateCache.getCertificate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("TLSCertificateCache.getCertificate() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestTLSCertificateCache_RefreshCertificate(t *testing.T) {
	type fields struct {
		serverCert        atomic.Value
		serverCertHash    []byte
		serverCertKeyHash []byte
		serverCertPath    string
		serverCertKeyPath string
		serverCertMutex   sync.Mutex
		certRefreshPeriod time.Duration
	}
	type args struct {
		ctx context.Context
	}
	type test struct {
		name       string
		fields     fields
		args       args
		want       error
		beforeFunc func() error
		checkFunc  func(*TLSCertificateCache, error) error
		afterFunc  func() error
	}
	copyCert := func(srcPath, dstPath string) error {
		src, err := os.Open(srcPath)
		if err != nil {
			t.Errorf("test cert copy failed: %s", err)
			return err
		}
		defer src.Close()

		dst, err := os.Create(dstPath)
		if err != nil {
			t.Errorf("test cert copy failed: %s", err)
			return err
		}
		defer dst.Close()

		_, err = io.Copy(dst, src)
		if err != nil {
			t.Errorf("test cert copy failed: %s", err)
			return err
		}
		return nil
	}
	testCertPath := "../test/data/test.crt"
	testCertKeyPath := "../test/data/test.key"
	oldCertPath := "../test/data/dummyServer.crt"
	oldCertKeyPath := "../test/data/dummyServer.key"
	newCertPath := "../test/data/newDummyServer.crt"
	invalidNewCertPath := "../test/data/invalid_newDummyServer.crt"

	var oldCert atomic.Value
	oldCertData, err := tls.LoadX509KeyPair("../test/data/dummyServer.crt", "../test/data/dummyServer.key")
	if err != nil {
		t.Errorf("LoadX509KeyPair failed: %s", err)
		return
	}
	oldCert.Store(&oldCertData)
	oldCertHash, err := hash(oldCertPath)
	if err != nil {
		t.Errorf("hash failed: %s", err)
		return
	}
	oldCertKeyHash, _ := hash(oldCertKeyPath)
	if err != nil {
		t.Errorf("hash failed: %s", err)
		return
	}
	// newCert key == oldCert key
	newCert, err := tls.LoadX509KeyPair(newCertPath, oldCertKeyPath)
	if err != nil {
		t.Errorf("LoadX509KeyPair failed: %s", err)
		return
	}

	tests := []test{
		func() test {
			ctx, cancelFunc := context.WithCancel(context.Background())

			return test{
				name: "Test refresh server cert and stop",
				fields: fields{
					serverCert:        oldCert,
					serverCertHash:    oldCertHash,
					serverCertKeyHash: oldCertKeyHash,
					serverCertPath:    testCertPath,
					serverCertKeyPath: testCertKeyPath,
					certRefreshPeriod: 500 * time.Millisecond,
					serverCertMutex:   sync.Mutex{},
				},
				args: args{
					ctx: ctx,
				},
				beforeFunc: func() error {
					err := copyCert(oldCertPath, testCertPath)
					if err != nil {
						return err
					}
					err = copyCert(oldCertKeyPath, testCertKeyPath)
					if err != nil {
						return err
					}
					return nil
				},
				checkFunc: func(tcc *TLSCertificateCache, want error) error {
					cachedCert := tcc.serverCert.Load()
					cc, _ := x509.ParseCertificate(cachedCert.(*tls.Certificate).Certificate[0])
					oc, _ := x509.ParseCertificate(oldCertData.Certificate[0])
					if cc.SerialNumber.String() != oc.SerialNumber.String() {
						return errors.New("cached cert / old cert Serial Number not Matched")
					}
					// refresh certificate
					err = copyCert(newCertPath, testCertPath)
					if err != nil {
						return err
					}
					// wait refresh period
					time.Sleep(1 * time.Second)
					cachedCert = tcc.serverCert.Load()
					cc, _ = x509.ParseCertificate(cachedCert.(*tls.Certificate).Certificate[0])
					nc, _ := x509.ParseCertificate(newCert.Certificate[0])
					// check cert refreshed
					if cc.SerialNumber.String() != nc.SerialNumber.String() {
						return errors.New("cert not refreshed")
					}
					// refresh stop
					cancelFunc()
					err = copyCert(oldCertPath, testCertPath)
					if err != nil {
						return err
					}
					time.Sleep(1 * time.Second)
					if cc.SerialNumber.String() == oc.SerialNumber.String() {
						return errors.New("refresh not stopped")
					}
					return nil
				},
				afterFunc: func() error {
					cancelFunc()
					err := os.Remove(testCertPath)
					if err != nil {
						t.Errorf("test cert remove failed: %s", err)
						return err
					}
					err = os.Remove(testCertKeyPath)
					if err != nil {
						t.Errorf("test cert remove failed: %s", err)
						return err
					}
					return nil
				},
			}
		}(),
		func() test {
			ctx, cancelFunc := context.WithCancel(context.Background())

			return test{
				name: "Test not refresh and stop",
				fields: fields{
					serverCert:        oldCert,
					serverCertHash:    oldCertHash,
					serverCertKeyHash: oldCertKeyHash,
					serverCertPath:    testCertPath,
					serverCertKeyPath: testCertKeyPath,
					certRefreshPeriod: 500 * time.Millisecond,
					serverCertMutex:   sync.Mutex{},
				},
				args: args{
					ctx: ctx,
				},
				beforeFunc: func() error {
					err := copyCert(oldCertPath, testCertPath)
					if err != nil {
						return err
					}
					err = copyCert(oldCertKeyPath, testCertKeyPath)
					if err != nil {
						return err
					}
					return nil
				},
				checkFunc: func(tcc *TLSCertificateCache, want error) error {
					cachedCert := tcc.serverCert.Load()
					cc, _ := x509.ParseCertificate(cachedCert.(*tls.Certificate).Certificate[0])
					oc, _ := x509.ParseCertificate(oldCertData.Certificate[0])
					if cc.SerialNumber.String() != oc.SerialNumber.String() {
						return errors.New("cached cert / old cert Serial Number not Matched")
					}

					// wait refresh period
					time.Sleep(1 * time.Second)
					cachedCert = tcc.serverCert.Load()
					cc, _ = x509.ParseCertificate(cachedCert.(*tls.Certificate).Certificate[0])
					// check cert not refreshed
					if cc.SerialNumber.String() != oc.SerialNumber.String() {
						return errors.New("cached cert / old cert Serial Number not Matched")
					}
					// refresh stop
					cancelFunc()
					err = copyCert(newCertPath, testCertPath)
					if err != nil {
						return err
					}
					time.Sleep(1 * time.Second)
					nc, _ := x509.ParseCertificate(newCert.Certificate[0])
					if cc.SerialNumber.String() == nc.SerialNumber.String() {
						return errors.New("refresh not stopped")
					}
					return nil
				},
				afterFunc: func() error {
					cancelFunc()
					err := os.Remove(testCertPath)
					if err != nil {
						t.Errorf("test cert remove failed: %s", err)
						return err
					}
					err = os.Remove(testCertKeyPath)
					if err != nil {
						t.Errorf("test cert remove failed: %s", err)
						return err
					}
					return nil
				},
			}
		}(),
		func() test {
			ctx, cancelFunc := context.WithCancel(context.Background())

			return test{
				name: "Test invalid cert not refresh, next period refresh success",
				fields: fields{
					serverCert:        oldCert,
					serverCertHash:    oldCertHash,
					serverCertKeyHash: oldCertKeyHash,
					serverCertPath:    testCertPath,
					serverCertKeyPath: testCertKeyPath,
					certRefreshPeriod: 500 * time.Millisecond,
					serverCertMutex:   sync.Mutex{},
				},
				args: args{
					ctx: ctx,
				},
				beforeFunc: func() error {
					err := copyCert(oldCertPath, testCertPath)
					if err != nil {
						return err
					}
					err = copyCert(oldCertKeyPath, testCertKeyPath)
					if err != nil {
						return err
					}
					return nil
				},
				checkFunc: func(tcc *TLSCertificateCache, want error) error {
					cachedCert := tcc.serverCert.Load()
					cc, _ := x509.ParseCertificate(cachedCert.(*tls.Certificate).Certificate[0])
					oc, _ := x509.ParseCertificate(oldCertData.Certificate[0])
					if cc.SerialNumber.String() != oc.SerialNumber.String() {
						return errors.New("cached cert / old cert Serial Number not Matched")
					}
					// refresh certificate but invalid
					err = copyCert(invalidNewCertPath, testCertPath)
					if err != nil {
						return err
					}
					// wait refresh period
					time.Sleep(1 * time.Second)
					cachedCert = tcc.serverCert.Load()
					cc, _ = x509.ParseCertificate(cachedCert.(*tls.Certificate).Certificate[0])
					// check cert not refreshed
					if cc.SerialNumber.String() != oc.SerialNumber.String() {
						return errors.New("cert refreshed")
					}
					// refresh certificate
					err = copyCert(newCertPath, testCertPath)
					if err != nil {
						return err
					}
					// wait refresh period
					time.Sleep(1 * time.Second)
					cachedCert = tcc.serverCert.Load()
					cc, _ = x509.ParseCertificate(cachedCert.(*tls.Certificate).Certificate[0])
					nc, _ := x509.ParseCertificate(newCert.Certificate[0])
					// check cert refreshed
					if cc.SerialNumber.String() != nc.SerialNumber.String() {
						return errors.New("cert not refreshed")
					}
					cancelFunc()
					return nil
				},
				afterFunc: func() error {
					cancelFunc()
					err := os.Remove(testCertPath)
					if err != nil {
						t.Errorf("test cert remove failed: %s", err)
						return err
					}
					err = os.Remove(testCertKeyPath)
					if err != nil {
						t.Errorf("test cert remove failed: %s", err)
						return err
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

			tcc := &TLSCertificateCache{
				serverCert:        tt.fields.serverCert,
				serverCertHash:    tt.fields.serverCertHash,
				serverCertKeyHash: tt.fields.serverCertKeyHash,
				serverCertPath:    tt.fields.serverCertPath,
				serverCertKeyPath: tt.fields.serverCertKeyPath,
				serverCertMutex:   tt.fields.serverCertMutex,
				certRefreshPeriod: tt.fields.certRefreshPeriod,
			}
			// errCh := make(chan error)
			go func() error {
				return tcc.RefreshCertificate(tt.args.ctx)
			}()
			if err := tt.checkFunc(tcc, tt.want); err != nil {
				t.Errorf("TLSCertificateCache.RefreshCertificate() error = %v, want %v", err, tt.want)
			}
		})
	}
}

func Test_isValidDuration(t *testing.T) {
	type args struct {
		durationString string
	}
	tests := []struct {
		name    string
		args    args
		want    bool
		wantErr error
	}{
		{
			name: "test true, valid duration",
			args: args{
				durationString: "123s",
			},
			want: true,
		},
		{
			name: "test false, empty string",
			args: args{
				durationString: "",
			},
			want: false,
		},
		{
			name: "test false, zero",
			args: args{
				durationString: "0h",
			},
			want: false,
		},
		{
			name: "test false and error, abcdefg",
			args: args{
				durationString: "abcdefg",
			},
			want:    false,
			wantErr: errors.New("time: invalid duration \"abcdefg\""),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := isValidDuration(tt.args.durationString)
			if tt.wantErr != nil {
				if err.Error() != tt.wantErr.Error() {
					t.Errorf("isValidDuration() error = %s, wantErr %s", err.Error(), tt.wantErr.Error())
				}
			}
			if got != tt.want {
				t.Errorf("isValidDuration() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_cipherSuites(t *testing.T) {
	type args struct {
		dcs  []string
		eics []string
	}
	tests := []struct {
		name    string
		args    args
		want    []uint16
		wantErr error
	}{
		{
			name: "Check TLS.DisableCipherSuites == nil, default cipher suites is available",
			args: args{
				dcs:  nil,
				eics: nil,
			},
			want: func() (cipherSuites []uint16) {
				ciphers := make(map[string]uint16, len(tls.CipherSuites()))
				for _, c := range tls.CipherSuites() {
					ciphers[c.Name] = c.ID
				}
				for _, id := range ciphers {
					cipherSuites = append(cipherSuites, id)
				}
				return cipherSuites
			}(),
			wantErr: nil,
		},
		{
			name: "Check default cipher suite is used when cipher suite specified in disableCipherSuites is invalid",
			args: args{
				dcs: []string{
					"dummy",
				},
				eics: nil,
			},
			want: func() (cipherSuites []uint16) {
				ciphers := make(map[string]uint16, len(tls.CipherSuites()))
				for _, c := range tls.CipherSuites() {
					ciphers[c.Name] = c.ID
				}
				for _, id := range ciphers {
					cipherSuites = append(cipherSuites, id)
				}
				return cipherSuites
			}(),
			wantErr: nil,
		},
		{
			name: "Check disable cipher suites containing SHA-1",
			args: args{
				dcs: []string{
					"TLS_RSA_WITH_AES_128_CBC_SHA",
					"TLS_RSA_WITH_AES_256_CBC_SHA",
					"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
					"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
					"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
					"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
				},
				eics: nil,
			},
			want: []uint16{
				tls.TLS_AES_128_GCM_SHA256,
				tls.TLS_AES_256_GCM_SHA384,
				tls.TLS_CHACHA20_POLY1305_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
				tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			},
			wantErr: nil,
		},
		{
			name: "Check enable insecure cipher suites",
			args: args{
				dcs: []string{
					"TLS_RSA_WITH_AES_128_CBC_SHA",
					"TLS_RSA_WITH_AES_256_CBC_SHA",
					"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
					"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
					"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
					"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
				},
				eics: []string{
					"TLS_RSA_WITH_RC4_128_SHA",
					"TLS_ECDHE_ECDSA_WITH_RC4_128_SHA",
					"TLS_ECDHE_RSA_WITH_RC4_128_SHA",
					"TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
					"TLS_RSA_WITH_3DES_EDE_CBC_SHA",
				},
			},
			want: []uint16{
				tls.TLS_AES_128_GCM_SHA256,
				tls.TLS_AES_256_GCM_SHA384,
				tls.TLS_CHACHA20_POLY1305_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
				tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				tls.TLS_RSA_WITH_RC4_128_SHA,
				tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
				tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA,
				tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
				tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
			},
			wantErr: nil,
		},
		{
			name: "Check enable allowInsecureCipherSuites",
			args: args{
				dcs: []string{
					"TLS_RSA_WITH_AES_128_CBC_SHA",
					"TLS_RSA_WITH_AES_256_CBC_SHA",
					"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
					"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
					"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
					"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
				},
				eics: []string{
					"TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
					"TLS_RSA_WITH_3DES_EDE_CBC_SHA",
				},
			},
			want: []uint16{
				tls.TLS_AES_128_GCM_SHA256,
				tls.TLS_AES_256_GCM_SHA384,
				tls.TLS_CHACHA20_POLY1305_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
				tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
				tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
			},
			wantErr: nil,
		},
		{
			name: "Check default cipher suite is used when cipher suite specified in enableInsecureCipherSuites is invalid",
			args: args{
				dcs: nil,
				eics: []string{
					"insecureDummy",
				},
			},
			want: func() (cipherSuites []uint16) {
				ciphers := make(map[string]uint16, len(tls.CipherSuites()))
				for _, c := range tls.CipherSuites() {
					ciphers[c.Name] = c.ID
				}
				for _, id := range ciphers {
					cipherSuites = append(cipherSuites, id)
				}
				return cipherSuites
			}(),
			wantErr: nil,
		},
		{
			name: "Check valid cipher suite is configured when both disableCipherSuites and enableInsecureCipherSuites are specified",
			args: args{
				dcs: []string{
					"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
				},
				eics: []string{
					"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
				},
			},
			want: func() (cipherSuites []uint16) {
				ciphers := make(map[string]uint16, len(tls.CipherSuites()))
				for _, c := range tls.CipherSuites() {
					ciphers[c.Name] = c.ID
				}
				delete(ciphers, "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA")
				for _, id := range ciphers {
					cipherSuites = append(cipherSuites, id)
				}
				return cipherSuites
			}(),
			wantErr: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := cipherSuites(tt.args.dcs, tt.args.eics)
			sort.Slice(got, func(i, j int) bool {
				return got[i] < got[j]
			})
			sort.Slice(tt.want, func(i, j int) bool {
				return tt.want[i] < tt.want[j]
			})
			if tt.wantErr != nil {
				if err.Error() != tt.wantErr.Error() {
					t.Errorf("cipherSuites() error = %s, wantErr %s", err.Error(), tt.wantErr.Error())
				}
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("cipherSuites() = %v, want %v", got, tt.want)
			}
		})
	}
}
