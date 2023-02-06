package service

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io/ioutil"
	"reflect"
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
			CertPath: "../test/data/dummyServer.crt",
			KeyPath:  "../test/data/dummyServer.key",
			CAPath:   "../test/data/dummyCa.pem",
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
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.beforeFunc != nil {
				tt.beforeFunc(tt.args)
			}

			got, err := NewTLSConfig(tt.args.cfg)
			if err != nil {
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
		want       *TLSConfigWithTLSCertificateCache
		beforeFunc func(args args)
		checkFunc  func(*TLSConfigWithTLSCertificateCache, *TLSConfigWithTLSCertificateCache) error
		afterFunc  func(args args)
		wantErr    error
	}{
		{
			name: "return value MinVersion test.",
			args: defaultArgs,
			want: &TLSConfigWithTLSCertificateCache{
				&tls.Config{
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
				&TLSCertificateCache{
					serverCert:        defaultServerCert,
					serverCertHash:    defaultServerCerttHash,
					serverCertKeyHash: defaultServerCerttKeyHash,
					serverCertPath:    defaultArgs.cfg.CertPath,
					serverCertKeyPath: defaultArgs.cfg.KeyPath,
					certRefreshPeriod: 0,
				},
			},
			checkFunc: func(got, want *TLSConfigWithTLSCertificateCache) error {
				if got.TLSConfig.MinVersion != want.TLSConfig.MinVersion {
					return fmt.Errorf("MinVersion not Matched :\tgot %d\twant %d", got.TLSConfig.MinVersion, want.TLSConfig.MinVersion)
				}
				gotCert, _ := x509.ParseCertificate(got.TLSCertficateCache.serverCert.Load().(*tls.Certificate).Certificate[0])
				wantCert, _ := x509.ParseCertificate(want.TLSCertficateCache.serverCert.Load().(*tls.Certificate).Certificate[0])
				if gotCert.SerialNumber.String() != wantCert.SerialNumber.String() {
					return fmt.Errorf("Certificate SerialNumber not Matched\tgot: %s\twant: %s", gotCert.SerialNumber, wantCert.SerialNumber)
				}
				if got.TLSCertficateCache.certRefreshPeriod != want.TLSCertficateCache.certRefreshPeriod {
					return fmt.Errorf("certRefreshPeriod not Matched\tgot: %s\twant: %s", got.TLSCertficateCache.certRefreshPeriod, want.TLSCertficateCache.certRefreshPeriod)
				}
				return nil
			},
		},
		{
			name: "return value CurvePreferences test.",
			args: defaultArgs,
			want: &TLSConfigWithTLSCertificateCache{&tls.Config{
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
				&TLSCertificateCache{
					serverCert:        defaultServerCert,
					serverCertHash:    defaultServerCerttHash,
					serverCertKeyHash: defaultServerCerttKeyHash,
					serverCertPath:    defaultArgs.cfg.CertPath,
					serverCertKeyPath: defaultArgs.cfg.KeyPath,
					certRefreshPeriod: 0,
				},
			},
			checkFunc: func(got, want *TLSConfigWithTLSCertificateCache) error {
				if len(got.TLSConfig.CurvePreferences) != len(want.TLSConfig.CurvePreferences) {
					return fmt.Errorf("CurvePreferences not Matched length:\tgot %d\twant %d", len(got.TLSConfig.CurvePreferences), len(want.TLSConfig.CurvePreferences))
				}
				for _, actualValue := range got.TLSConfig.CurvePreferences {
					var match bool
					for _, expectedValue := range want.TLSConfig.CurvePreferences {
						if actualValue == expectedValue {
							match = true
							break
						}
					}

					if !match {
						return fmt.Errorf("CurvePreferences not Find :\twant %d", want.TLSConfig.MinVersion)
					}
				}
				gotCert, _ := x509.ParseCertificate(got.TLSCertficateCache.serverCert.Load().(*tls.Certificate).Certificate[0])
				wantCert, _ := x509.ParseCertificate(want.TLSCertficateCache.serverCert.Load().(*tls.Certificate).Certificate[0])
				if gotCert.SerialNumber.String() != wantCert.SerialNumber.String() {
					return fmt.Errorf("Certificate SerialNumber not Matched\tgot: %s\twant: %s", gotCert.SerialNumber, wantCert.SerialNumber)
				}
				if got.TLSCertficateCache.certRefreshPeriod != want.TLSCertficateCache.certRefreshPeriod {
					return fmt.Errorf("certRefreshPeriod not Matched\tgot: %s\twant: %s", got.TLSCertficateCache.certRefreshPeriod, want.TLSCertficateCache.certRefreshPeriod)
				}
				return nil
			},
		},
		{
			name: "return value SessionTicketsDisabled test.",
			args: defaultArgs,
			want: &TLSConfigWithTLSCertificateCache{
				&tls.Config{
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
				&TLSCertificateCache{
					serverCert:        defaultServerCert,
					serverCertHash:    defaultServerCerttHash,
					serverCertKeyHash: defaultServerCerttKeyHash,
					serverCertPath:    defaultArgs.cfg.CertPath,
					serverCertKeyPath: defaultArgs.cfg.KeyPath,
					certRefreshPeriod: 0,
				},
			},
			checkFunc: func(got, want *TLSConfigWithTLSCertificateCache) error {
				if got.TLSConfig.SessionTicketsDisabled != want.TLSConfig.SessionTicketsDisabled {
					return fmt.Errorf("SessionTicketsDisabled not matched :\tgot %v\twant %v", got.TLSConfig.SessionTicketsDisabled, want.TLSConfig.SessionTicketsDisabled)
				}
				gotCert, _ := x509.ParseCertificate(got.TLSCertficateCache.serverCert.Load().(*tls.Certificate).Certificate[0])
				wantCert, _ := x509.ParseCertificate(want.TLSCertficateCache.serverCert.Load().(*tls.Certificate).Certificate[0])
				if gotCert.SerialNumber.String() != wantCert.SerialNumber.String() {
					return fmt.Errorf("Certificate SerialNumber not Matched\tgot: %s\twant: %s", gotCert.SerialNumber, wantCert.SerialNumber)
				}
				if got.TLSCertficateCache.certRefreshPeriod != want.TLSCertficateCache.certRefreshPeriod {
					return fmt.Errorf("certRefreshPeriod not Matched\tgot: %s\twant: %s", got.TLSCertficateCache.certRefreshPeriod, want.TLSCertficateCache.certRefreshPeriod)
				}
				return nil
			},
		},
		{
			name: "return value Certificates test.",
			args: defaultArgs,
			want: &TLSConfigWithTLSCertificateCache{
				&tls.Config{
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
				&TLSCertificateCache{
					serverCert:        defaultServerCert,
					serverCertHash:    defaultServerCerttHash,
					serverCertKeyHash: defaultServerCerttKeyHash,
					serverCertPath:    defaultArgs.cfg.CertPath,
					serverCertKeyPath: defaultArgs.cfg.KeyPath,
					certRefreshPeriod: 0,
				},
			},
			checkFunc: func(got, want *TLSConfigWithTLSCertificateCache) error {
				for _, wantVal := range want.TLSConfig.Certificates {
					notExist := false
					for _, gotVal := range got.TLSConfig.Certificates {
						if gotVal.PrivateKey == wantVal.PrivateKey {
							notExist = true
							break
						}
					}
					if notExist {
						return fmt.Errorf("Certificates PrivateKey not Matched :\twant %s", wantVal.PrivateKey)
					}
				}
				gotCert, _ := x509.ParseCertificate(got.TLSCertficateCache.serverCert.Load().(*tls.Certificate).Certificate[0])
				wantCert, _ := x509.ParseCertificate(want.TLSCertficateCache.serverCert.Load().(*tls.Certificate).Certificate[0])
				if gotCert.SerialNumber.String() != wantCert.SerialNumber.String() {
					return fmt.Errorf("Certificate SerialNumber not Matched\tgot: %s\twant: %s", gotCert.SerialNumber, wantCert.SerialNumber)
				}
				if got.TLSCertficateCache.certRefreshPeriod != want.TLSCertficateCache.certRefreshPeriod {
					return fmt.Errorf("certRefreshPeriod not Matched\tgot: %s\twant: %s", got.TLSCertficateCache.certRefreshPeriod, want.TLSCertficateCache.certRefreshPeriod)
				}
				return nil
			},
		},
		{
			name: "return value ClientAuth test.",
			args: defaultArgs,
			want: &TLSConfigWithTLSCertificateCache{
				&tls.Config{
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
				&TLSCertificateCache{
					serverCert:        defaultServerCert,
					serverCertHash:    defaultServerCerttHash,
					serverCertKeyHash: defaultServerCerttKeyHash,
					serverCertPath:    defaultArgs.cfg.CertPath,
					serverCertKeyPath: defaultArgs.cfg.KeyPath,
					certRefreshPeriod: 0,
				},
			},
			checkFunc: func(got, want *TLSConfigWithTLSCertificateCache) error {
				if got.TLSConfig.ClientAuth != want.TLSConfig.ClientAuth {
					return fmt.Errorf("ClientAuth not Matched :\tgot %d \twant %d", got.TLSConfig.ClientAuth, want.TLSConfig.ClientAuth)
				}
				gotCert, _ := x509.ParseCertificate(got.TLSCertficateCache.serverCert.Load().(*tls.Certificate).Certificate[0])
				wantCert, _ := x509.ParseCertificate(want.TLSCertficateCache.serverCert.Load().(*tls.Certificate).Certificate[0])
				if gotCert.SerialNumber.String() != wantCert.SerialNumber.String() {
					return fmt.Errorf("Certificate SerialNumber not Matched\tgot: %s\twant: %s", gotCert.SerialNumber, wantCert.SerialNumber)
				}
				if got.TLSCertficateCache.certRefreshPeriod != want.TLSCertficateCache.certRefreshPeriod {
					return fmt.Errorf("certRefreshPeriod not Matched\tgot: %s\twant: %s", got.TLSCertficateCache.certRefreshPeriod, want.TLSCertficateCache.certRefreshPeriod)
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
			want: &TLSConfigWithTLSCertificateCache{
				&tls.Config{
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
				&TLSCertificateCache{
					serverCert:        defaultServerCert,
					serverCertHash:    defaultServerCerttHash,
					serverCertKeyHash: defaultServerCerttKeyHash,
					serverCertPath:    defaultArgs.cfg.CertPath,
					serverCertKeyPath: defaultArgs.cfg.KeyPath,
					certRefreshPeriod: 12345 * time.Second,
				},
			},
			checkFunc: func(got, want *TLSConfigWithTLSCertificateCache) error {
				if got.TLSConfig.ClientAuth != want.TLSConfig.ClientAuth {
					return fmt.Errorf("ClientAuth not Matched :\tgot %d \twant %d", got.TLSConfig.ClientAuth, want.TLSConfig.ClientAuth)
				}
				gotCert, _ := x509.ParseCertificate(got.TLSCertficateCache.serverCert.Load().(*tls.Certificate).Certificate[0])
				wantCert, _ := x509.ParseCertificate(want.TLSCertficateCache.serverCert.Load().(*tls.Certificate).Certificate[0])
				if gotCert.SerialNumber.String() != wantCert.SerialNumber.String() {
					return fmt.Errorf("Certificate SerialNumber not Matched\tgot: %s\twant: %s", gotCert.SerialNumber, wantCert.SerialNumber)
				}
				if got.TLSCertficateCache.certRefreshPeriod != want.TLSCertficateCache.certRefreshPeriod {
					return fmt.Errorf("certRefreshPeriod not Matched\tgot: %s\twant: %s", got.TLSCertficateCache.certRefreshPeriod, want.TLSCertficateCache.certRefreshPeriod)
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
			want: &TLSConfigWithTLSCertificateCache{
				&tls.Config{
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
				&TLSCertificateCache{},
			},
			checkFunc: func(got, want *TLSConfigWithTLSCertificateCache) error {
				if got.TLSConfig.Certificates != nil {
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
			want: &TLSConfigWithTLSCertificateCache{
				&tls.Config{
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
				&TLSCertificateCache{},
			},
			checkFunc: func(got, want *TLSConfigWithTLSCertificateCache) error {
				if got.TLSConfig.Certificates != nil {
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

			want: &TLSConfigWithTLSCertificateCache{
				&tls.Config{
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
				&TLSCertificateCache{},
			},
			checkFunc: func(got, want *TLSConfigWithTLSCertificateCache) error {
				if got.TLSConfig.ClientAuth != 0 {
					return fmt.Errorf("ClientAuth is :\t%d", got.TLSConfig.ClientAuth)
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
			want:    nil,
			wantErr: errors.New("ParseDuration(cfg.CertRefreshPeriod): time: invalid duration \"invalid duration\""),
			checkFunc: func(got, want *TLSConfigWithTLSCertificateCache) error {
				if got != nil {
					return fmt.Errorf("got not nil :\tgot %d \twant %d", &got, &want)
				}
				return nil
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.beforeFunc != nil {
				tt.beforeFunc(tt.args)
			}

			got, err := NewTLSConfigWithTLSCertificateCache(tt.args.cfg)
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
				err = tt.checkFunc(got, tt.want)
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
