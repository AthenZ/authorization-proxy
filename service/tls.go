/*
Copyright (C)  2018 Yahoo Japan Corporation Athenz team.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package service

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"io"
	"io/ioutil"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/AthenZ/authorization-proxy/v4/config"
	"github.com/kpango/glg"
	"github.com/pkg/errors"
)

// TLSCertificateCache caches a certificate
type TLSCertificateCache struct {
	serverCert        atomic.Value
	serverCertHash    []byte
	serverCertKeyHash []byte
	serverCertPath    string
	serverCertKeyPath string
	serverCertMutex   sync.Mutex
	certRefreshPeriod time.Duration
}

type TLSConfigWithTLSCertificateCache struct {
	TLSConfig           *tls.Config
	TLSCertificateCache *TLSCertificateCache
}

// NewTLSConfig returns a *tls.Config struct or error.
// It reads TLS configuration and initializes *tls.Config struct.
// It initializes TLS configuration, for example the CA certificate and key to start TLS server.
// Server and CA Certificate, and private key will read from files from file paths defined in environment variables.
func NewTLSConfig(cfg config.TLS) (*tls.Config, error) {
	t, err := NewTLSConfigWithTLSCertificateCache(cfg)
	if err != nil {
		return nil, err
	}
	// GetCertificate can only be used with TLSCertificateCache.
	t.TLSConfig.GetCertificate = nil
	cert := config.GetActualValue(cfg.CertPath)
	key := config.GetActualValue(cfg.KeyPath)
	if cert != "" && key != "" {
		crt, err := tls.LoadX509KeyPair(cert, key)
		if err != nil {
			return nil, errors.Wrap(err, "tls.LoadX509KeyPair(cert, key)")
		}
		t.TLSConfig.Certificates = make([]tls.Certificate, 1)
		t.TLSConfig.Certificates[0] = crt
	}
	return t.TLSConfig, nil
}

// NewTLSConfigWithTLSCertificateCache returns a *TLSConfigWithTLSCertificateCache struct or error.
// cfg.CertRefreshPeriod is set(cert refresh enable), returns TLSCertificateCache: not nil / TLSConfig.GetCertificate: not nil / TLSConfig.Certificates: nil
// cfg.CertRefreshPeriod is not set(cert refresh disable), returns TLSCertificateCache: nil / TLSConfig.GetCertificate: nil / TLSConfig.Certificates: not nil
// It uses to enable the certificate auto-reload feature.
// It reads TLS configuration and initializes *tls.Config / *TLSCertificateCache struct.
// It initializes TLS configuration, for example the CA certificate and key to start TLS server.
// Server and CA Certificate, and private key will read from files from file paths defined in environment variables.
func NewTLSConfigWithTLSCertificateCache(cfg config.TLS) (*TLSConfigWithTLSCertificateCache, error) {
	var tcc *TLSCertificateCache
	t := &tls.Config{
		MinVersion: tls.VersionTLS12,
		CurvePreferences: []tls.CurveID{
			tls.CurveP521,
			tls.CurveP384,
			tls.CurveP256,
			tls.X25519,
		},
		SessionTicketsDisabled: true,
		ClientAuth:             tls.NoClientCert,
	}

	var err error

	cert := config.GetActualValue(cfg.CertPath)
	key := config.GetActualValue(cfg.KeyPath)
	ca := config.GetActualValue(cfg.CAPath)

	isEnableCertRefresh, err := isValidDuration(cfg.CertRefreshPeriod)
	if err != nil {
		return nil, errors.Wrap(err, "cannot isValidDuration(cfg.CertRefreshPeriod)")
	}
	if isEnableCertRefresh {
		// GetCertificate can only be used with TLSCertificateCache.
		tcc = &TLSCertificateCache{}
		t.GetCertificate = tcc.getCertificate

		tcc.certRefreshPeriod, err = time.ParseDuration(cfg.CertRefreshPeriod)
		if err != nil {
			return nil, errors.Wrap(err, "ParseDuration(cfg.CertRefreshPeriod)")
		}
		if cert != "" && key != "" {
			crt, err := tls.LoadX509KeyPair(cert, key)
			if err != nil {
				return nil, errors.Wrap(err, "tls.LoadX509KeyPair(cert, key)")
			}

			crtHash, err := hash(cert)
			if err != nil {
				return nil, errors.Wrap(err, "hash(cert)")
			}

			crtKeyHash, err := hash(key)
			if err != nil {
				return nil, errors.Wrap(err, "hash(key)")
			}
			tcc.serverCert.Store(&crt)
			tcc.serverCertHash = crtHash
			tcc.serverCertKeyHash = crtKeyHash
			tcc.serverCertPath = cert
			tcc.serverCertKeyPath = key
		}
	} else {
		if cert != "" && key != "" {
			crt, err := tls.LoadX509KeyPair(cert, key)
			if err != nil {
				return nil, errors.Wrap(err, "tls.LoadX509KeyPair(cert, key)")
			}
			t.Certificates = make([]tls.Certificate, 1)
			t.Certificates[0] = crt
		}
	}

	if ca != "" {
		pool, err := NewX509CertPool(ca)
		if err != nil {
			return nil, errors.Wrap(err, "NewX509CertPool(ca)")
		}
		t.ClientCAs = pool
		t.ClientAuth = tls.RequireAndVerifyClientCert
	}

	return &TLSConfigWithTLSCertificateCache{
		TLSConfig:           t,
		TLSCertificateCache: tcc,
	}, nil
}

// NewX509CertPool returns *x509.CertPool struct or error.
// The CertPool will read the certificate from the path, and append the content to the system certificate pool.
func NewX509CertPool(path string) (*x509.CertPool, error) {
	var pool *x509.CertPool
	c, err := ioutil.ReadFile(path)
	if err == nil && c != nil {
		pool, err = x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(c) {
			err = errors.New("Certification Failed")
		}
	}
	return pool, errors.Wrap(err, "x509.SystemCertPool()")
}

// getCertificate returns the cached certificate.
func (tcc *TLSCertificateCache) getCertificate(h *tls.ClientHelloInfo) (*tls.Certificate, error) {
	// serverCert is atomic.Value, so this can read it without lock.
	return tcc.serverCert.Load().(*tls.Certificate), nil
}

// RefreshCertificate refreshes the cached certificate asynchronously.
func (tcc *TLSCertificateCache) RefreshCertificate(ctx context.Context) error {
	ticker := time.NewTicker(tcc.certRefreshPeriod)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			glg.Info("Start refreshing server certificate")
			serverCertHash, err := hash(tcc.serverCertPath)
			if err != nil {
				glg.Error("Failed to refresh server certificate: %s.", err.Error())
				continue
			}
			serverCertKeyHash, err := hash(tcc.serverCertKeyPath)
			if err != nil {
				glg.Error("Failed to refresh server certificate: %s.", err.Error())
				continue
			}
			// lock the whole struct before write (prevent race from multiple calls).
			// serverCert is atomic.Value, so this can read it without lock.
			tcc.serverCertMutex.Lock()
			different := !bytes.Equal(tcc.serverCertHash, serverCertHash) ||
				!bytes.Equal(tcc.serverCertKeyHash, serverCertKeyHash)

			if different {
				newCert, err := tls.LoadX509KeyPair(tcc.serverCertPath, tcc.serverCertKeyPath)
				if err != nil {
					glg.Error("Failed to refresh server certificate: %s.", err.Error())
					tcc.serverCertMutex.Unlock()
					continue
				}
				tcc.serverCert.Store(&newCert)
				tcc.serverCertHash = serverCertHash
				tcc.serverCertKeyHash = serverCertKeyHash
				glg.Info("Refreshed server certificate")
			}
			tcc.serverCertMutex.Unlock()
		}
	}
}

func hash(file string) ([]byte, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return nil, err
	}

	return h.Sum(nil), nil
}

// isValidDuration returns whether duration is valid.
// "" -> false, "abcdefg" -> false, "0s" -> false, "123s" -> true
func isValidDuration(durationString string) (bool, error) {
	if durationString != "" {
		crp, err := time.ParseDuration(durationString)
		if err != nil {
			return false, err
		}
		if crp == 0 {
			return false, nil
		}
		return true, nil
	}
	return false, nil
}
