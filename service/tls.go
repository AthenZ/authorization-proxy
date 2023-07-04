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
	"strings"
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

// NewTLSConfig returns a *tls.Config struct or error.
// It reads TLS configuration and initializes *tls.Config struct.
// It initializes TLS configuration, for example the CA certificate and key to start TLS server.
// Server and CA Certificate, and private key will read from files from file paths defined in environment variables.
func NewTLSConfig(cfg config.TLS) (*tls.Config, error) {
	// This is config for not using TLSCertificateCache.
	modifiedCfg := cfg
	modifiedCfg.CertRefreshPeriod = ""
	t, _, err := NewTLSConfigWithTLSCertificateCache(modifiedCfg)
	if err != nil {
		return nil, err
	}
	return t, nil
}

// NewTLSConfigWithTLSCertificateCache returns a *tls.Config/*TLSCertificateCache struct or error.
// cfg.CertRefreshPeriod is set(cert refresh enable), returns TLSCertificateCache: not nil / TLSConfig.GetCertificate: not nil / TLSConfig.Certificates: nil
// cfg.CertRefreshPeriod is not set(cert refresh disable), returns TLSCertificateCache: nil / TLSConfig.GetCertificate: nil / TLSConfig.Certificates: not nil
// It uses to enable the certificate auto-reload feature.
// It reads TLS configuration and initializes *tls.Config / *TLSCertificateCache struct.
// It initializes TLS configuration, for example the CA certificate and key to start TLS server.
// Server and CA Certificate, and private key will read from files from file paths defined in environment variables.
func NewTLSConfigWithTLSCertificateCache(cfg config.TLS) (*tls.Config, *TLSCertificateCache, error) {
	var tcc *TLSCertificateCache

	cs, err := cipherSuites(cfg.DisableCipherSuites, cfg.EnableInsecureCipherSuites)
	if err != nil {
		return nil, nil, errors.Wrap(err, "cipherSuite(cfg.DisableCipherSuites, cfg.EnableInsecureCipherSuites)")
	}

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
		CipherSuites:           cs,
	}

	cert := config.GetActualValue(cfg.CertPath)
	key := config.GetActualValue(cfg.KeyPath)
	ca := config.GetActualValue(cfg.CAPath)

	isEnableCertRefresh, err := isValidDuration(cfg.CertRefreshPeriod)
	if err != nil {
		return nil, nil, errors.Wrap(err, "isValidDuration(cfg.CertRefreshPeriod)")
	}
	if isEnableCertRefresh {
		// GetCertificate can only be used with TLSCertificateCache.
		tcc = &TLSCertificateCache{}
		t.GetCertificate = tcc.getCertificate

		tcc.certRefreshPeriod, err = time.ParseDuration(cfg.CertRefreshPeriod)
		if err != nil {
			return nil, nil, errors.Wrap(err, "ParseDuration(cfg.CertRefreshPeriod)")
		}
		if cert != "" && key != "" {
			crt, err := tls.LoadX509KeyPair(cert, key)
			if err != nil {
				return nil, nil, errors.Wrap(err, "tls.LoadX509KeyPair(cert, key)")
			}

			crtHash, err := hash(cert)
			if err != nil {
				return nil, nil, errors.Wrap(err, "hash(cert)")
			}

			crtKeyHash, err := hash(key)
			if err != nil {
				return nil, nil, errors.Wrap(err, "hash(key)")
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
				return nil, nil, errors.Wrap(err, "tls.LoadX509KeyPair(cert, key)")
			}
			t.Certificates = make([]tls.Certificate, 1)
			t.Certificates[0] = crt
		}
	}

	if ca != "" {
		pool, err := NewX509CertPool(ca)
		if err != nil {
			return nil, nil, errors.Wrap(err, "NewX509CertPool(ca)")
		}
		t.ClientCAs = pool
		t.ClientAuth = tls.RequireAndVerifyClientCert
	}

	return t, tcc, nil
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
			} else {
				glg.Info("Server certificate is same as the file")
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

// cipherSuites returns list of available cipher suites
func cipherSuites(dcs []string, eics []string) ([]uint16, error) {
	ciphers := defaultCipherSuitesMap()
	if len(dcs) != 0 {
		for _, cipher := range dcs {
			if _, ok := ciphers[cipher]; !ok {
				err := errors.WithMessage(errors.New(cipher), "Invalid cipher suite")
				return nil, err
			}
			delete(ciphers, cipher)
		}
	}
	if len(eics) != 0 {
		insecureCiphers := make(map[string]uint16)
		for _, c := range tls.InsecureCipherSuites() {
			insecureCiphers[c.Name] = c.ID
		}
		for _, cipher := range eics {
			if _, ok := insecureCiphers[cipher]; !ok {
				err := errors.WithMessage(errors.New(cipher), "Invalid insecure cipher suite")
				return nil, err
			}
			ciphers[cipher] = insecureCiphers[cipher]
		}
	}

	availableCipherSuites := make([]uint16, 0, len(ciphers))
	availableCipherSuitesName := make([]string, 0, len(ciphers))

	for cipherName, cipherId := range ciphers {
		availableCipherSuites = append(availableCipherSuites, cipherId)
		availableCipherSuitesName = append(availableCipherSuitesName, cipherName)
	}
	glg.Infof("available cipher suites: %v", strings.Join(availableCipherSuitesName, ":"))

	return availableCipherSuites, nil
}

// defaultCipherSuitesMap returns a map of name and id in default cipher suites
func defaultCipherSuitesMap() map[string]uint16 {
	var (
		// allowInsecureCipherSuites is a list of cipher suites supported in tls.InsecureCipherSuites()
		// Default cipher suites is a list of tls.CipherSuites() and allowInsecureCipherSuites
		allowInsecureCipherSuites = map[string]uint16{
			"TLS_RSA_WITH_3DES_EDE_CBC_SHA":       tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
			"TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA": tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
		}
	)

	ciphers := make(map[string]uint16)
	for _, c := range tls.CipherSuites() {
		ciphers[c.Name] = c.ID
	}
	for _, c := range tls.InsecureCipherSuites() {
		if _, ok := allowInsecureCipherSuites[c.Name]; ok {
			ciphers[c.Name] = c.ID
		}
	}
	return ciphers
}
