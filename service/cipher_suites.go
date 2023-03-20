package service

import "crypto/tls"

var (
	DenyCipherSuites = map[string]uint16{
		"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256": tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
		"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256":   tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
		"TLS_RSA_WITH_AES_128_CBC_SHA256":         tls.TLS_RSA_WITH_AES_128_CBC_SHA256,
		"TLS_ECDHE_ECDSA_WITH_RC4_128_SHA":        tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
		"TLS_ECDHE_RSA_WITH_RC4_128_SHA":          tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA,
		"TLS_RSA_WITH_RC4_128_SHA":                tls.TLS_RSA_WITH_RC4_128_SHA,
	}
)

// getCipherSuites return a map of CipherSuites and availability
func getCipherSuitesAvailability() map[string]bool {
	ciphers := make(map[string]bool)
	for _, c := range tls.CipherSuites() {
		ciphers[c.Name] = true
	}
	for _, c := range tls.InsecureCipherSuites() {
		if _, ok := DenyCipherSuites[c.Name]; !ok {
			ciphers[c.Name] = true
		}
	}
	return ciphers
}

// getCipherSuites return a map of CipherSuites.Name and CipherSuites.ID
func getCipherSuites() map[string]uint16 {
	ciphers := make(map[string]uint16)
	for _, c := range tls.CipherSuites() {
		ciphers[c.Name] = c.ID
	}
	for _, c := range tls.InsecureCipherSuites() {
		if _, ok := DenyCipherSuites[c.Name]; !ok {
			ciphers[c.Name] = c.ID
		}
	}
	return ciphers
}
