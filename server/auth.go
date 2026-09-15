package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func agentKeyIndex(agents []agentConfig) (map[string]string, error) {
	keys := make(map[string]string, len(agents))
	for _, agent := range agents {
		if agent.PublicKeySHA256 == "" {
			return nil, fmt.Errorf("agent %s has a missing public_key_sha256", agent.ID)
		}
		if len(agent.PublicKeySHA256) != sha256.Size*2 {
			return nil, fmt.Errorf("agent %s has an invalid public_key_sha256", agent.ID)
		}
		if _, err := hex.DecodeString(agent.PublicKeySHA256); err != nil {
			return nil, fmt.Errorf("agent %s has an invalid public_key_sha256", agent.ID)
		}
		key := normalizeFingerprint(agent.PublicKeySHA256)
		if keys[key] != "" {
			return nil, errors.New("agent public keys must be unique")
		}
		keys[key] = agent.ID
	}
	return keys, nil
}

func loadOrCreateServerTLS(dir string, acceptsAgentKey func(string) bool) (*tls.Config, string, error) {
	certificate, err := loadOrCreateCertificate(dir, "server", x509.ExtKeyUsageServerAuth)
	if err != nil {
		return nil, "", err
	}
	fingerprint, err := certificateFingerprint(certificate.Certificate[0])
	if err != nil {
		return nil, "", err
	}
	config := &tls.Config{
		Certificates: []tls.Certificate{certificate},
		ClientAuth:   tls.RequireAnyClientCert,
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{"RelayToGo"},
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) != 1 {
				return errors.New("exactly one client certificate is required")
			}
			fingerprint, err := certificateFingerprint(rawCerts[0])
			if err != nil {
				return err
			}
			if !acceptsAgentKey(fingerprint) {
				return errors.New("client public key is not registered")
			}
			return nil
		},
	}
	return config, fingerprint, nil
}

func loadOrCreateCertificate(dir, name string, usage x509.ExtKeyUsage) (tls.Certificate, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return tls.Certificate{}, err
	}
	certPath, keyPath := filepath.Join(dir, name+".crt"), filepath.Join(dir, name+".key")
	if certPEM, err := os.ReadFile(certPath); err == nil {
		keyPEM, keyErr := os.ReadFile(keyPath)
		if keyErr != nil {
			return tls.Certificate{}, keyErr
		}
		return tls.X509KeyPair(certPEM, keyPEM)
	} else if !errors.Is(err, os.ErrNotExist) {
		return tls.Certificate{}, err
	}

	key, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}
	now := time.Now()
	template := &x509.Certificate{SerialNumber: serial, NotBefore: now.Add(-time.Minute), NotAfter: now.AddDate(10, 0, 0), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, ExtKeyUsage: []x509.ExtKeyUsage{usage}, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return tls.Certificate{}, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(certPath, certPEM, 0600); err != nil {
		return tls.Certificate{}, err
	}
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		return tls.Certificate{}, err
	}
	return tls.X509KeyPair(certPEM, keyPEM)
}

func certificateFingerprint(raw []byte) (string, error) {
	certificate, err := x509.ParseCertificate(raw)
	if err != nil {
		return "", err
	}
	if _, ok := certificate.PublicKey.(*rsa.PublicKey); !ok {
		return "", errors.New("RSA public key is required")
	}
	sum := sha256.Sum256(certificate.RawSubjectPublicKeyInfo)
	return hex.EncodeToString(sum[:]), nil
}

func normalizeFingerprint(value string) string { return strings.ToLower(value) }
