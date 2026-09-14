package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type serverIdentity struct {
	ServerPublicKeySHA256 string `json:"server_public_key_sha256"`
}

func loadAgentTLS() (serverIdentity, *tls.Config, string, error) {
	identityPath := filepath.Join("agent", "secret", "server.json")
	certificate, err := loadOrCreateAgentCertificate(filepath.Join("agent", "secret"))
	if err != nil {
		return serverIdentity{}, nil, "", err
	}
	fingerprint, err := agentCertificateFingerprint(certificate.Certificate[0])
	if err != nil {
		return serverIdentity{}, nil, "", err
	}
	data, err := os.ReadFile(identityPath)
	if errors.Is(err, os.ErrNotExist) {
		template, _ := json.MarshalIndent(serverIdentity{}, "", "  ")
		if writeErr := os.WriteFile(identityPath, template, 0600); writeErr != nil {
			return serverIdentity{}, nil, fingerprint, writeErr
		}
		return serverIdentity{}, nil, fingerprint, fmt.Errorf("created %s; set server_public_key_sha256 and restart", identityPath)
	}
	if err != nil {
		return serverIdentity{}, nil, fingerprint, fmt.Errorf("read %s: %w", identityPath, err)
	}
	var identity serverIdentity
	if err := json.Unmarshal(data, &identity); err != nil {
		return serverIdentity{}, nil, fingerprint, err
	}
	if !validFingerprint(identity.ServerPublicKeySHA256) {
		return serverIdentity{}, nil, fingerprint, errors.New("server.json requires server_public_key_sha256")
	}
	identity.ServerPublicKeySHA256 = strings.ToLower(identity.ServerPublicKeySHA256)
	config := &tls.Config{
		Certificates:       []tls.Certificate{certificate},
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS13,
		NextProtos:         []string{"RelayToGo"},
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) != 1 {
				return errors.New("exactly one server certificate is required")
			}
			actual, err := agentCertificateFingerprint(rawCerts[0])
			if err != nil {
				return err
			}
			if actual != identity.ServerPublicKeySHA256 {
				return errors.New("server public key does not match server.json")
			}
			return nil
		},
	}
	return identity, config, fingerprint, nil
}

func loadOrCreateAgentCertificate(dir string) (tls.Certificate, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return tls.Certificate{}, err
	}
	certPath, keyPath := filepath.Join(dir, "agent.crt"), filepath.Join(dir, "agent.key")
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
	template := &x509.Certificate{SerialNumber: serial, NotBefore: now.Add(-time.Minute), NotAfter: now.AddDate(10, 0, 0), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, BasicConstraintsValid: true}
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

func agentCertificateFingerprint(raw []byte) (string, error) {
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

func validFingerprint(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}
