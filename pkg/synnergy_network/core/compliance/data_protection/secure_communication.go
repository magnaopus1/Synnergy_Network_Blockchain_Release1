package data_protection

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
	"time"
)

// SecureCommunication handles the setup and management of secure communication channels.
type SecureCommunication struct {
	privateKey  *rsa.PrivateKey
	publicKey   *rsa.PublicKey
	certificate *x509.Certificate
	tlsConfig   *tls.Config
}

// NewSecureCommunication initializes a new SecureCommunication with TLS configuration.
func NewSecureCommunication() (*SecureCommunication, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Synnergy Network"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, err
	}

	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, err
	}

	tlsCert := tls.Certificate{
		Certificate: [][]byte{certBytes},
		PrivateKey:  privateKey,
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
	}

	return &SecureCommunication{
		privateKey:  privateKey,
		publicKey:   &privateKey.PublicKey,
		certificate: cert,
		tlsConfig:   tlsConfig,
	}, nil
}

// SaveCertificate saves the certificate to a file.
func (sc *SecureCommunication) SaveCertificate(fileName string) error {
	certOut, err := os.Create(fileName)
	if err != nil {
		return err
	}
	defer certOut.Close()

	err = pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: sc.certificate.Raw})
	if err != nil {
		return err
	}

	return nil
}

// LoadCertificate loads the certificate from a file.
func (sc *SecureCommunication) LoadCertificate(fileName string) error {
	certPEM, err := ioutil.ReadFile(fileName)
	if err != nil {
		return err
	}

	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return errors.New("failed to decode PEM block containing certificate")
	}

	sc.certificate, err = x509.ParseCertificate(block.Bytes)
	if err != nil {
		return err
	}

	return nil
}

// SavePrivateKey saves the private key to a file.
func (sc *SecureCommunication) SavePrivateKey(fileName string) error {
	outFile, err := os.Create(fileName)
	if err != nil {
		return err
	}
	defer outFile.Close()

	privBytes := x509.MarshalPKCS1PrivateKey(sc.privateKey)
	pem.Encode(outFile, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privBytes,
	})

	return nil
}

// LoadPrivateKey loads the private key from a file.
func (sc *SecureCommunication) LoadPrivateKey(fileName string) error {
	privFile, err := os.Open(fileName)
	if err != nil {
		return err
	}
	defer privFile.Close()

	privBytes, err := ioutil.ReadAll(privFile)
	if err != nil {
		return err
	}

	block, _ := pem.Decode(privBytes)
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		return errors.New("failed to decode PEM block containing private key")
	}

	sc.privateKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return err
	}

	sc.publicKey = &sc.privateKey.PublicKey
	return nil
}

// SavePublicKey saves the public key to a file.
func (sc *SecureCommunication) SavePublicKey(fileName string) error {
	outFile, err := os.Create(fileName)
	if err != nil {
		return err
	}
	defer outFile.Close()

	pubBytes, err := x509.MarshalPKIXPublicKey(sc.publicKey)
	if err != nil {
		return err
	}
	pem.Encode(outFile, &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubBytes,
	})

	return nil
}

// LoadPublicKey loads the public key from a file.
func (sc *SecureCommunication) LoadPublicKey(fileName string) error {
	pubFile, err := os.Open(fileName)
	if err != nil {
		return err
	}
	defer pubFile.Close()

	pubBytes, err := ioutil.ReadAll(pubFile)
	if err != nil {
		return err
	}

	block, _ := pem.Decode(pubBytes)
	if block == nil || block.Type != "PUBLIC KEY" {
		return errors.New("failed to decode PEM block containing public key")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return err
	}

	switch pub := pub.(type) {
	case *rsa.PublicKey:
		sc.publicKey = pub
		return nil
	default:
		return errors.New("not an RSA public key")
	}
}

// EncryptWithPublicKey encrypts data with the public key.
func (sc *SecureCommunication) EncryptWithPublicKey(data []byte) ([]byte, error) {
	label := []byte("")
	hash := sha256.New()
	ciphertext, err := rsa.EncryptOAEP(hash, rand.Reader, sc.publicKey, data, label)
	if err != nil {
		return nil, err
	}
	return ciphertext, nil
}

// DecryptWithPrivateKey decrypts data with the private key.
func (sc *SecureCommunication) DecryptWithPrivateKey(ciphertext []byte) ([]byte, error) {
	label := []byte("")
	hash := sha256.New()
	plaintext, err := rsa.DecryptOAEP(hash, rand.Reader, sc.privateKey, ciphertext, label)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

// GetTLSConfig returns the TLS configuration for secure communication.
func (sc *SecureCommunication) GetTLSConfig() *tls.Config {
	return sc.tlsConfig
}
