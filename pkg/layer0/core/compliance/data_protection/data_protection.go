package data_protection

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
)

// DataProtector manages the encryption and decryption processes for data at rest and in transit.
type DataProtector struct {
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
}

// NewDataProtector initializes a new DataProtector with RSA keys.
func NewDataProtector() (*DataProtector, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	return &DataProtector{
		privateKey: privateKey,
		publicKey:  &privateKey.PublicKey,
	}, nil
}

// EncryptDataAES encrypts data using AES-256.
func (dp *DataProtector) EncryptDataAES(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(dp.generateAESKey())
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return ciphertext, nil
}

// DecryptDataAES decrypts data using AES-256.
func (dp *DataProtector) DecryptDataAES(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(dp.generateAESKey())
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce, ciphertext := data[:gcm.NonceSize()], data[gcm.NonceSize():]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

// generateAESKey generates a 32-byte key using SHA-256 from RSA public key.
func (dp *DataProtector) generateAESKey() []byte {
	hash := sha256.New()
	hash.Write(dp.publicKey.N.Bytes()) // Use public key modulus in hash to generate AES key.
	return hash.Sum(nil)[:32]          // Use first 32 bytes of hash as key.
}

// SetupTLSConfig sets up a TLS configuration for secure communication.
func SetupTLSConfig() (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair("server.crt", "server.key")
	if err != nil {
		return nil, err
	}
	config := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}
	return config, nil
}

// GenerateRSAKeys generates and exports RSA public and private keys.
func GenerateRSAKeys() (string, string, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", err
	}
	privBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})
	pubASN1, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return "", "", err
	}
	pubBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: pubASN1,
	})
	return string(privBytes), string(pubBytes), nil
}

