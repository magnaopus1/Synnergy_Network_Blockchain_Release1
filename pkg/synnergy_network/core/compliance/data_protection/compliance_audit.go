package data_protection

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"io"
	"io/ioutil"
	"os"
)

// DataProtectionService provides methods for data protection within the Synnergy Network.
type DataProtectionService struct {
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
}

// NewDataProtectionService initializes a new DataProtectionService with RSA key pair generation.
func NewDataProtectionService() (*DataProtectionService, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	return &DataProtectionService{
		privateKey: privateKey,
		publicKey:  &privateKey.PublicKey,
	}, nil
}

// EncryptDataAtRest encrypts data using AES encryption.
func (dps *DataProtectionService) EncryptDataAtRest(data []byte, key []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// DecryptDataAtRest decrypts data encrypted using AES encryption.
func (dps *DataProtectionService) DecryptDataAtRest(encryptedData string, key []byte) ([]byte, error) {
	data, err := base64.StdEncoding.DecodeString(encryptedData)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

// SecureCommunication establishes a TLS connection between nodes.
func (dps *DataProtectionService) SecureCommunication(certFile, keyFile string) (*tls.Conn, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}

	config := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}

	conn, err := tls.Dial("tcp", "example.com:443", config)
	if err != nil {
		return nil, err
	}

	return conn, nil
}

// GenerateRSAKeyPair generates RSA key pair for encryption and decryption.
func GenerateRSAKeyPair(bits int) (*rsa.PrivateKey, *rsa.PublicKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, nil, err
	}
	return privateKey, &privateKey.PublicKey, nil
}

// EncryptWithPublicKey encrypts data with a public key.
func EncryptWithPublicKey(msg []byte, pub *rsa.PublicKey) ([]byte, error) {
	label := []byte("")
	hash := sha256.New()
	ciphertext, err := rsa.EncryptOAEP(hash, rand.Reader, pub, msg, label)
	if err != nil {
		return nil, err
	}
	return ciphertext, nil
}

// DecryptWithPrivateKey decrypts data with a private key.
func DecryptWithPrivateKey(ciphertext []byte, priv *rsa.PrivateKey) ([]byte, error) {
	label := []byte("")
	hash := sha256.New()
	plaintext, err := rsa.DecryptOAEP(hash, rand.Reader, priv, ciphertext, label)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

// SavePrivateKey saves a private key to a file.
func SavePrivateKey(fileName string, key *rsa.PrivateKey) error {
	outFile, err := os.Create(fileName)
	if err != nil {
		return err
	}
	defer outFile.Close()

	privBytes := x509.MarshalPKCS1PrivateKey(key)
	pem.Encode(outFile, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privBytes,
	})

	return nil
}

// LoadPrivateKey loads a private key from a file.
func LoadPrivateKey(fileName string) (*rsa.PrivateKey, error) {
	privFile, err := os.Open(fileName)
	if err != nil {
		return nil, err
	}
	defer privFile.Close()

	privBytes, err := ioutil.ReadAll(privFile)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(privBytes)
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		return nil, errors.New("failed to decode PEM block containing private key")
	}

	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

// SavePublicKey saves a public key to a file.
func SavePublicKey(fileName string, pub *rsa.PublicKey) error {
	outFile, err := os.Create(fileName)
	if err != nil {
		return err
	}
	defer outFile.Close()

	pubBytes, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return err
	}
	pem.Encode(outFile, &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubBytes,
	})

	return nil
}

// LoadPublicKey loads a public key from a file.
func LoadPublicKey(fileName string) (*rsa.PublicKey, error) {
	pubFile, err := os.Open(fileName)
	if err != nil {
		return nil, err
	}
	defer pubFile.Close()

	pubBytes, err := ioutil.ReadAll(pubFile)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(pubBytes)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, errors.New("failed to decode PEM block containing public key")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	switch pub := pub.(type) {
	case *rsa.PublicKey:
		return pub, nil
	default:
		return nil, errors.New("not an RSA public key")
	}
}
