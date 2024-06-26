package data_protection

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"io"
	"io/ioutil"
	"os"
)

// KeyManagementService provides methods for key management within the Synnergy Network.
type KeyManagementService struct {
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
}

// NewKeyManagementService initializes a new KeyManagementService with RSA key pair generation.
func NewKeyManagementService() (*KeyManagementService, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	return &KeyManagementService{
		privateKey: privateKey,
		publicKey:  &privateKey.PublicKey,
	}, nil
}

// EncryptWithPublicKey encrypts data with the public key.
func (kms *KeyManagementService) EncryptWithPublicKey(data []byte) ([]byte, error) {
	label := []byte("")
	hash := sha256.New()
	ciphertext, err := rsa.EncryptOAEP(hash, rand.Reader, kms.publicKey, data, label)
	if err != nil {
		return nil, err
	}
	return ciphertext, nil
}

// DecryptWithPrivateKey decrypts data with the private key.
func (kms *KeyManagementService) DecryptWithPrivateKey(ciphertext []byte) ([]byte, error) {
	label := []byte("")
	hash := sha256.New()
	plaintext, err := rsa.DecryptOAEP(hash, rand.Reader, kms.privateKey, ciphertext, label)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

// SavePrivateKey saves the private key to a file.
func (kms *KeyManagementService) SavePrivateKey(fileName string) error {
	outFile, err := os.Create(fileName)
	if err != nil {
		return err
	}
	defer outFile.Close()

	privBytes := x509.MarshalPKCS1PrivateKey(kms.privateKey)
	pem.Encode(outFile, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privBytes,
	})

	return nil
}

// LoadPrivateKey loads the private key from a file.
func (kms *KeyManagementService) LoadPrivateKey(fileName string) error {
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

	kms.privateKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return err
	}

	kms.publicKey = &kms.privateKey.PublicKey
	return nil
}

// SavePublicKey saves the public key to a file.
func (kms *KeyManagementService) SavePublicKey(fileName string) error {
	outFile, err := os.Create(fileName)
	if err != nil {
		return err
	}
	defer outFile.Close()

	pubBytes, err := x509.MarshalPKIXPublicKey(kms.publicKey)
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
func (kms *KeyManagementService) LoadPublicKey(fileName string) error {
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
		kms.publicKey = pub
		return nil
	default:
		return errors.New("not an RSA public key")
	}
}

// EncryptDataAtRest encrypts data using AES encryption.
func (kms *KeyManagementService) EncryptDataAtRest(data []byte, key []byte) (string, error) {
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
func (kms *KeyManagementService) DecryptDataAtRest(encryptedData string, key []byte) ([]byte, error) {
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
