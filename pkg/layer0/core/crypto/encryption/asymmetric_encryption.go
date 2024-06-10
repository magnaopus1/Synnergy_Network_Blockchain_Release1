package encryption

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"

	"golang.org/x/crypto/scrypt"
)

// AsymmetricEncryptionService handles the encryption and decryption operations using asymmetric key pairs.
type AsymmetricEncryptionService struct {
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
}

// NewAsymmetricEncryptionService initializes a new service with a generated RSA key pair.
func NewAsymmetricEncryptionService() (*AsymmetricEncryptionService, error) {
	// Generate RSA keys with 2048 bits which is considered secure by current standards.
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	return &AsymmetricEncryptionService{
		privateKey: privKey,
		publicKey:  &privKey.PublicKey,
	}, nil
}

// Encrypt encrypts data using the RSA public key.
func (aes *AsymmetricEncryptionService) Encrypt(data []byte) ([]byte, error) {
	encryptedData, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, aes.publicKey, data, nil)
	if err != nil {
		return nil, err
	}
	return encryptedData, nil
}

// Decrypt decrypts data using the RSA private key.
func (aes *AsymmetricEncryptionService) Decrypt(data []byte) ([]byte, error) {
	decryptedData, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, aes.privateKey, data, nil)
	if err != nil {
		return nil, err
	}
	return decryptedData, nil
}

// ExportPublicKey exports the RSA public key to a PEM format.
func (aes *AsymmetricEncryptionService) ExportPublicKey() ([]byte, error) {
	pubASN1, err := x509.MarshalPKIXPublicKey(aes.publicKey)
	if err != nil {
		return nil, err
	}

	pubBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: pubASN1,
	})
	return pubBytes, nil
}

// ImportPublicKey imports a public key from a PEM encoded block.
func (aes *AsymmetricEncryptionService) ImportPublicKey(pemBytes []byte) error {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return errors.New("failed to parse PEM block containing the key")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return err
	}

	var ok bool
	if aes.publicKey, ok = pub.(*rsa.PublicKey); !ok {
		return errors.New("not an RSA public key")
	}
	return nil
}

// UseCaseExample demonstrates how to encrypt and decrypt data.
func UseCaseExample() {
	aesService, err := NewAsymmetricEncryptionService()
	if err != nil {
		panic(err)
	}

	// Simulating the encryption of a message.
	originalText := "Hello, Synthron Blockchain Security!"
	encryptedText, err := aesService.Encrypt([]byte(originalText))
	if err != nil {
		panic(err)
	}

	// Simulating the decryption of the message.
	decryptedText, err := aesService.Decrypt(encryptedText)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Original: %s\nEncrypted: %x\nDecrypted: %s\n", originalText, encryptedText, string(decryptedText))
}

// Additional methods to support homomorphic encryption and post-quantum algorithms would be planned as per future standards.
