package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"golang.org/x/crypto/ed25519"
	"math/big"
	"os"
)

// DigitalSignatures handles all digital signature operations
type DigitalSignatures struct {
	privateKeys map[string]interface{}
	publicKeys  map[string]interface{}
}

// NewDigitalSignatures creates a new DigitalSignatures instance
func NewDigitalSignatures() *DigitalSignatures {
	return &DigitalSignatures{
		privateKeys: make(map[string]interface{}),
		publicKeys:  make(map[string]interface{}),
	}
}

// GenerateRSAKeyPair generates a new RSA key pair and stores them
func (ds *DigitalSignatures) GenerateRSAKeyPair(alias string, bits int) error {
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return err
	}
	ds.privateKeys[alias] = privateKey
	ds.publicKeys[alias] = &privateKey.PublicKey
	return nil
}

// GenerateECDSAKeyPair generates a new ECDSA key pair and stores them
func (ds *DigitalSignatures) GenerateECDSAKeyPair(alias string) error {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	ds.privateKeys[alias] = privateKey
	ds.publicKeys[alias] = &privateKey.PublicKey
	return nil
}

// GenerateED25519KeyPair generates a new ED25519 key pair and stores them
func (ds *DigitalSignatures) GenerateED25519KeyPair(alias string) error {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	ds.privateKeys[alias] = privateKey
	ds.publicKeys[alias] = publicKey
	return nil
}

// SavePrivateKey saves a private key to a PEM file
func (ds *DigitalSignatures) SavePrivateKey(alias, filename string) error {
	privateKey, exists := ds.privateKeys[alias]
	if !exists {
		return errors.New("private key not found")
	}

	var keyBytes []byte
	var err error
	var keyType string

	switch key := privateKey.(type) {
	case *rsa.PrivateKey:
		keyBytes = x509.MarshalPKCS1PrivateKey(key)
		keyType = "RSA PRIVATE KEY"
	case *ecdsa.PrivateKey:
		keyBytes, err = x509.MarshalECPrivateKey(key)
		keyType = "EC PRIVATE KEY"
	case ed25519.PrivateKey:
		keyBytes, err = x509.MarshalPKCS8PrivateKey(key)
		keyType = "PRIVATE KEY"
	default:
		return errors.New("unsupported key type")
	}

	if err != nil {
		return err
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  keyType,
		Bytes: keyBytes,
	})

	return os.WriteFile(filename, keyPEM, 0600)
}

// SavePublicKey saves a public key to a PEM file
func (ds *DigitalSignatures) SavePublicKey(alias, filename string) error {
	publicKey, exists := ds.publicKeys[alias]
	if !exists {
		return errors.New("public key not found")
	}

	var keyBytes []byte
	var err error
	var keyType string

	switch key := publicKey.(type) {
	case *rsa.PublicKey:
		keyBytes, err = x509.MarshalPKIXPublicKey(key)
		keyType = "RSA PUBLIC KEY"
	case *ecdsa.PublicKey:
		keyBytes, err = x509.MarshalPKIXPublicKey(key)
		keyType = "EC PUBLIC KEY"
	case ed25519.PublicKey:
		keyBytes, err = x509.MarshalPKIXPublicKey(key)
		keyType = "PUBLIC KEY"
	default:
		return errors.New("unsupported key type")
	}

	if err != nil {
		return err
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  keyType,
		Bytes: keyBytes,
	})

	return os.WriteFile(filename, keyPEM, 0600)
}

// LoadPrivateKey loads a private key from a PEM file
func (ds *DigitalSignatures) LoadPrivateKey(alias, filename string) error {
	keyPEM, err := os.ReadFile(filename)
	if err != nil {
		return err
	}

	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return errors.New("failed to decode PEM block")
	}

	var privateKey interface{}
	switch block.Type {
	case "RSA PRIVATE KEY":
		privateKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		privateKey, err = x509.ParseECPrivateKey(block.Bytes)
	case "PRIVATE KEY":
		privateKey, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	default:
		return errors.New("unsupported key type")
	}

	if err != nil {
		return err
	}

	ds.privateKeys[alias] = privateKey
	return nil
}

// LoadPublicKey loads a public key from a PEM file
func (ds *DigitalSignatures) LoadPublicKey(alias, filename string) error {
	keyPEM, err := os.ReadFile(filename)
	if err != nil {
		return err
	}

	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return errors.New("failed to decode PEM block")
	}

	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return err
	}

	ds.publicKeys[alias] = publicKey
	return nil
}

// SignData signs data using a private key
func (ds *DigitalSignatures) SignData(alias string, data []byte) ([]byte, error) {
	privateKey, exists := ds.privateKeys[alias]
	if !exists {
		return nil, errors.New("private key not found")
	}

	switch key := privateKey.(type) {
	case *rsa.PrivateKey:
		hash := sha256.New()
		hash.Write(data)
		hashed := hash.Sum(nil)
		return rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, hashed)
	case *ecdsa.PrivateKey:
		hash := sha256.New()
		hash.Write(data)
		hashed := hash.Sum(nil)
		r, s, err := ecdsa.Sign(rand.Reader, key, hashed)
		if err != nil {
			return nil, err
		}
		signature := append(r.Bytes(), s.Bytes()...)
		return signature, nil
	case ed25519.PrivateKey:
		return ed25519.Sign(key, data), nil
	default:
		return nil, errors.New("unsupported key type")
	}
}

// VerifySignature verifies a signature using a public key
func (ds *DigitalSignatures) VerifySignature(alias string, data, signature []byte) (bool, error) {
	publicKey, exists := ds.publicKeys[alias]
	if !exists {
		return false, errors.New("public key not found")
	}

	switch key := publicKey.(type) {
	case *rsa.PublicKey:
		hash := sha256.New()
		hash.Write(data)
		hashed := hash.Sum(nil)
		err := rsa.VerifyPKCS1v15(key, crypto.SHA256, hashed, signature)
		return err == nil, err
	case *ecdsa.PublicKey:
		hash := sha256.New()
		hash.Write(data)
		hashed := hash.Sum(nil)
		r := new(big.Int).SetBytes(signature[:len(signature)/2])
		s := new(big.Int).SetBytes(signature[len(signature)/2:])
		return ecdsa.Verify(key, hashed, r, s), nil
	case ed25519.PublicKey:
		return ed25519.Verify(key, data, signature), nil
	default:
		return false, errors.New("unsupported key type")
	}
}

// ExportKey exports a key to a PEM file
func (ds *DigitalSignatures) ExportKey(alias, filename string) error {
	if privateKey, exists := ds.privateKeys[alias]; exists {
		return ds.SavePrivateKey(alias, filename)
	} else if publicKey, exists := ds.publicKeys[alias]; exists {
		return ds.SavePublicKey(alias, filename)
	} else {
		return fmt.Errorf("key with alias %s not found", alias)
	}
}

// ImportKey imports a key from a PEM file
func (ds *DigitalSignatures) ImportKey(alias, filename, keyType string) error {
	if keyType == "private" {
		return ds.LoadPrivateKey(alias, filename)
	} else if keyType == "public" {
		return ds.LoadPublicKey(alias, filename)
	} else {
		return fmt.Errorf("unsupported key type: %s", keyType)
	}
}

// ListKeys lists all stored keys
func (ds *DigitalSignatures) ListKeys() {
	fmt.Println("Stored keys:")
	for alias := range ds.privateKeys {
		fmt.Printf("Alias: %s\n", alias)
	}
	for alias := range ds.publicKeys {
		fmt.Printf("Alias: %s\n", alias)
	}
}


