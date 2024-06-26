package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/sha3"
	"math/big"
	"os"
)

// DecentralizedKeyManagement struct to handle decentralized key management operations
type DecentralizedKeyManagement struct {
	privateKeys map[string]interface{}
	publicKeys  map[string]interface{}
}

// NewDKM creates a new DecentralizedKeyManagement instance
func NewDKM() *DecentralizedKeyManagement {
	return &DecentralizedKeyManagement{
		privateKeys: make(map[string]interface{}),
		publicKeys:  make(map[string]interface{}),
	}
}

// GenerateRSAKeyPair generates a new RSA key pair and stores them in DKM
func (dkm *DecentralizedKeyManagement) GenerateRSAKeyPair(alias string, bits int) error {
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return err
	}
	dkm.privateKeys[alias] = privateKey
	dkm.publicKeys[alias] = &privateKey.PublicKey
	return nil
}

// GenerateED25519KeyPair generates a new ED25519 key pair and stores them in DKM
func (dkm *DecentralizedKeyManagement) GenerateED25519KeyPair(alias string) error {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	dkm.privateKeys[alias] = privateKey
	dkm.publicKeys[alias] = publicKey
	return nil
}

// SavePrivateKey saves a private key to a PEM file
func (dkm *DecentralizedKeyManagement) SavePrivateKey(alias, filename string) error {
	privateKey, exists := dkm.privateKeys[alias]
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
func (dkm *DecentralizedKeyManagement) SavePublicKey(alias, filename string) error {
	publicKey, exists := dkm.publicKeys[alias]
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
func (dkm *DecentralizedKeyManagement) LoadPrivateKey(alias, filename string) error {
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
	case "PRIVATE KEY":
		privateKey, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	default:
		return errors.New("unsupported key type")
	}

	if err != nil {
		return err
	}

	dkm.privateKeys[alias] = privateKey
	return nil
}

// LoadPublicKey loads a public key from a PEM file
func (dkm *DecentralizedKeyManagement) LoadPublicKey(alias, filename string) error {
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

	dkm.publicKeys[alias] = publicKey
	return nil
}

// EncryptWithPublicKey encrypts data using a public key
func (dkm *DecentralizedKeyManagement) EncryptWithPublicKey(alias string, data []byte) ([]byte, error) {
	publicKey, exists := dkm.publicKeys[alias]
	if !exists {
		return nil, errors.New("public key not found")
	}

	switch key := publicKey.(type) {
	case *rsa.PublicKey:
		hash := sha256.New()
		return rsa.EncryptOAEP(hash, rand.Reader, key, data, nil)
	case ed25519.PublicKey:
		hash := sha3.New256()
		hash.Write(data)
		encryptedData := hash.Sum(nil)
		return encryptedData, nil
	default:
		return nil, errors.New("unsupported key type")
	}
}

// DecryptWithPrivateKey decrypts data using a private key
func (dkm *DecentralizedKeyManagement) DecryptWithPrivateKey(alias string, ciphertext []byte) ([]byte, error) {
	privateKey, exists := dkm.privateKeys[alias]
	if !exists {
		return nil, errors.New("private key not found")
	}

	switch key := privateKey.(type) {
	case *rsa.PrivateKey:
		hash := sha256.New()
		return rsa.DecryptOAEP(hash, rand.Reader, key, ciphertext, nil)
	case ed25519.PrivateKey:
		hash := sha3.New256()
		hash.Write(ciphertext)
		decryptedData := hash.Sum(nil)
		return decryptedData, nil
	default:
		return nil, errors.New("unsupported key type")
	}
}

// SignData signs data using a private key
func (dkm *DecentralizedKeyManagement) SignData(alias string, data []byte) ([]byte, error) {
	privateKey, exists := dkm.privateKeys[alias]
	if !exists {
		return nil, errors.New("private key not found")
	}

	switch key := privateKey.(type) {
	case *rsa.PrivateKey:
		hash := sha256.New()
		hash.Write(data)
		hashed := hash.Sum(nil)
		return rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, hashed)
	case ed25519.PrivateKey:
		return ed25519.Sign(key, data), nil
	default:
		return nil, errors.New("unsupported key type")
	}
}

// VerifySignature verifies a signature using a public key
func (dkm *DecentralizedKeyManagement) VerifySignature(alias string, data, signature []byte) (bool, error) {
	publicKey, exists := dkm.publicKeys[alias]
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
	case ed25519.PublicKey:
		return ed25519.Verify(key, data, signature), nil
	default:
		return false, errors.New("unsupported key type")
	}
}

// GenerateRandomBigInt generates a random big.Int of the given size in bits
func GenerateRandomBigInt(bits int) (*big.Int, error) {
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), uint(bits)))
	if err != nil {
		return nil, err
	}
	return n, nil
}

// GenerateDeterministicKey generates a deterministic key using SHA3-256
func GenerateDeterministicKey(data []byte) []byte {
	hash := sha3.New256()
	hash.Write(data)
	return hash.Sum(nil)
}

// CreateAndStoreKey creates and stores a new key pair with given alias and type
func (dkm *DecentralizedKeyManagement) CreateAndStoreKey(alias, keyType string) error {
	switch keyType {
	case "rsa":
		return dkm.GenerateRSAKeyPair(alias, 2048)
	case "ed25519":
		return dkm.GenerateED25519KeyPair(alias)
	default:
		return fmt.Errorf("unsupported key type: %s", keyType)
	}
}

// ListKeys lists all stored keys
func (dkm *DecentralizedKeyManagement) ListKeys() {
	fmt.Println("Stored keys:")
	for alias := range dkm.privateKeys {
		fmt.Printf("Alias: %s\n", alias)
	}
}

// ExportKey exports a key to a PEM file
func (dkm *DecentralizedKeyManagement) ExportKey(alias, filename string) error {
	if privateKey, exists := dkm.privateKeys[alias]; exists {
		return dkm.SavePrivateKey(alias, filename)
	} else if publicKey, exists := dkm.publicKeys[alias]; exists {
		return dkm.SavePublicKey(alias, filename)
	} else {
		return fmt.Errorf("key with alias %s not found", alias)
	}
}

// ImportKey imports a key from a PEM file
func (dkm *DecentralizedKeyManagement) ImportKey(alias, filename, keyType string) error {
	if keyType == "private" {
		return dkm.LoadPrivateKey(alias, filename)
	} else if keyType == "public" {
		return dkm.LoadPublicKey(alias, filename)
	} else {
		return fmt.Errorf("unsupported key type: %s", keyType)
	}
}
