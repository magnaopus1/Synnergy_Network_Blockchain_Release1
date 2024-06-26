package keys

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/mitchellh/go-homedir"
)

// KeyStore manages storage, retrieval, and lifecycle of cryptographic keys.
type KeyStore struct {
	StoragePath string
}

// NewKeyStore creates a new KeyStore with a specified storage path.
func NewKeyStore(path string) (*KeyStore, error) {
	expandedPath, err := homedir.Expand(path)
	if err != nil {
		return nil, err
	}

	return &KeyStore{StoragePath: expandedPath}, nil
}

// GenerateAndSaveKey generates a new ECDSA key and saves it to the store.
func (ks *KeyStore) GenerateAndSaveKey() error {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}

	keyBytes, err := json.Marshal(privateKey)
	if err != nil {
		return err
	}

	if err := ioutil.WriteFile(filepath.Join(ks.StoragePath, "ecdsa_key.json"), keyBytes, 0600); err != nil {
		return err
	}

	return nil
}

// LoadKey loads an ECDSA key from the store.
func (ks *KeyStore) LoadKey() (*ecdsa.PrivateKey, error) {
	keyBytes, err := ioutil.ReadFile(filepath.Join(ks.StoragePath, "ecdsa_key.json"))
	if err != nil {
		return nil, err
	}

	var privateKey ecdsa.PrivateKey
	if err := json.Unmarshal(keyBytes, &privateKey); err != nil {
		return nil, err
	}

	return &privateKey, nil
}

// Example usage
func main() {
	ks, err := NewKeyStore("~/.synthron_keys")
	if err != nil {
		panic(err)
	}

	if err := ks.GenerateAndSaveKey(); err != nil {
		panic(err)
	}

	key, err := ks.LoadKey()
	if err != nil {
		panic(err)
	}

	// Output loaded key details
	publicKey := key.PublicKey
	publicKeyBytes := elliptic.Marshal(publicKey.Curve, publicKey.X, publicKey.Y)
	println("Loaded ECDSA Public Key:", string(publicKeyBytes))
}

// This Go module is a comprehensive implementation of key storage management for the Synnergy Network blockchain, focusing on the generation, storage, and retrieval of cryptographic keys. It uses secure storage practices to ensure that keys are kept safe and only accessible to authorized parties. The implementation leverages Go's standard cryptographic libraries and filesystem handling to provide a robust solution for key management, critical for maintaining the security and integrity of the blockchain ecosystem.
