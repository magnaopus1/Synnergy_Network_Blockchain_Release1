package authentication

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"os"
)

// CryptoKeys holds the RSA public and private keys.
type CryptoKeys struct {
	PrivateKey *rsa.PrivateKey
	PublicKey  *rsa.PublicKey
}

// GenerateKeys generates a new pair of RSA keys.
func GenerateKeys() (*CryptoKeys, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	return &CryptoKeys{
		PrivateKey: privateKey,
		PublicKey:  &privateKey.PublicKey,
	}, nil
}

// SignData signs data with the RSA private key.
func (ck *CryptoKeys) SignData(data []byte) ([]byte, error) {
	hashed := sha256.Sum256(data)
	signature, err := rsa.SignPKCS1v15(rand.Reader, ck.PrivateKey, crypto.SHA256, hashed[:])
	if err != nil {
		return nil, err
	}
	return signature, nil
}

// VerifySignature verifies the signature with the RSA public key.
func (ck *CryptoKeys) VerifySignature(data, signature []byte) error {
	hashed := sha256.Sum256(data)
	return rsa.VerifyPKCS1v15(ck.PublicKey, crypto.SHA256, hashed[:], signature)
}

// SavePrivateKeyToFile saves the private key to a file.
func (ck *CryptoKeys) SavePrivateKeyToFile(filename string) error {
	privASN1 := x509.MarshalPKCS1PrivateKey(ck.PrivateKey)
	privBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY", Bytes: privASN1,
	})
	return ioutil.WriteFile(filename, privBytes, 0600)
}

// LoadPrivateKeyFromFile loads the private key from a file.
func LoadPrivateKeyFromFile(filename string) (*rsa.PrivateKey, error) {
	privBytes, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	privPem, _ := pem.Decode(privBytes)
	if privPem == nil {
		return nil, errors.New("error decoding private key")
	}
	return x509.ParsePKCS1PrivateKey(privPem.Bytes)
}

// Example usage
func main() {
	keys, err := GenerateKeys()
	if err != nil {
		panic(err)
	}

	// Simulate signing and verifying a message
	message := []byte("authenticate this message")
	signature, err := keys.SignData(message)
	if err != nil {
		panic(err)
	}

	err = keys.VerifySignature(message, signature)
	if err != nil {
		fmt.Println("Failed to verify signature:", err)
	} else {
		fmt.Println("Signature verified.")
	}
}
