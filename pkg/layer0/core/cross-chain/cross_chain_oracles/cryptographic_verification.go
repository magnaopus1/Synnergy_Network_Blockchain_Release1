package crosschainoracles

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io/ioutil"
)

// CryptographicVerifier encapsulates functionality for verifying data integrity and authenticity.
type CryptographicVerifier struct {
	publicKey *rsa.PublicKey
}

// NewCryptographicVerifier initializes a verifier with a public key.
func NewCryptographicVerifier(publicKeyPath string) (*CryptographicVerifier, error) {
	keyData, err := ioutil.ReadFile(publicKeyPath)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(keyData)
	if block == nil {
		return nil, errors.New("failed to decode PEM block containing public key")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	var ok bool
	if publicKey, ok = pub.(*rsa.PublicKey); !ok {
		return nil, errors.New("not RSA public key")
	}

	return &CryptographicVerifier{
		publicKey: publicKey,
	}, nil
}

// VerifyData verifies the digital signature of the data using SHA256 with RSA.
func (v *CryptographicVerifier) VerifyData(data []byte, signature []byte) error {
	hashed := sha256.Sum256(data)
	return rsa.VerifyPKCS1v15(v.publicKey, crypto.SHA256, hashed[:], signature)
}

// Example usage
func main() {
	verifier, err := NewCryptographicVerifier("path/to/public_key.pem")
	if err != nil {
		panic(err)
	}

	// Example data and signature
	data := []byte("data to verify")
	signature := []byte{} // Signature should be the actual byte slice from signing

	if err := verifier.VerifyData(data, signature); err != nil {
		println("Verification failed:", err.Error())
	} else {
		println("Verification successful")
	}
}
