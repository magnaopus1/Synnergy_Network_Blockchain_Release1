package authentication

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"os"
)

// GenerateRSAKeys generates RSA public and private keys for digital signatures.
func GenerateRSAKeys() (*rsa.PrivateKey, *rsa.PublicKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	return privateKey, &privateKey.PublicKey, nil
}

// SavePrivateKey stores the RSA private key in a PEM format.
func SavePrivateKey(path string, privKey *rsa.PrivateKey) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	privPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(privKey),
		},
	)
	_, err = file.Write(privPEM)
	return err
}

// LoadPublicKey loads an RSA public key from a PEM-encoded file.
func LoadPublicKey(path string) (*rsa.PublicKey, error) {
	pubPEM, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(pubPEM)
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing the key")
	}

	pub, err := x509.ParsePKCS1PublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return pub, nil
}

// SignData signs data using a private key and returns the signature.
func SignData(privKey *rsa.PrivateKey, data []byte) ([]byte, error) {
	hashed := sha256.Sum256(data)
	signature, err := rsa.SignPKCS1v15(rand.Reader, privKey, crypto.SHA256, hashed[:])
	if err != nil {
		return nil, err
	}
	return signature, nil
}

// VerifySignature checks the data signature against a public key.
func VerifySignature(pubKey *rsa.PublicKey, data, signature []byte) error {
	hashed := sha256.Sum256(data)
	return rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, hashed[:], signature)
}

// Example usage
func main() {
	privKey, pubKey, err := GenerateRSAKeys()
	if err != nil {
		panic(err)
	}

	// Assume these functions are used elsewhere to manage keys
	SavePrivateKey("private.pem", privKey)
	pubKey, err = LoadPublicKey("public.pem")
	if err != nil {
		panic(err)
	}

	message := []byte("Secure message")
	signature, err := SignData(privKey, message)
	if err != nil {
		panic(err)
	}

	err = VerifySignature(pubKey, message, signature)
	if err != nil {
		println("Failed to verify signature:", err.Error())
	} else {
		println("Signature verified successfully")
	}
}
