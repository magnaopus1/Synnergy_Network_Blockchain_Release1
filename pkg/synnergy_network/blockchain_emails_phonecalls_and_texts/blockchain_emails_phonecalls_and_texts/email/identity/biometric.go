package identity

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"os"

	"golang.org/x/crypto/argon2"
)

// GenerateRSAKeys generates a new RSA key pair and saves them to files
func GenerateRSAKeys(privateKeyPath, publicKeyPath string) error {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	privateKeyFile, err := os.Create(privateKeyPath)
	if err != nil {
		return err
	}
	defer privateKeyFile.Close()

	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})

	_, err = privateKeyFile.Write(privateKeyPEM)
	if err != nil {
		return err
	}

	publicKey := &privateKey.PublicKey
	publicKeyPEM, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return err
	}

	publicKeyFile, err := os.Create(publicKeyPath)
	if err != nil {
		return err
	}
	defer publicKeyFile.Close()

	publicKeyPEMBlock := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: publicKeyPEM,
	})

	_, err = publicKeyFile.Write(publicKeyPEMBlock)
	return err
}

// EncryptWithPublicKey encrypts data with the provided public key
func EncryptWithPublicKey(msg string, publicKeyPath string) (string, error) {
	publicKeyFile, err := os.ReadFile(publicKeyPath)
	if err != nil {
		return "", err
	}

	block, _ := pem.Decode(publicKeyFile)
	if block == nil || block.Type != "RSA PUBLIC KEY" {
		return "", errors.New("failed to decode PEM block containing public key")
	}

	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return "", err
	}

	rsaPublicKey, ok := publicKey.(*rsa.PublicKey)
	if !ok {
		return "", errors.New("not RSA public key")
	}

	encryptedBytes, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, rsaPublicKey, []byte(msg), nil)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(encryptedBytes), nil
}

// DecryptWithPrivateKey decrypts data with the provided private key
func DecryptWithPrivateKey(cipherText string, privateKeyPath string) (string, error) {
	privateKeyFile, err := os.ReadFile(privateKeyPath)
	if err != nil {
		return "", err
	}

	block, _ := pem.Decode(privateKeyFile)
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		return "", errors.New("failed to decode PEM block containing private key")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return "", err
	}

	cipherBytes, err := base64.StdEncoding.DecodeString(cipherText)
	if err != nil {
		return "", err
	}

	decryptedBytes, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privateKey, cipherBytes, nil)
	if err != nil {
		return "", err
	}

	return string(decryptedBytes), nil
}

// HashBiometricData hashes the provided biometric data using Argon2
func HashBiometricData(data string, saltSize int) (string, string, error) {
	salt := make([]byte, saltSize)
	_, err := rand.Read(salt)
	if err != nil {
		return "", "", err
	}

	hash := argon2.IDKey([]byte(data), salt, 1, 64*1024, 4, 32)

	return base64.StdEncoding.EncodeToString(salt), base64.StdEncoding.EncodeToString(hash), nil
}

// VerifyBiometricData verifies the provided biometric data against the stored salt and hash
func VerifyBiometricData(data, storedSalt, storedHash string) (bool, error) {
	salt, err := base64.StdEncoding.DecodeString(storedSalt)
	if err != nil {
		return false, err
	}

	hash := argon2.IDKey([]byte(data), salt, 1, 64*1024, 4, 32)

	return base64.StdEncoding.EncodeToString(hash) == storedHash, nil
}
