package security

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"golang.org/x/crypto/scrypt"
	"math/big"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/ssh/terminal"
)

// Constants
const (
	KeySize         = 2048
	HashMemory      = 64 * 1024
	HashIterations  = 3
	HashParallelism = 2
	SaltSize        = 16
)

// Authentication represents the authentication mechanism for the node
type Authentication struct {
	privateKey *rsa.PrivateKey
	cert       *x509.Certificate
}

// GenerateKeyPair generates a new RSA key pair
func (a *Authentication) GenerateKeyPair() error {
	var err error
	a.privateKey, err = rsa.GenerateKey(rand.Reader, KeySize)
	if err != nil {
		return fmt.Errorf("failed to generate private key: %v", err)
	}

	return nil
}

// GenerateCertificate generates a self-signed certificate
func (a *Authentication) GenerateCertificate() error {
	if a.privateKey == nil {
		return errors.New("private key not generated")
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return fmt.Errorf("failed to generate serial number: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Synnergy Network"},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().AddDate(1, 0, 0),

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &a.privateKey.PublicKey, a.privateKey)
	if err != nil {
		return fmt.Errorf("failed to create certificate: %v", err)
	}

	a.cert, err = x509.ParseCertificate(certDER)
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %v", err)
	}

	return nil
}

// SaveKeyAndCert saves the private key and certificate to files
func (a *Authentication) SaveKeyAndCert(keyPath, certPath string) error {
	keyFile, err := os.Create(keyPath)
	if err != nil {
		return fmt.Errorf("failed to create key file: %v", err)
	}
	defer keyFile.Close()

	certFile, err := os.Create(certPath)
	if err != nil {
		return fmt.Errorf("failed to create cert file: %v", err)
	}
	defer certFile.Close()

	privateKeyBytes := x509.MarshalPKCS1PrivateKey(a.privateKey)
	if err := pem.Encode(keyFile, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: privateKeyBytes}); err != nil {
		return fmt.Errorf("failed to encode private key: %v", err)
	}

	if err := pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: a.cert.Raw}); err != nil {
		return fmt.Errorf("failed to encode certificate: %v", err)
	}

	return nil
}

// HashPassword hashes a password using scrypt
func HashPassword(password string) (string, error) {
	salt := make([]byte, SaltSize)
	_, err := rand.Read(salt)
	if err != nil {
		return "", fmt.Errorf("failed to generate salt: %v", err)
	}

	hash, err := scrypt.Key([]byte(password), salt, HashMemory, HashIterations, HashParallelism, 32)
	if err != nil {
		return "", fmt.Errorf("failed to hash password: %v", err)
	}

	return fmt.Sprintf("%x$%x", salt, hash), nil
}

// VerifyPassword verifies a password against a hashed password using scrypt
func VerifyPassword(password, hashedPassword string) (bool, error) {
	parts := strings.Split(hashedPassword, "$")
	if len(parts) != 2 {
		return false, errors.New("invalid hashed password format")
	}

	salt, err := hexToBytes(parts[0])
	if err != nil {
		return false, fmt.Errorf("failed to decode salt: %v", err)
	}

	expectedHash, err := hexToBytes(parts[1])
	if err != nil {
		return false, fmt.Errorf("failed to decode expected hash: %v", err)
	}

	hash, err := scrypt.Key([]byte(password), salt, HashMemory, HashIterations, HashParallelism, 32)
	if err != nil {
		return false, fmt.Errorf("failed to hash password: %v", err)
	}

	return string(hash) == string(expectedHash), nil
}

// GenerateArgon2Hash generates a hash using Argon2
func GenerateArgon2Hash(password string) (string, error) {
	salt := make([]byte, SaltSize)
	_, err := rand.Read(salt)
	if err != nil {
		return "", fmt.Errorf("failed to generate salt: %v", err)
	}

	hash := argon2.IDKey([]byte(password), salt, HashIterations, HashMemory, HashParallelism, 32)

	return fmt.Sprintf("%x$%x", salt, hash), nil
}

// VerifyArgon2Hash verifies a password against a hashed password using Argon2
func VerifyArgon2Hash(password, hashedPassword string) (bool, error) {
	parts := strings.Split(hashedPassword, "$")
	if len(parts) != 2 {
		return false, errors.New("invalid hashed password format")
	}

	salt, err := hexToBytes(parts[0])
	if err != nil {
		return false, fmt.Errorf("failed to decode salt: %v", err)
	}

	expectedHash, err := hexToBytes(parts[1])
	if err != nil {
		return false, fmt.Errorf("failed to decode expected hash: %v", err)
	}

	hash := argon2.IDKey([]byte(password), salt, HashIterations, HashMemory, HashParallelism, 32)

	return string(hash) == string(expectedHash), nil
}

// hexToBytes converts a hex string to a byte slice
func hexToBytes(hexStr string) ([]byte, error) {
	bytes := make([]byte, len(hexStr)/2)
	_, err := fmt.Sscanf(hexStr, "%x", &bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to convert hex to bytes: %v", err)
	}

	return bytes, nil
}

// PromptForPassword prompts the user to enter a password
func PromptForPassword(prompt string) (string, error) {
	fmt.Print(prompt)
	password, err := terminal.ReadPassword(0)
	if err != nil {
		return "", fmt.Errorf("failed to read password: %v", err)
	}
	fmt.Println()

	return string(password), nil
}

// ValidatePasswordPolicy checks if a password meets the required policy
func ValidatePasswordPolicy(password string) error {
	if len(password) < 8 {
		return errors.New("password must be at least 8 characters long")
	}
	if !strings.ContainsAny(password, "0123456789") {
		return errors.New("password must contain at least one digit")
	}
	if !strings.ContainsAny(password, "abcdefghijklmnopqrstuvwxyz") {
		return errors.New("password must contain at least one lowercase letter")
	}
	if !strings.ContainsAny(password, "ABCDEFGHIJKLMNOPQRSTUVWXYZ") {
		return errors.New("password must contain at least one uppercase letter")
	}
	if !strings.ContainsAny(password, "!@#$%^&*()-_=+[]{}|;:'\",.<>?/`~") {
		return errors.New("password must contain at least one special character")
	}

	return nil
}
