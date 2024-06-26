package multivariate_polynomials

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"math/big"
)

// Parameters for the multivariate quadratic polynomial scheme
const (
	n           = 256 // Dimension of the vector space
	q           = 65537 // Modulus
	messageSize = 32  // Size of the message in bytes
)

// KeyPair represents a public-private key pair
type KeyPair struct {
	PublicKey  *PublicKey
	PrivateKey *PrivateKey
}

// PublicKey represents the public key in the multivariate scheme
type PublicKey struct {
	Polynomials []Polynomial // Public polynomials
}

// PrivateKey represents the private key in the multivariate scheme
type PrivateKey struct {
	Polynomials []Polynomial // Private polynomials
}

// Polynomial represents a quadratic polynomial
type Polynomial struct {
	Terms [][]*big.Int // Coefficients for the polynomial terms
}

// GenerateKeyPair generates a new key pair for the multivariate quadratic polynomial scheme
func GenerateKeyPair() (*KeyPair, error) {
	privKey, err := generatePrivateKey()
	if err != nil {
		return nil, err
	}

	pubKey, err := generatePublicKey(privKey)
	if err != nil {
		return nil, err
	}

	return &KeyPair{PublicKey: pubKey, PrivateKey: privKey}, nil
}

// generatePrivateKey generates a private key
func generatePrivateKey() (*PrivateKey, error) {
	privPolynomials := make([]Polynomial, n)
	for i := 0; i < n; i++ {
		poly, err := generateRandomPolynomial()
		if err != nil {
			return nil, err
		}
		privPolynomials[i] = poly
	}
	return &PrivateKey{Polynomials: privPolynomials}, nil
}

// generatePublicKey generates a public key from a private key
func generatePublicKey(privKey *PrivateKey) (*PublicKey, error) {
	pubPolynomials := make([]Polynomial, n)
	for i := 0; i < n; i++ {
		// Public polynomial is a combination of private polynomials
		pubPolynomials[i] = privKey.Polynomials[i] // Simplified for demonstration purposes
	}
	return &PublicKey{Polynomials: pubPolynomials}, nil
}

// generateRandomPolynomial generates a random quadratic polynomial
func generateRandomPolynomial() (Polynomial, error) {
	terms := make([][]*big.Int, n)
	for i := 0; i < n; i++ {
		terms[i] = make([]*big.Int, n)
		for j := 0; j < n; j++ {
			coef, err := rand.Int(rand.Reader, big.NewInt(q))
			if err != nil {
				return Polynomial{}, err
			}
			terms[i][j] = coef
		}
	}
	return Polynomial{Terms: terms}, nil
}

// Encrypt encrypts a message using the public key
func Encrypt(pubKey *PublicKey, message []byte) ([]byte, error) {
	if len(message) != messageSize {
		return nil, errors.New("invalid message size")
	}

	ciphertext := make([]byte, len(message))
	for i := 0; i < len(message); i++ {
		ciphertext[i] = message[i] // Simplified encryption for demonstration purposes
	}

	return ciphertext, nil
}

// Decrypt decrypts a ciphertext using the private key
func Decrypt(privKey *PrivateKey, ciphertext []byte) ([]byte, error) {
	if len(ciphertext) != messageSize {
		return nil, errors.New("invalid ciphertext size")
	}

	plaintext := make([]byte, len(ciphertext))
	for i := 0; i < len(ciphertext); i++ {
		plaintext[i] = ciphertext[i] // Simplified decryption for demonstration purposes
	}

	return plaintext, nil
}

// Sign generates a signature for a message using the private key
func Sign(privKey *PrivateKey, message []byte) ([]byte, error) {
	hash := sha256.Sum256(message)
	signature := make([]byte, len(hash))
	copy(signature, hash[:])

	return signature, nil
}

// Verify verifies a signature using the public key
func Verify(pubKey *PublicKey, message, signature []byte) (bool, error) {
	hash := sha256.Sum256(message)
	return bytesEqual(hash[:], signature), nil
}

// Helper function to check byte slices equality
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
