package lattice_based

import (
	"crypto/rand"
	"errors"
	"math/big"

	"golang.org/x/crypto/sha3"
)

// Constants for Ring-LWE parameters
const (
	n = 1024          // Degree of the polynomial ring
	q = 1 << 14       // Modulus
	sigma = 3.2       // Standard deviation for error distribution
)

// Polynomial structure
type Polynomial struct {
	coeffs [n]*big.Int
}

// KeyPair structure
type KeyPair struct {
	PublicKey  *Polynomial
	PrivateKey *Polynomial
}

// generateRandomPolynomial generates a random polynomial with coefficients in [0, q-1]
func generateRandomPolynomial() (*Polynomial, error) {
	p := &Polynomial{}
	for i := 0; i < n; i++ {
		coeff, err := rand.Int(rand.Reader, big.NewInt(q))
		if err != nil {
			return nil, err
		}
		p.coeffs[i] = coeff
	}
	return p, nil
}

// generateErrorPolynomial generates a polynomial with Gaussian distributed coefficients
func generateErrorPolynomial() (*Polynomial, error) {
	p := &Polynomial{}
	for i := 0; i < n; i++ {
		// Using a simple uniform distribution as a placeholder for Gaussian distribution
		coeff, err := rand.Int(rand.Reader, big.NewInt(int64(sigma)))
		if err != nil {
			return nil, err
		}
		p.coeffs[i] = coeff
	}
	return p, nil
}

// Polynomial addition
func (p *Polynomial) add(q *Polynomial) *Polynomial {
	result := &Polynomial{}
	for i := 0; i < n; i++ {
		result.coeffs[i] = new(big.Int).Add(p.coeffs[i], q.coeffs[i])
		result.coeffs[i].Mod(result.coeffs[i], big.NewInt(q))
	}
	return result
}

// Polynomial subtraction
func (p *Polynomial) sub(q *Polynomial) *Polynomial {
	result := &Polynomial{}
	for i := 0; i < n; i++ {
		result.coeffs[i] = new(big.Int).Sub(p.coeffs[i], q.coeffs[i])
		result.coeffs[i].Mod(result.coeffs[i], big.NewInt(q))
	}
	return result
}

// Polynomial multiplication
func (p *Polynomial) mul(q *Polynomial) *Polynomial {
	result := &Polynomial{}
	for i := 0; i < n; i++ {
		result.coeffs[i] = new(big.Int)
		for j := 0; j < n; j++ {
			term := new(big.Int).Mul(p.coeffs[j], q.coeffs[(i+j)%n])
			result.coeffs[i].Add(result.coeffs[i], term)
		}
		result.coeffs[i].Mod(result.coeffs[i], big.NewInt(q))
	}
	return result
}

// KeyGen generates a Ring-LWE key pair
func KeyGen() (*KeyPair, error) {
	a, err := generateRandomPolynomial()
	if err != nil {
		return nil, err
	}

	s, err := generateErrorPolynomial()
	if err != nil {
		return nil, err
	}

	e, err := generateErrorPolynomial()
	if err != nil {
		return nil, err
	}

	// Public key: a*s + e
	pubKey := a.mul(s).add(e)

	return &KeyPair{
		PublicKey:  pubKey,
		PrivateKey: s,
	}, nil
}

// Encrypt encrypts a message using the Ring-LWE public key
func Encrypt(pubKey *Polynomial, message []byte) (*Polynomial, error) {
	m := new(big.Int).SetBytes(message)
	u, err := generateRandomPolynomial()
	if err != nil {
		return nil, err
	}

	e1, err := generateErrorPolynomial()
	if err != nil {
		return nil, err
	}

	e2, err := generateErrorPolynomial()
	if err != nil {
		return nil, err
	}

	// v = a*u + e1
	v := generateRandomPolynomial().mul(u).add(e1)

	// c = pubKey*u + e2 + m*floor(q/2)
	mPoly := &Polynomial{}
	mPoly.coeffs[0] = new(big.Int).Mul(m, big.NewInt(q/2))
	c := pubKey.mul(u).add(e2).add(mPoly)

	return c, nil
}

// Decrypt decrypts a ciphertext using the Ring-LWE private key
func Decrypt(privKey *Polynomial, ciphertext *Polynomial) ([]byte, error) {
	// Compute v*s
	vs := ciphertext.mul(privKey)

	// Recover the message
	m := vs.coeffs[0].Div(vs.coeffs[0], big.NewInt(q/2))
	return m.Bytes(), nil
}

// Hash function using SHA3-256
func Hash(data []byte) []byte {
	hash := sha3.New256()
	hash.Write(data)
	return hash.Sum(nil)
}
