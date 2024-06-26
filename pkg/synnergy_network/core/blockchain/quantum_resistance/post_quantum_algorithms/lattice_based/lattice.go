package lattice_based

import (
	"crypto/rand"
	"errors"
	"math/big"

	"golang.org/x/crypto/sha3"
)

// Constants for LWE parameters
const (
	nLWE     = 1024   // Dimension of the LWE instance
	qLWE     = 1 << 14 // Modulus for coefficients
	sigmaLWE = 3.2     // Standard deviation for error distribution
)

// Vector structure representing LWE polynomials
type Vector struct {
	coeffs []*big.Int
}

// KeyPairLWE structure for LWE
type KeyPairLWE struct {
	PublicKey  *Vector
	PrivateKey *Vector
}

// generateRandomVector generates a random vector with coefficients in [0, q-1]
func generateRandomVector(length int, modulus *big.Int) (*Vector, error) {
	v := &Vector{coeffs: make([]*big.Int, length)}
	for i := 0; i < length; i++ {
		coeff, err := rand.Int(rand.Reader, modulus)
		if err != nil {
			return nil, err
		}
		v.coeffs[i] = coeff
	}
	return v, nil
}

// generateErrorVector generates a vector with Gaussian distributed coefficients
func generateErrorVector(length int, stddev float64) (*Vector, error) {
	v := &Vector{coeffs: make([]*big.Int, length)}
	for i := 0; i < length; i++ {
		// Using a simple uniform distribution as a placeholder for Gaussian distribution
		coeff, err := rand.Int(rand.Reader, big.NewInt(int64(stddev)))
		if err != nil {
			return nil, err
		}
		v.coeffs[i] = coeff
	}
	return v, nil
}

// Vector addition
func (v *Vector) add(u *Vector, modulus *big.Int) *Vector {
	result := &Vector{coeffs: make([]*big.Int, len(v.coeffs))}
	for i := 0; i < len(v.coeffs); i++ {
		result.coeffs[i] = new(big.Int).Add(v.coeffs[i], u.coeffs[i])
		result.coeffs[i].Mod(result.coeffs[i], modulus)
	}
	return result
}

// Vector subtraction
func (v *Vector) sub(u *Vector, modulus *big.Int) *Vector {
	result := &Vector{coeffs: make([]*big.Int, len(v.coeffs))}
	for i := 0; i < len(v.coeffs); i++ {
		result.coeffs[i] = new(big.Int).Sub(v.coeffs[i], u.coeffs[i])
		result.coeffs[i].Mod(result.coeffs[i], modulus)
	}
	return result
}

// Scalar multiplication
func (v *Vector) scalarMul(scalar *big.Int, modulus *big.Int) *Vector {
	result := &Vector{coeffs: make([]*big.Int, len(v.coeffs))}
	for i := 0; i < len(v.coeffs); i++ {
		result.coeffs[i] = new(big.Int).Mul(v.coeffs[i], scalar)
		result.coeffs[i].Mod(result.coeffs[i], modulus)
	}
	return result
}

// Inner product
func (v *Vector) innerProduct(u *Vector, modulus *big.Int) *big.Int {
	result := big.NewInt(0)
	for i := 0; i < len(v.coeffs); i++ {
		term := new(big.Int).Mul(v.coeffs[i], u.coeffs[i])
		result.Add(result, term)
	}
	return result.Mod(result, modulus)
}

// KeyGenLWE generates an LWE key pair
func KeyGenLWE() (*KeyPairLWE, error) {
	a, err := generateRandomVector(nLWE, big.NewInt(qLWE))
	if err != nil {
		return nil, err
	}

	s, err := generateErrorVector(nLWE, sigmaLWE)
	if err != nil {
		return nil, err
	}

	e, err := generateErrorVector(nLWE, sigmaLWE)
	if err != nil {
		return nil, err
	}

	// Public key: a*s + e
	pubKey := a.scalarMul(s.coeffs[0], big.NewInt(qLWE)).add(e, big.NewInt(qLWE))

	return &KeyPairLWE{
		PublicKey:  pubKey,
		PrivateKey: s,
	}, nil
}

// EncryptLWE encrypts a message using the LWE public key
func EncryptLWE(pubKey *Vector, message []byte) (*Vector, error) {
	m := new(big.Int).SetBytes(message)
	u, err := generateRandomVector(nLWE, big.NewInt(qLWE))
	if err != nil {
		return nil, err
	}

	e1, err := generateErrorVector(nLWE, sigmaLWE)
	if err != nil {
		return nil, err
	}

	e2, err := generateErrorVector(nLWE, sigmaLWE)
	if err != nil {
		return nil, err
	}

	// v = a*u + e1
	v := pubKey.scalarMul(u.coeffs[0], big.NewInt(qLWE)).add(e1, big.NewInt(qLWE))

	// c = pubKey*u + e2 + m*floor(q/2)
	mVec := &Vector{coeffs: make([]*big.Int, nLWE)}
	mVec.coeffs[0] = new(big.Int).Mul(m, big.NewInt(qLWE/2))
	c := pubKey.scalarMul(u.coeffs[0], big.NewInt(qLWE)).add(e2, big.NewInt(qLWE)).add(mVec, big.NewInt(qLWE))

	return c, nil
}

// DecryptLWE decrypts a ciphertext using the LWE private key
func DecryptLWE(privKey *Vector, ciphertext *Vector) ([]byte, error) {
	// Compute v*s
	vs := ciphertext.innerProduct(privKey, big.NewInt(qLWE))

	// Recover the message
	m := vs.Div(vs, big.NewInt(qLWE/2))
	return m.Bytes(), nil
}

// RingLWEParams contains parameters for the Ring-LWE scheme
type RingLWEParams struct {
	N int       // Polynomial degree
	Q *big.Int  // Modulus
}

// KeyPairRingLWE structure for Ring-LWE
type KeyPairRingLWE struct {
	PublicKey  []*big.Int
	PrivateKey []*big.Int
}

// generatePolynomial generates a random polynomial with coefficients in [0, q-1]
func generatePolynomial(n int, q *big.Int) ([]*big.Int, error) {
	poly := make([]*big.Int, n)
	for i := 0; i < n; i++ {
		coeff, err := rand.Int(rand.Reader, q)
		if err != nil {
			return nil, err
		}
		poly[i] = coeff
	}
	return poly, nil
}

// KeyGenRingLWE generates a Ring-LWE key pair
func KeyGenRingLWE(params *RingLWEParams) (*KeyPairRingLWE, error) {
	a, err := generatePolynomial(params.N, params.Q)
	if err != nil {
		return nil, err
	}

	s, err := generatePolynomial(params.N, params.Q)
	if err != nil {
		return nil, err
	}

	e, err := generatePolynomial(params.N, params.Q)
	if err != nil {
		return nil, err
	}

	// Public key: a*s + e
	pubKey := make([]*big.Int, params.N)
	for i := 0; i < params.N; i++ {
		pubKey[i] = new(big.Int).Mul(a[i], s[i])
		pubKey[i].Add(pubKey[i], e[i])
		pubKey[i].Mod(pubKey[i], params.Q)
	}

	return &KeyPairRingLWE{
		PublicKey:  pubKey,
		PrivateKey: s,
	}, nil
}

// EncryptRingLWE encrypts a message using the Ring-LWE public key
func EncryptRingLWE(params *RingLWEParams, pubKey []*big.Int, message []byte) ([]*big.Int, error) {
	m := new(big.Int).SetBytes(message)
	u, err := generatePolynomial(params.N, params.Q)
	if err != nil {
		return nil, err
	}

	e1, err := generatePolynomial(params.N, params.Q)
	if err != nil {
		return nil, err
	}

	e2, err := generatePolynomial(params.N, params.Q)
	if err != nil {
		return nil, err
	}

	// v = a*u + e1
	v := make([]*big.Int, params.N)
	for i := 0; i < params.N; i++ {
		v[i] = new(big.Int).Mul(pubKey[i], u[i])
		v[i].Add(v[i], e1[i])
		v[i].Mod(v[i], params.Q)
	}

	// c = pubKey*u + e2 + m*floor(q/2)
	c := make([]*big.Int, params.N)
	mVal := new(big.Int).Mul(m, new(big.Int).Div(params.Q, big.NewInt(2)))
	for i := 0; i < params.N; i++ {
		c[i] = new(big.Int).Mul(pubKey[i], u[i])
		c[i].Add(c[i], e2[i])
		c[i].Add(c[i], mVal)
		c[i].Mod(c[i], params.Q)
	}

	return c, nil
}

// DecryptRingLWE decrypts a ciphertext using the Ring-LWE private key
func DecryptRingLWE(params *RingLWEParams, privKey []*big.Int, ciphertext []*big.Int) ([]byte, error) {
	// Compute v*s
	vs := big.NewInt(0)
	for i := 0; i < params.N; i++ {
		term := new(big.Int).Mul(privKey[i], ciphertext[i])
		vs.Add(vs, term)
	}
	vs.Mod(vs, params.Q)

	// Recover the message
	m := vs.Div(vs, new(big.Int).Div(params.Q, big.NewInt(2)))
	return m.Bytes(), nil
}

// HashLWE function using SHA3-256
func HashLWE(data []byte) []byte {
	hash := sha3.New256()
	hash.Write(data)
	return hash.Sum(nil)
}
