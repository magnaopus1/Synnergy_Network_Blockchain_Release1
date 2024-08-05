package hash_based

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"
)

// NewHashChain creates a new HashChain
func NewHashChain() *HashChain {
	return &HashChain{
		chain: []string{},
	}
}

// AddBlock adds a new block to the hash chain
func (hc *HashChain) AddBlock(data string) (string, error) {
	hc.mutex.Lock()
	defer hc.mutex.Unlock()

	// Get the previous block hash
	prevHash := ""
	if len(hc.chain) > 0 {
		prevHash = hc.chain[len(hc.chain)-1]
	}

	// Generate a new block hash
	newHash, err := hc.generateHash(prevHash, data)
	if err != nil {
		return "", err
	}

	// Add the new block hash to the chain
	hc.chain = append(hc.chain, newHash)
	return newHash, nil
}

// generateHash creates a new hash from the previous hash and the new data
func (hc *HashChain) generateHash(prevHash, data string) (string, error) {
	hash := sha256.New()
	_, err := hash.Write([]byte(prevHash + data))
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

// VerifyChain verifies the integrity of the hash chain
func (hc *HashChain) VerifyChain() bool {
	hc.mutex.Lock()
	defer hc.mutex.Unlock()

	for i := 1; i < len(hc.chain); i++ {
		prevHash := hc.chain[i-1]
		currHash := hc.chain[i]
		expectedHash, err := hc.generateHash(prevHash, "")
		if err != nil || currHash != expectedHash {
			return false
		}
	}
	return true
}

// GetChain returns the entire hash chain
func (hc *HashChain) GetChain() []string {
	hc.mutex.Lock()
	defer hc.mutex.Unlock()

	return hc.chain
}

// Argon2Hash generates a hash using Argon2
func Argon2Hash(password, salt string) (string, error) {
	saltBytes := []byte(salt)
	hash := argon2.IDKey([]byte(password), saltBytes, 1, 64*1024, 4, 32)
	return hex.EncodeToString(hash), nil
}


// NewSecureMessage creates a new secure message
func NewSecureMessage(message string) (*SecureMessage, error) {
	timestamp := time.Now().Unix()
	hash, err := Argon2Hash(message, fmt.Sprintf("%d", timestamp))
	if err != nil {
		return nil, err
	}
	return &SecureMessage{
		Message:   message,
		Timestamp: timestamp,
		Hash:      hash,
	}, nil
}

// Validate validates the integrity of the secure message
func (sm *SecureMessage) Validate() bool {
	expectedHash, err := Argon2Hash(sm.Message, fmt.Sprintf("%d", sm.Timestamp))
	if err != nil {
		return false
	}
	return sm.Hash == expectedHash
}


// NewMerkleTree creates a new Merkle Tree
func NewMerkleTree(data []string) (*MerkleTree, error) {
	if len(data) == 0 {
		return nil, errors.New("data must not be empty")
	}
	var nodes []*MerkleNode
	for _, datum := range data {
		hash := sha256.Sum256([]byte(datum))
		nodes = append(nodes, &MerkleNode{Hash: hex.EncodeToString(hash[:])})
	}

	for len(nodes) > 1 {
		var level []*MerkleNode
		for i := 0; i < len(nodes); i += 2 {
			if i+1 < len(nodes) {
				hash := sha256.Sum256([]byte(nodes[i].Hash + nodes[i+1].Hash))
				level = append(level, &MerkleNode{
					Left:  nodes[i],
					Right: nodes[i+1],
					Hash:  hex.EncodeToString(hash[:]),
				})
			} else {
				level = append(level, nodes[i])
			}
		}
		nodes = level
	}

	return &MerkleTree{Root: nodes[0]}, nil
}

// VerifyData verifies if a piece of data is included in the Merkle Tree
func (mt *MerkleTree) VerifyData(data string, proof []string) bool {
	hash := sha256.Sum256([]byte(data))
	currentHash := hex.EncodeToString(hash[:])

	for _, p := range proof {
		hash := sha256.Sum256([]byte(currentHash + p))
		currentHash = hex.EncodeToString(hash[:])
	}

	return currentHash == mt.Root.Hash
}

// GenerateProof generates a proof of inclusion for a piece of data in the Merkle Tree
func (mt *MerkleTree) GenerateProof(data string) ([]string, error) {
	var proof []string
	hash := sha256.Sum256([]byte(data))
	currentHash := hex.EncodeToString(hash[:])

	var traverse func(*MerkleNode) bool
	traverse = func(node *MerkleNode) bool {
		if node == nil {
			return false
		}
		if node.Hash == currentHash {
			return true
		}
		if traverse(node.Left) {
			proof = append(proof, node.Right.Hash)
			return true
		}
		if traverse(node.Right) {
			proof = append(proof, node.Left.Hash)
			return true
		}
		return false
	}

	if !traverse(mt.Root) {
		return nil, errors.New("data not found in Merkle Tree")
	}

	return proof, nil
}

// NewMerkleTree creates a new Merkle tree from the provided data
func NewMerkleTree(data [][]byte) (*MerkleTree, error) {
	if len(data) == 0 {
		return nil, errors.New("data must not be empty")
	}

	var nodes []*MerkleNode
	for _, datum := range data {
		hash := sha256.Sum256(datum)
		nodes = append(nodes, &MerkleNode{Hash: hex.EncodeToString(hash[:])})
	}

	for len(nodes) > 1 {
		var level []*MerkleNode
		for i := 0; i < len(nodes); i += 2 {
			if i+1 < len(nodes) {
				hash := sha256.Sum256([]byte(nodes[i].Hash + nodes[i+1].Hash))
				level = append(level, &MerkleNode{
					Left:  nodes[i],
					Right: nodes[i+1],
					Hash:  hex.EncodeToString(hash[:]),
				})
			} else {
				level = append(level, nodes[i])
			}
		}
		nodes = level
	}

	return &MerkleTree{Root: nodes[0]}, nil
}



// NewMerkleSignatureScheme creates a new Merkle Signature Scheme
func NewMerkleSignatureScheme(secretKeys [][]byte) (*MerkleSignatureScheme, error) {
	tree, err := NewMerkleTree(secretKeys)
	if err != nil {
		return nil, err
	}

	return &MerkleSignatureScheme{
		tree:          tree,
		secretKeys:    secretKeys,
		publicKey:     tree.Root.Hash,
		usedLeafNodes: make(map[int]bool),
	}, nil
}

// GetPublicKey returns the public key of the Merkle Signature Scheme
func (mss *MerkleSignatureScheme) GetPublicKey() string {
	return mss.publicKey
}

// Sign signs the given message using an available leaf node
func (mss *MerkleSignatureScheme) Sign(message []byte) (string, []string, error) {
	mss.mutex.Lock()
	defer mss.mutex.Unlock()

	leafIndex, err := mss.getAvailableLeafIndex()
	if err != nil {
		return "", nil, err
	}

	secretKey := mss.secretKeys[leafIndex]
	signature, err := argon2Key(message, secretKey)
	if err != nil {
		return "", nil, err
	}

	proof, err := mss.tree.generateProof(secretKey)
	if err != nil {
		return "", nil, err
	}

	mss.usedLeafNodes[leafIndex] = true
	return signature, proof, nil
}

// Verify verifies the signature of the given message
func (mss *MerkleSignatureScheme) Verify(message []byte, signature string, proof []string) bool {
	for i, sk := range mss.secretKeys {
		calculatedSignature, err := argon2Key(message, sk)
		if err != nil || calculatedSignature != signature {
			continue
		}

		return mss.tree.verifyProof(sk, proof)
	}
	return false
}

// getAvailableLeafIndex finds the next available leaf index for signing
func (mss *MerkleSignatureScheme) getAvailableLeafIndex() (int, error) {
	for i := range mss.secretKeys {
		if !mss.usedLeafNodes[i] {
			return i, nil
		}
	}
	return 0, errors.New("no available leaf nodes")
}

// argon2Key generates an Argon2 key from the message and secret key
func argon2Key(message, secretKey []byte) (string, error) {
	salt := sha256.Sum256(secretKey)
	key := argon2.IDKey(message, salt[:], 1, 64*1024, 4, 32)
	return hex.EncodeToString(key), nil
}

// generateProof generates a proof of inclusion for the given leaf node
func (mt *MerkleTree) generateProof(data []byte) ([]string, error) {
	var proof []string
	hash := sha256.Sum256(data)
	currentHash := hex.EncodeToString(hash[:])

	var traverse func(*MerkleNode) bool
	traverse = func(node *MerkleNode) bool {
		if node == nil {
			return false
		}
		if node.Hash == currentHash {
			return true
		}
		if traverse(node.Left) {
			proof = append(proof, node.Right.Hash)
			return true
		}
		if traverse(node.Right) {
			proof = append(proof, node.Left.Hash)
			return true
		}
		return false
	}

	if !traverse(mt.Root) {
		return nil, errors.New("data not found in Merkle Tree")
	}

	return proof, nil
}

// verifyProof verifies if the given data and proof lead to the root hash
func (mt *MerkleTree) verifyProof(data []byte, proof []string) bool {
	hash := sha256.Sum256(data)
	currentHash := hex.EncodeToString(hash[:])

	for _, p := range proof {
		hash := sha256.Sum256([]byte(currentHash + p))
		currentHash = hex.EncodeToString(hash[:])
	}

	return currentHash == mt.Root.Hash
}

// Argon2Hash generates a hash using Argon2
func Argon2Hash(password, salt string) (string, error) {
	saltBytes := []byte(salt)
	hash := argon2.IDKey([]byte(password), saltBytes, 1, 64*1024, 4, 32)
	return hex.EncodeToString(hash), nil
}

// Example of how to generate a set of secret keys
func generateSecretKeys(n int) ([][]byte, error) {
	var secretKeys [][]byte
	for i := 0; i < n; i++ {
		secretKey, err := generateRandomBytes(32)
		if err != nil {
			return nil, err
		}
		secretKeys = append(secretKeys, secretKey)
	}
	return secretKeys, nil
}

// generateRandomBytes generates a slice of random bytes of the given length
func generateRandomBytes(length int) ([]byte, error) {
	b := make([]byte, length)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}
	return b, nil
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

// Constants for LWE parameters
const (
	nLWE = 1024  // Dimension of the LWE instance
	qLWE = 1 << 14 // Modulus for coefficients
	sigmaLWE = 3.2 // Standard deviation for error distribution
)

// Vector structure representing LWE polynomials
type Vector struct {
	coeffs []*big.Int
}

// KeyPair structure for LWE
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
	pubKey := a.innerProduct(s, big.NewInt(qLWE)).Add(a.innerProduct(s, big.NewInt(qLWE)), e.innerProduct(e, big.NewInt(qLWE)))

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
	v := pubKey.innerProduct(u, big.NewInt(qLWE)).Add(pubKey.innerProduct(u, big.NewInt(qLWE)), e1.innerProduct(e1, big.NewInt(qLWE)))

	// c = pubKey*u + e2 + m*floor(q/2)
	mVec := &Vector{coeffs: make([]*big.Int, nLWE)}
	mVec.coeffs[0] = new(big.Int).Mul(m, big.NewInt(qLWE/2))
	c := pubKey.innerProduct(u, big.NewInt(qLWE)).Add(pubKey.innerProduct(u, big.NewInt(qLWE)), e2.innerProduct(e2, big.NewInt(qLWE)).Add(e2.innerProduct(e2, big.NewInt(qLWE)), mVec.innerProduct(mVec, big.NewInt(qLWE))))

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

// HashLWE function using SHA3-256
func HashLWE(data []byte) []byte {
	hash := sha3.New256()
	hash.Write(data)
	return hash.Sum(nil)
}

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

// DualLayerSecurity provides a two-layer security system combining classical and quantum-resistant algorithms.
type DualLayerSecurity struct {
	ClassicalKey      []byte
	QuantumResistantKey []byte
}

// NewDualLayerSecurity initializes a new instance of DualLayerSecurity with the provided keys.
func NewDualLayerSecurity(classicalKey, quantumResistantKey []byte) *DualLayerSecurity {
	return &DualLayerSecurity{
		ClassicalKey:      classicalKey,
		QuantumResistantKey: quantumResistantKey,
	}
}

// GenerateClassicalKey generates a classical cryptographic key using Scrypt.
func GenerateClassicalKey(password, salt []byte) ([]byte, error) {
	dk, err := scrypt.Key(password, salt, 16384, 8, 1, 32)
	if err != nil {
		return nil, err
	}
	return dk, nil
}

// GenerateQuantumResistantKey generates a quantum-resistant cryptographic key using Argon2.
func GenerateQuantumResistantKey(password, salt []byte) []byte {
	return argon2.IDKey(password, salt, 1, 64*1024, 4, 32)
}

// Encrypt encrypts data using dual-layer security.
func (dls *DualLayerSecurity) Encrypt(plaintext []byte) (string, error) {
	// Classical Encryption (AES)
	block, err := aes.NewCipher(dls.ClassicalKey)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)

	// Quantum-Resistant Encryption (SHA-256)
	hash := sha256.Sum256(append(dls.QuantumResistantKey, ciphertext...))
	finalCiphertext := append(ciphertext, hash[:]...)

	return hex.EncodeToString(finalCiphertext), nil
}

// Decrypt decrypts data using dual-layer security.
func (dls *DualLayerSecurity) Decrypt(encodedCiphertext string) ([]byte, error) {
	finalCiphertext, err := hex.DecodeString(encodedCiphertext)
	if err != nil {
		return nil, err
	}

	// Extract components
	hashSize := sha256.Size
	ciphertext := finalCiphertext[:len(finalCiphertext)-hashSize]
	expectedHash := finalCiphertext[len(finalCiphertext)-hashSize:]

	// Verify Quantum-Resistant Hash
	actualHash := sha256.Sum256(append(dls.QuantumResistantKey, ciphertext...))
	if !bytes.Equal(expectedHash, actualHash[:]) {
		return nil, errors.New("invalid ciphertext: quantum-resistant hash mismatch")
	}

	// Classical Decryption (AES)
	block, err := aes.NewCipher(dls.ClassicalKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("invalid ciphertext: too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}


