package common

import (
	"math/big"
	"math/rand"
)

// ZeroKnowledgeProof represents the structure of a zero-knowledge proof.
type ZeroKnowledgeProof struct {
	A, B, C *big.Int // Components of the zero-knowledge proof
}

// CreateZeroKnowledgeProof creates a zero-knowledge proof for a given secret using the public key.
func CreateZeroKnowledgeProof(secret, publicKey *big.Int) (*ZeroKnowledgeProof, error) {
	r, err := rand.Int(rand.Reader, publicKey)
	if err != nil {
		return nil, err
	}
	
	// A = g^r (mod p)
	A := new(big.Int).Exp(publicKey, r, nil)
	
	// c = Hash(A || secret)
	c := sha256Hash(A, secret)
	
	// z = r + c * secret (mod q)
	z := new(big.Int).Add(r, new(big.Int).Mul(c, secret))
	
	return &ZeroKnowledgeProof{
		A: A,
		B: c,
		C: z,
	}, nil
}

// VerifyZeroKnowledgeProof verifies a zero-knowledge proof for a given secret and public key.
func VerifyZeroKnowledgeProof(zkp *ZeroKnowledgeProof, publicKey *big.Int) (bool, error) {
	// A' = g^z / y^c (mod p)
	A1 := new(big.Int).Exp(publicKey, zkp.C, nil)
	A2 := new(big.Int).Exp(publicKey, zkp.B, nil)
	A1.Mod(A1.Mul(A1, A2), nil)
	
	// c' = Hash(A' || secret)
	c := sha256Hash(zkp.A, zkp.B)
	
	// Check if c == c'
	return c.Cmp(zkp.B) == 0, nil
}