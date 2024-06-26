package data_protection

import (
	"crypto/rand"
	"crypto/sha256"
	"math/big"

	"github.com/didiercrunch/zkp"
)

// ZeroKnowledgeProofs handles ZKP operations
type ZeroKnowledgeProofs struct {
	secret *big.Int
	public *big.Int
	proof  *zkp.Proof
}

// NewZeroKnowledgeProofs initializes a new ZeroKnowledgeProofs instance
func NewZeroKnowledgeProofs(secret *big.Int) *ZeroKnowledgeProofs {
	z := &ZeroKnowledgeProofs{
		secret: secret,
		public: new(big.Int).Exp(big.NewInt(2), secret, nil),
	}
	return z
}

// GenerateProof generates a zero-knowledge proof for the secret
func (z *ZeroKnowledgeProofs) GenerateProof() error {
	prover := zkp.NewProver(z.secret, big.NewInt(2), z.public)
	proof, err := prover.Prove(rand.Reader)
	if err != nil {
		return err
	}
	z.proof = proof
	return nil
}

// VerifyProof verifies the zero-knowledge proof
func (z *ZeroKnowledgeProofs) VerifyProof() (bool, error) {
	verifier := zkp.NewVerifier(big.NewInt(2), z.public)
	return verifier.Verify(z.proof)
}

// SerializeProof serializes the proof to a byte slice
func (z *ZeroKnowledgeProofs) SerializeProof() ([]byte, error) {
	return z.proof.MarshalBinary()
}

// DeserializeProof deserializes the proof from a byte slice
func (z *ZeroKnowledgeProofs) DeserializeProof(data []byte) error {
	proof := new(zkp.Proof)
	err := proof.UnmarshalBinary(data)
	if err != nil {
		return err
	}
	z.proof = proof
	return nil
}

// HashProof generates a SHA-256 hash of the proof
func (z *ZeroKnowledgeProofs) HashProof() ([]byte, error) {
	proofBytes, err := z.SerializeProof()
	if err != nil {
		return nil, err
	}
	hash := sha256.Sum256(proofBytes)
	return hash[:], nil
}

// ZeroKnowledgeProofExample demonstrates how to use zero-knowledge proofs
func ZeroKnowledgeProofExample() {
	secret := big.NewInt(12345)
	z := NewZeroKnowledgeProofs(secret)

	err := z.GenerateProof()
	if err != nil {
		panic(err)
	}

	valid, err := z.VerifyProof()
	if err != nil {
		panic(err)
	}

	if !valid {
		panic("proof is not valid")
	}

	proofBytes, err := z.SerializeProof()
	if err != nil {
		panic(err)
	}

	newZ := NewZeroKnowledgeProofs(secret)
	err = newZ.DeserializeProof(proofBytes)
	if err != nil {
		panic(err)
	}

	valid, err = newZ.VerifyProof()
	if err != nil {
		panic(err)
	}

	if !valid {
		panic("deserialized proof is not valid")
	}

	hash, err := z.HashProof()
	if err != nil {
		panic(err)
	}

	println("Proof hash:", hash)
}
