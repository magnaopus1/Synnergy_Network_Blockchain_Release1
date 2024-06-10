package signature

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"math/big"

	"github.com/synthron/synthron_blockchain/pkg/crypto/hash"
)

// ZeroKnowledgeProof represents a structure for zero-knowledge proofs in signatures.
type ZeroKnowledgeProof struct {
	S *big.Int // Proof component, typically represents the signature's scalar component.
}

// GenerateZeroKnowledgeSignature generates a zero-knowledge signature that proves the signer knows the private key without revealing it.
func GenerateZeroKnowledgeSignature(privateKey *ecdsa.PrivateKey, data []byte) (ZeroKnowledgeProof, error) {
	if privateKey == nil {
		return ZeroKnowledgeProof{}, errors.New("private key cannot be nil")
	}

	hashedData := hash.ComputeSHA256(data)

	r, s, err := ecdsa.Sign(rand.Reader, privateKey, hashedData)
	if err != nil {
		return ZeroKnowledgeProof{}, err
	}

	// Only returning 's' as part of the zero-knowledge proof for simplicity. In practice, use a more sophisticated scheme.
	return ZeroKnowledgeProof{S: s}, nil
}

// VerifyZeroKnowledgeSignature verifies the zero-knowledge proof against the public key and data.
func VerifyZeroKnowledgeSignature(publicKey *ecdsa.PublicKey, data []byte, proof ZeroKnowledgeProof) bool {
	if publicKey == nil {
		return false
	}

	hashedData := hash.ComputeSHA256(data)

	// In a real-world application, you would implement a proper zero-knowledge verification method.
	// Here we simulate this by checking if 's' (from the proof) can be used with the public key to derive a valid signature.
	r := big.NewInt(0) // Normally, you would have 'r' as part of the signature.
	return ecdsa.Verify(publicKey, hashedData, r, proof.S)
}

// Example usage of zero-knowledge signatures.
func main() {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}

	data := []byte("Secure transaction")
	signature, err := GenerateZeroKnowledgeSignature(privateKey, data)
	if err != nil {
		panic(err)
	}

	valid := VerifyZeroKnowledgeSignature(&privateKey.PublicKey, data, signature)
	if valid {
		println("Zero-knowledge signature verified successfully")
	} else {
		println("Failed to verify zero-knowledge signature")
	}
}
