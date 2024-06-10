package signature

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/asn1"
	"errors"
	"math/big"

	"github.com/synthron/synthron_blockchain/pkg/crypto/hash"
)

// Signature represents an ECDSA signature.
type Signature struct {
	R, S *big.Int
}

// AggregateSignatures combines multiple signatures into a single signature.
func AggregateSignatures(signatures []Signature) (Signature, error) {
	if len(signatures) == 0 {
		return Signature{}, errors.New("no signatures provided")
	}

	// Placeholder for aggregation logic. In practice, you would implement a specific aggregation technique.
	// For example, using BLS or Schnorr signatures (not directly supported in Golang standard library).
	// Here we just return the first signature for demonstration purposes.
	return signatures[0], nil
}

// VerifyAggregatedSignature verifies an aggregated signature against multiple public keys and a message.
func VerifyAggregatedSignature(aggregatedSig Signature, publicKeys []*ecdsa.PublicKey, message []byte) bool {
	// Example implementation using a simple verification method.
	// In a real-world application, a more complex scheme such as BLS or Schnorr would be used for aggregation and verification.
	for _, publicKey := range publicKeys {
		if !ecdsa.Verify(publicKey, hash.ComputeSHA256(message), aggregatedSig.R, aggregatedSig.S) {
			return false
		}
	}
	return true
}

// Example usage of aggregating and verifying signatures.
func main() {
	// Simulate generating keys and signing a message.
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}

	message := []byte("Hello, blockchain!")
	hashed := hash.ComputeSHA256(message)

	r, s, err := ecdsa.Sign(rand.Reader, privateKey, hashed)
	if err != nil {
		panic(err)
	}
	signature := Signature{R: r, S: s}

	// Simulate aggregation.
	signatures := []Signature{signature}
	aggregatedSignature, err := AggregateSignatures(signatures)
	if err != nil {
		panic(err)
	}

	// Verify aggregated signature.
	publicKeys := []*ecdsa.PublicKey{&privateKey.PublicKey}
	isValid := VerifyAggregatedSignature(aggregatedSignature, publicKeys, message)
	if !isValid {
		println("Failed to verify aggregated signature")
	} else {
		println("Aggregated signature verified successfully")
	}
}
