package signature

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"math/big"

	"github.com/pkg/errors"
)

// DigitalSignature encapsulates the details of an ECDSA signature.
type DigitalSignature struct {
	R, S *big.Int
}

// SignaturePayload represents the data needed for signing or verifying.
type SignaturePayload struct {
	Data []byte
}

// DigitalSignatureGenerator handles the creation and verification of digital signatures.
type DigitalSignatureGenerator struct {
	PrivateKey *ecdsa.PrivateKey
	PublicKey  *ecdsa.PublicKey
}

// NewDigitalSignatureGenerator initializes a new DigitalSignatureGenerator with given private key.
func NewDigitalSignatureGenerator(privateKey *ecdsa.PrivateKey) *DigitalSignatureGenerator {
	return &DigitalSignatureGenerator{
		PrivateKey: privateKey,
		PublicKey:  &privateKey.PublicKey,
	}
}

// GenerateSignature creates a digital signature for the given payload.
func (dsg *DigitalSignatureGenerator) GenerateSignature(payload SignaturePayload) (DigitalSignature, error) {
	hashed := sha256.Sum256(payload.Data)
	r, s, err := ecdsa.Sign(rand.Reader, dsg.PrivateKey, hashed[:])
	if err != nil {
		return DigitalSignature{}, errors.Wrap(err, "failed to sign payload")
	}
	return DigitalSignature{R: r, S: s}, nil
}

// VerifySignature verifies the digital signature against the payload.
func (dsg *DigitalSignatureGenerator) VerifySignature(payload SignaturePayload, sig DigitalSignature) bool {
	hashed := sha256.Sum256(payload.Data)
	return ecdsa.Verify(dsg.PublicKey, hashed[:], sig.R, sig.S)
}

// ASN1Marshal marshals DigitalSignature to ASN.1 DER encoded form.
func (sig *DigitalSignature) ASN1Marshal() ([]byte, error) {
	return asn1.Marshal(*sig)
}

// ASN1Unmarshal unmarshals ASN.1 DER encoded byte slice into a DigitalSignature.
func (sig *DigitalSignature) ASN1Unmarshal(data []byte) error {
	_, err := asn1.Unmarshal(data, sig)
	if err != nil {
		return errors.Wrap(err, "failed to unmarshal ASN.1 encoded signature")
	}
	return nil
}

// Example usage
func main() {
	// Generate a new ECDSA private key.
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}

	generator := NewDigitalSignatureGenerator(privateKey)

	// Simulating a transaction payload
	payload := SignaturePayload{Data: []byte("Hello, Blockchain!")}

	// Generate signature
	signature, err := generator.GenerateSignature(payload)
	if err != nil {
		panic(err)
	}

	// Verify signature
	valid := generator.VerifySignature(payload, signature)
	if valid {
		println("Signature verified successfully!")
	} else {
		println("Signature verification failed.")
	}
}

// This code implements a comprehensive digital signature generation and verification system using ECDSA, providing essential security features for blockchain transactions. It includes functionality for generating and verifying signatures, handling ASN.1 encoding, and integrating advanced cryptographic techniques, ensuring high standards of data integrity and authentication.
