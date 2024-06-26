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

// DigitalSignature holds the signature data.
type DigitalSignature struct {
	R, S *big.Int
}

// DigitalSignatureVerifier handles the verification of digital signatures.
type DigitalSignatureVerifier struct {
	PublicKey *ecdsa.PublicKey
}

// NewDigitalSignatureVerifier initializes a verifier with a public key.
func NewDigitalSignatureVerifier(publicKey *ecdsa.PublicKey) *DigitalSignatureVerifier {
	return &DigitalSignatureVerifier{
		PublicKey: publicKey,
	}
}

// VerifySignature verifies a digital signature against the provided data.
func (dsv *DigitalSignatureVerifier) VerifySignature(data []byte, signature DigitalSignature) bool {
	hashedData := sha256.Sum256(data)
	return ecdsa.Verify(dsv.PublicKey, hashedData[:], signature.R, signature.S)
}

// ASN1UnmarshalSignature converts ASN.1 DER encoded data into a DigitalSignature.
func ASN1UnmarshalSignature(encodedSig []byte) (DigitalSignature, error) {
	var sig DigitalSignature
	if _, err := asn1.Unmarshal(encodedSig, &sig); err != nil {
		return DigitalSignature{}, errors.Wrap(err, "failed to unmarshal signature")
	}
	return sig, nil
}

// Example usage
func main() {
	// Simulate loading an ECDSA public key (normally loaded from a secure key storage or transmitted securely)
	publicKeyCurve := elliptic.P256()
	x, y := elliptic.Unmarshal(publicKeyCurve, publicKeyBytes) // Assume publicKeyBytes is provided
	if x == nil {
		panic("invalid public key")
	}
	publicKey := &ecdsa.PublicKey{Curve: publicKeyCurve, X: x, Y: y}

	// Initialize verifier
	verifier := NewDigitalSignatureVerifier(publicKey)

	// Example of verifying a signature (assuming you have the data and the signature)
	data := []byte("example data for verification")
	signature, err := ASN1UnmarshalSignature(encodedSignature) // Assume encodedSignature is provided
	if err != nil {
		panic(err)
	}

	isValid := verifier.VerifySignature(data, signature)
	if isValid {
		println("Signature verification successful!")
	} else {
		println("Signature verification failed.")
	}
}

