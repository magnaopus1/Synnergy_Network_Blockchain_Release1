// Package assets provides functionalities for verifying ownership of agricultural tokens in the SYN4900 Token Standard.
package assets

import (
	"errors"
	"time"

	"github.com/synnergy_network/compliance"
	"github.com/synnergy_network/ledger"
	"github.com/synnergy_network/security"
)

// OwnershipVerification represents the verification details of a token's ownership.
type OwnershipVerification struct {
	TokenID           string    `json:"token_id"`
	OwnerPublicKey    string    `json:"owner_public_key"`
	VerificationDate  time.Time `json:"verification_date"`
	Verified          bool      `json:"verified"`
	VerificationProof string    `json:"verification_proof"`
}

// VerifyOwnership performs ownership verification for a given token using the owner's public key.
func VerifyOwnership(token *AgriculturalToken, ownerPublicKey, signature string) (*OwnershipVerification, error) {
	if token == nil || ownerPublicKey == "" || signature == "" {
		return nil, errors.New("invalid input for ownership verification")
	}

	// Verify the signature using the public key and token details
	verificationData := token.TokenID + token.Owner
	isValid, err := security.VerifySignature(ownerPublicKey, verificationData, signature)
	if err != nil || !isValid {
		return nil, errors.New("ownership verification failed")
	}

	// Create an OwnershipVerification record
	verification := &OwnershipVerification{
		TokenID:          token.TokenID,
		OwnerPublicKey:   ownerPublicKey,
		VerificationDate: time.Now(),
		Verified:         true,
		VerificationProof: security.GenerateVerificationProof(verificationData, ownerPublicKey),
	}

	// Log verification in the ledger
	if err := ledger.LogOwnershipVerification(verification); err != nil {
		return nil, err
	}

	return verification, nil
}

// RevokeOwnership revokes the ownership of a token based on compliance issues or other critical reasons.
func RevokeOwnership(token *AgriculturalToken, reason string) error {
	if token == nil || reason == "" {
		return errors.New("invalid input for ownership revocation")
	}

	// Update the token's status to reflect ownership revocation
	token.Status = "Revoked"

	// Log the revocation event
	revocationEvent := ledger.OwnershipRevocationEvent{
		TokenID:         token.TokenID,
		RevocationDate:  time.Now(),
		Reason:          reason,
	}
	if err := ledger.LogOwnershipRevocation(revocationEvent); err != nil {
		return err
	}

	return nil
}

// ValidateOwnerCompliance ensures that the current owner complies with relevant regulations.
func ValidateOwnerCompliance(token *AgriculturalToken) error {
	if token == nil {
		return errors.New("token cannot be nil")
	}

	// Assume the compliance check involves verifying the owner's adherence to specific standards
	compliant := compliance.CheckOwnerCompliance(token.Owner)
	if !compliant {
		return errors.New("owner is not compliant with the relevant regulations")
	}

	return nil
}

// LogOwnershipVerification logs the details of ownership verification in the ledger.
func LogOwnershipVerification(verification *OwnershipVerification) error {
	return ledger.LogOwnershipVerification(verification)
}

// GenerateVerificationProof generates a proof of verification for ownership claims.
func GenerateVerificationProof(verificationData, publicKey string) string {
	return security.GenerateVerificationProof(verificationData, publicKey)
}
