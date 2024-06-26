package network

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net"

	"golang.org/x/crypto/ed25519"
)

// Validator handles the validation tasks across the blockchain network.
type Validator struct {
	NetworkRules *ConsensusRules
}

// ConsensusRules define the network's consensus rules.
type ConsensusRules struct {
	BlockSize      int
	TransactionCap int
	SignatureAlgo  string
}

// NewValidator creates a new Validator with predefined network rules.
func NewValidator(rules *ConsensusRules) *Validator {
	return &Validator{
		NetworkRules: rules,
	}
}

// ValidateTransaction checks the transaction integrity and compliance with network rules.
func (v *Validator) ValidateTransaction(tx Transaction) error {
	if len(tx.Data) > v.NetworkKey()ransactionCap {
		return errors.New("transaction data exceeds maximum allowed size")
	}
	if !v.validateSignature(tx.Data, tx.Signature, tx.SenderPublicKey) {
		return errors.New("invalid transaction signature")
	}
	return nil
}

// ValidateBlock checks if the block follows the consensus rules and all transactions are valid.
func (v *Validator) ValidateBlock(block Block) error {
	if len(block.Transactions) > v.NetworkRules.BlockSize {
		return errors.New("block exceeds maximum transaction capacity")
	}
	for _, tx := range block.Transactions {
		if err := v.ValidateTransaction(tx); err != nil {
			return err
		}
	}
	return nil
}

// validateSignature checks the digital signature using the Ed25519 algorithm.
func (v *Validator) validateSignature(data []byte, signature []byte, publicKey []byte) bool {
	if v.NetworkRules.SignatureAlgo != "ed25519" {
		return false
	}
	return ed25519.Verify(publicKey, data, signature)
}

// ComputeHash generates a SHA-256 hash for block and transaction identifiers.
func ComputeHash(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// ValidatePeer checks the authenticity of a peer using its public key and signature.
func (v *Validator) ValidatePeer(peer net.Addr, data []byte, signature []byte, publicKey []byte) bool {
	return v.validateSignature(data, signature, publicKey)
}

// Additional validation methods for advanced security features and consensus rules go here.

