package consensus

import (
    "crypto/ecdsa"
    "crypto/elliptic"
    "crypto/rand"
    "crypto/sha256"
    "errors"
    "math/big"
    "sync"

    "synnergy_network_blockchain/pkg/synnergy_network/core/cryptocurrency"
)

// SecurityProvider encapsulates all security-related functionalities for the PoS mechanism
type SecurityProvider struct {
    slashingConditions map[string]func(validator *Validator, violationType string) bool
    mutex              sync.Mutex
}

// Validator represents a stakeholder in the PoS system
type Validator struct {
    PublicKey  *ecdsa.PublicKey
    Stake      *big.Int
    Penalty    *big.Int
    IsSlashed  bool
}

// NewSecurityProvider initializes a security provider with predefined slashing conditions
func NewSecurityProvider() *SecurityProvider {
    sp := &SecurityProvider{
        slashingConditions: make(map[string]func(validator *Validator, violationType string) bool),
    }
    sp.setupSlashingConditions()
    return sp
}

// setupSlashingConditions defines various types of slashing conditions
func (sp *SecurityProvider) setupSlashingConditions() {
    sp.slashingConditions["doubleSigning"] = func(validator *Validator, violationType string) bool {
        if violationType == "doubleSigning" {
            penaltyPercentage := big.NewInt(10) // 10% penalty for double signing
            penalty := new(big.Int).Div(new(big.Int).Mul(validator.Stake, penaltyPercentage), big.NewInt(100))
            validator.Penalty = penalty
            validator.IsSlashed = true
            return true
        }
        return false
    }

    sp.slashingConditions["downtime"] = func(validator *Validator, violationType string) bool {
        if violationType == "downtime" {
            penaltyPercentage := big.NewInt(5) // 5% penalty for downtime
            penalty := new(big.Int).Div(new(big.Int).Mul(validator.Stake, penaltyPercentage), big.NewInt(100))
            validator.Penalty = penalty
            validator.IsSlashed = true
            return true
        }
        return false
    }
}

// VerifyBlockSignature checks if the block signature is valid using ECDSA
func (sp *SecurityProvider) VerifyBlockSignature(signature []byte, blockHash []byte, validator *Validator) bool {
    return cryptography.VerifyECDSASignature(validator.PublicKey, signature, blockHash)
}

// ApplySlashing applies the appropriate slashing condition based on the violation type
func (sp *SecurityProvider) ApplySlashing(validator *Validator, violationType string) error {
    sp.mutex.Lock()
    defer sp.mutex.Unlock()
    if condition, exists := sp.slashingConditions[violationType]; exists {
        if condition(validator, violationType) {
            return nil
        }
    }
    return errors.New("no slashing condition met")
}

// HashTransaction creates a hash of the transaction data using SHA-256
func HashTransaction(tx []byte) []byte {
    hash := sha256.Sum256(tx)
    return hash[:]
}

// EnforceMultiSig enforces that a block must be signed by the required quorum of validators
func EnforceMultiSig(blockHash []byte, signatures [][]byte, validators []*Validator, quorum int) bool {
    validSignatures := 0
    for _, validator := range validators {
        for _, signature := range signatures {
            if VerifySignature(signature, blockHash, validator) {
                validSignatures++
                break
            }
        }
    }
    return validSignatures >= quorum
}

// VerifySignature verifies a single signature against a validator's public key
func VerifySignature(signature []byte, data []byte, validator *Validator) bool {
    r, s := new(big.Int).SetBytes(signature[:32]), new(big.Int).SetBytes(signature[32:])
    return ecdsa.Verify(validator.PublicKey, data, r, s)
}
