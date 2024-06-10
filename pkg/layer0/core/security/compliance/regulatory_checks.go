package compliance

import (
	"crypto/rand"
	"encoding/hex"
	"log"
	"errors"
	"golang.org/x/crypto/argon2"
)

const (
	SaltSize       = 16
	KeyLength      = 32
	ArgonTime      = 1
	ArgonMemory    = 64 * 1024
	ArgonThreads   = 4
)

type RegulatoryRequirements struct {
	MaxTransactionValue float64
	BlacklistedAddresses map[string]bool
	RequiredDocumentation map[string][]string
}

type ComplianceChecker struct {
	Requirements *RegulatoryRequirements
}

func NewComplianceChecker(req *RegulatoryRequirements) *ComplianceChecker {
	return &ComplianceChecker{
		Requirements: req,
	}
}

func (cc *ComplianceChecker) CheckTransactionCompliance(tx Transaction) (bool, error) {
	if cc.Requirements.BlacklistedAddresses[tx.SourceAddress] {
		return false, errors.New("transaction from blacklisted address")
	}
	if tx.Value > cc.Requirements.MaxTransactionValue {
		return false, errors.New("transaction exceeds maximum value limit")
	}
	if docs, ok := cc.Requirements.RequiredDocumentation[tx.Type]; ok {
		if !validateDocumentation(tx.Documentation, docs) {
			return false, errors.New("required documentation not complete")
		}
	}
	return true, nil
}

func validateDocumentation(provided, required []string) bool {
	providedMap := make(map[string]bool)
	for _, doc := range provided {
		providedMap[doc] = true
	}
	for _, doc := range required {
		if !providedMap[doc] {
			return false
		}
	}
	return true
}

func GenerateSalt() ([]byte, error) {
	salt := make([]byte, SaltSize)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	return salt, nil
}

func EncryptData(data []byte) ([]byte, error) {
	salt, err := GenerateSalt()
	if err != nil {
		return nil, err
	}
	hash := argon2.IDKey(data, salt, ArgonTime, ArgonMemory, ArgonThreads, KeyLength)
	return append(salt, hash...), nil
}

func DecryptData(encryptedData []byte) ([]byte, error) {
	if len(encryptedData) < SaltSize {
		return nil, errors.New("encrypted data is too short")
	}
	salt := encryptedData[:SaltSize]
	data := encryptedData[SaltSize:]
	// Normally Argon2 is not used for decryption. This is just an example to handle the encrypted data.
	return argon2.IDKey(data, salt, ArgonTime, ArgonMemory, ArgonThreads, KeyLength), nil
}

func main() {
	req := &RegulatoryRequirements{
		MaxTransactionValue: 10000.0,
		BlacklistedAddresses: map[string]bool{
			"1EvilAddress": true,
		},
		RequiredDocumentation: map[string][]string{
			"international": []string{"passport", "bank_statement"},
		},
	}
	checker := NewComplianceChecker(req)
	tx := Transaction{
		SourceAddress: "1EvilAddress",
		Value: 9500,
		Type: "international",
		Documentation: []string{"passport"},
	}
	compliant, err := checker.CheckTransactionCompliance(tx)
	if err != nil {
		log.Printf("Compliance check failed: %v", err)
	} else {
		log.Printf("Transaction compliant: %v", compliant)
	}
}
