package syn200

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"sync"
	"time"

	"synthron-blockchain/pkg/common"
)

// CarbonCredit represents a single carbon credit or a batch of credits.
type CarbonCredit struct {
	ID            string    // Unique identifier for the credit
	Issuer        string    // Entity that issues the credits
	Amount        float64   // Amount of CO2 offset, in tonnes
	VerificationID string   // ID for verifying the validity of the credits
	Valid         bool      // Status of credit validation
	CreatedAt     time.Time // Timestamp of credit issuance
}

// TokenRegistry manages the lifecycle of carbon credits.
type TokenRegistry struct {
	Credits map[string]*CarbonCredit // Map of credit IDs to carbon credits
	mutex   sync.RWMutex
}

// NewTokenRegistry creates a registry to manage carbon credits.
func NewTokenRegistry() *TokenRegistry {
	return &TokenRegistry{
		Credits: make(map[string]*CarbonCredit),
	}
}

// IssueCredit issues a new set of carbon credits to an entity.
func (tr *TokenRegistry) IssueCredit(issuer string, amount float64, verificationID string) (*CarbonCredit, error) {
	tr.mutex.Lock()
	defer tr.mutex.Unlock()

	creditID := generateCreditID(issuer, amount, time.Now())
	credit := &CarbonCredit{
		ID:            creditID,
		Issuer:        issuer,
		Amount:        amount,
		VerificationID: verificationID,
		Valid:         false,  // Initially set to false until verified
		CreatedAt:     time.Now(),
	}

	tr.Credits[creditID] = credit
	log.Printf("Issued %f tonnes of carbon credits to %s, ID: %s", amount, issuer, creditID)
	return credit, nil
}

// VerifyCredit marks a carbon credit as verified.
func (tr *TokenRegistry) VerifyCredit(creditID string) error {
	tr.mutex.Lock()
	defer tr.mutex.Unlock()

	credit, exists := tr.Credits[creditID]
	if !exists {
		return fmt.Errorf("credit ID %s not found", creditID)
	}

	credit.Valid = true
	log.Printf("Verified carbon credit ID: %s", creditID)
	return nil
}

// TransferCredit transfers credits from one issuer to another.
func (tr *TokenRegistry) TransferCredit(creditID, newIssuer string, amount float64) error {
	tr.mutex.Lock()
	defer tr.mutex.Unlock()

	credit, exists := tr.Credits[creditID]
	if !exists {
		return fmt.Errorf("credit ID %s not found", creditID)
	}

	if credit.Amount < amount {
		return fmt.Errorf("insufficient credit amount for transfer: %f requested, %f available", amount, credit.Amount)
	}

	// Reduce the amount from the current credit and issue new credit to the new issuer
	credit.Amount -= amount
	newCredit, _ := tr.IssueCredit(newIssuer, amount, credit.VerificationID) // Ignore error for simplicity
	log.Printf("Transferred %f tonnes of carbon credits from %s to %s", amount, credit.Issuer, newIssuer)

	// Optionally, validate the new credit immediately if the original was already validated
	if credit.Valid {
		newCredit.Valid = true
	}

	return nil
}

func generateCreditID(issuer string, amount float64, timestamp time.Time) string {
	data := fmt.Sprintf("%s:%f:%v", issuer, amount, timestamp)
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}
