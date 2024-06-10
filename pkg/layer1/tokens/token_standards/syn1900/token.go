package syn1900

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

// EducationCredit represents a single unit of educational achievement.
type EducationCredit struct {
	CreditID       string    `json:"creditId"`       // Unique identifier for the credit
	CourseID       string    `json:"courseId"`       // Identifier for the course associated with the credit
	CourseName     string    `json:"courseName"`     // Name of the course
	Issuer         string    `json:"issuer"`         // Identifier for the issuer (school, university, online platform)
	Recipient      string    `json:"recipient"`      // Identifier for the recipient (student)
	CreditValue    float64   `json:"creditValue"`    // Value of the credit, e.g., credit hours or CEUs
	IssueDate      time.Time `json:"issueDate"`      // Date the credit was issued
	ExpirationDate time.Time `json:"expirationDate"` // Optional expiration date for the credit
	Metadata       string    `json:"metadata"`       // Additional data as JSON string
	Signature      string    `json:"signature"`      // Digital signature to verify the credit's authenticity
}

// Ledger maintains a record of all education credits issued.
type Ledger struct {
	Credits map[string]EducationCredit // Maps Credit IDs to their corresponding EducationCredits
}

// NewLedger initializes a new empty Ledger for managing Education Credits.
func NewLedger() *Ledger {
	return &Ledger{
		Credits: make(map[string]EducationCredit),
	}
}

// IssueCredit issues a new education credit to a recipient.
func (l *Ledger) IssueCredit(credit EducationCredit) error {
	if _, exists := l.Credits[credit.CreditID]; exists {
		return fmt.Errorf("credit with ID %s already exists", credit.CreditID)
	}

	// Ensure the credit has a valid signature
	if credit.Signature == "" || !verifySignature(credit) {
		return errors.New("invalid signature, cannot issue the credit")
	}

	l.Credits[credit.CreditID] = credit
	return nil
}

// GetCredit retrieves an education credit by its ID.
func (l *Ledger) GetCredit(creditID string) (EducationCredit, error) {
	credit, exists := l.Credits[creditID]
	if !exists {
		return EducationCredit{}, fmt.Errorf("credit with ID %s not found", creditID)
	}
	return credit, nil
}

// RevokeCredit removes a credit from the ledger, effectively revoking it.
func (l *Ledger) RevokeCredit(creditID string) error {
	if _, exists := l.Credits[creditID]; !exists {
		return fmt.Errorf("no credit found with ID %s to revoke", creditID)
	}
	delete(l.Credits, creditID)
	return nil
}

// ListCreditsForRecipient returns all credits for a specific recipient.
func (l *Ledger) ListCreditsForRecipient(recipientID string) ([]EducationCredit, error) {
	var credits []EducationCredit
	for _, credit := range l.Credits {
		if credit.Recipient == recipientID {
			credits = append(credits, credit)
		}
	}
	if len(credits) == 0 {
		return nil, fmt.Errorf("no credits found for recipient ID %s", recipientID)
	}
	return credits, nil
}

// verifySignature simulates a digital signature verification process.
func verifySignature(credit EducationCredit) bool {
	// Simple hash function for demonstration purposes
	data := fmt.Sprintf("%s:%s:%f:%s", credit.CreditID, credit.Recipient, credit.CreditValue, credit.IssueDate)
	hash := sha256.Sum256([]byte(data))
	expectedSignature := hex.EncodeToString(hash[:])
	return credit.Signature == expectedSignature
}
