package challenge

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"
)

// ArbitrationMechanism is the main structure for handling disputes in the optimistic rollup.
type ArbitrationMechanism struct {
	disputes map[string]*Dispute
	mutex    sync.Mutex
}

// Dispute represents a dispute in the rollup.
type Dispute struct {
	ID             string
	Challenger     string
	Defendant      string
	Status         string
	SubmittedAt    time.Time
	ResolutionTime time.Time
	Result         string
	Evidence       []string
}

// NewArbitrationMechanism initializes a new ArbitrationMechanism.
func NewArbitrationMechanism() *ArbitrationMechanism {
	return &ArbitrationMechanism{
		disputes: make(map[string]*Dispute),
	}
}

// CreateDispute initiates a new dispute.
func (am *ArbitrationMechanism) CreateDispute(challenger, defendant string, evidence []string) (string, error) {
	am.mutex.Lock()
	defer am.mutex.Unlock()

	disputeID := generateDisputeID(challenger, defendant, time.Now().String())
	if _, exists := am.disputes[disputeID]; exists {
		return "", errors.New("dispute already exists")
	}

	dispute := &Dispute{
		ID:          disputeID,
		Challenger:  challenger,
		Defendant:   defendant,
		Status:      "Pending",
		SubmittedAt: time.Now(),
		Evidence:    evidence,
	}
	am.disputes[disputeID] = dispute
	return disputeID, nil
}

// ResolveDispute resolves a dispute with the given result.
func (am *ArbitrationMechanism) ResolveDispute(disputeID, result string) error {
	am.mutex.Lock()
	defer am.mutex.Unlock()

	dispute, exists := am.disputes[disputeID]
	if !exists {
		return errors.New("dispute does not exist")
	}

	if dispute.Status != "Pending" {
		return errors.New("dispute already resolved")
	}

	dispute.Status = "Resolved"
	dispute.ResolutionTime = time.Now()
	dispute.Result = result
	return nil
}

// ListPendingDisputes lists all pending disputes.
func (am *ArbitrationMechanism) ListPendingDisputes() []*Dispute {
	am.mutex.Lock()
	defer am.mutex.Unlock()

	var pendingDisputes []*Dispute
	for _, dispute := range am.disputes {
		if dispute.Status == "Pending" {
			pendingDisputes = append(pendingDisputes, dispute)
		}
	}
	return pendingDisputes
}

// GetDispute retrieves a dispute by its ID.
func (am *ArbitrationMechanism) GetDispute(disputeID string) (*Dispute, error) {
	am.mutex.Lock()
	defer am.mutex.Unlock()

	dispute, exists := am.disputes[disputeID]
	if !exists {
		return nil, errors.New("dispute does not exist")
	}
	return dispute, nil
}

// generateDisputeID generates a unique ID for a dispute.
func generateDisputeID(challenger, defendant, timestamp string) string {
	hash := sha256.Sum256([]byte(challenger + defendant + timestamp))
	return hex.EncodeToString(hash[:])
}

// ValidateEvidence validates the provided evidence.
func (am *ArbitrationMechanism) ValidateEvidence(evidence []string) (bool, error) {
	// Implement validation logic here.
	// This could involve checking the format, authenticity, and relevance of the evidence.
	// For this example, we'll assume all evidence is valid.
	if len(evidence) == 0 {
		return false, errors.New("no evidence provided")
	}
	return true, nil
}

// SubmitEvidence allows for additional evidence to be submitted to an existing dispute.
func (am *ArbitrationMechanism) SubmitEvidence(disputeID string, evidence []string) error {
	am.mutex.Lock()
	defer am.mutex.Unlock()

	dispute, exists := am.disputes[disputeID]
	if !exists {
		return errors.New("dispute does not exist")
	}

	if dispute.Status != "Pending" {
		return errors.New("cannot submit evidence to a resolved dispute")
	}

	dispute.Evidence = append(dispute.Evidence, evidence...)
	return nil
}

// generateDisputeSummary generates a summary of the dispute for reporting purposes.
func (am *ArbitrationMechanism) GenerateDisputeSummary(disputeID string) (string, error) {
	am.mutex.Lock()
	defer am.mutex.Unlock()

	dispute, exists := am.disputes[disputeID]
	if !exists {
		return "", errors.New("dispute does not exist")
	}

	summary := fmt.Sprintf("Dispute ID: %s\nChallenger: %s\nDefendant: %s\nStatus: %s\nSubmitted At: %s\nResolution Time: %s\nResult: %s\nEvidence: %v\n",
		dispute.ID, dispute.Challenger, dispute.Defendant, dispute.Status, dispute.SubmittedAt, dispute.ResolutionTime, dispute.Result, dispute.Evidence)
	return summary, nil
}
