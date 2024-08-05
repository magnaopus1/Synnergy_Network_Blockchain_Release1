package challenge

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sync"
	"time"
)

// ChallengeSubmission represents the mechanism for submitting challenges in the optimistic rollup system.
type ChallengeSubmission struct {
	challenges map[string]*Challenge
	mutex      sync.Mutex
}

// Challenge represents a single challenge in the rollup.
type Challenge struct {
	ID             string
	Challenger     string
	Defendant      string
	Status         string
	SubmittedAt    time.Time
	ResolutionTime time.Time
	Result         string
	Evidence       []string
}

// NewChallengeSubmission initializes a new ChallengeSubmission system.
func NewChallengeSubmission() *ChallengeSubmission {
	return &ChallengeSubmission{
		challenges: make(map[string]*Challenge),
	}
}

// SubmitChallenge allows a user to submit a new challenge.
func (cs *ChallengeSubmission) SubmitChallenge(challenger, defendant string, evidence []string) (string, error) {
	cs.mutex.Lock()
	defer cs.mutex.Unlock()

	challengeID := generateChallengeID(challenger, defendant, time.Now().String())
	if _, exists := cs.challenges[challengeID]; exists {
		return "", errors.New("challenge already exists")
	}

	challenge := &Challenge{
		ID:          challengeID,
		Challenger:  challenger,
		Defendant:   defendant,
		Status:      "Pending",
		SubmittedAt: time.Now(),
		Evidence:    evidence,
	}
	cs.challenges[challengeID] = challenge
	return challengeID, nil
}

// ResolveChallenge resolves a challenge with the given result.
func (cs *ChallengeSubmission) ResolveChallenge(challengeID, result string) error {
	cs.mutex.Lock()
	defer cs.mutex.Unlock()

	challenge, exists := cs.challenges[challengeID]
	if !exists {
		return errors.New("challenge does not exist")
	}

	if challenge.Status != "Pending" {
		return errors.New("challenge already resolved")
	}

	challenge.Status = "Resolved"
	challenge.ResolutionTime = time.Now()
	challenge.Result = result
	return nil
}

// ListPendingChallenges lists all pending challenges.
func (cs *ChallengeSubmission) ListPendingChallenges() []*Challenge {
	cs.mutex.Lock()
	defer cs.mutex.Unlock()

	var pendingChallenges []*Challenge
	for _, challenge := range cs.challenges {
		if challenge.Status == "Pending" {
			pendingChallenges = append(pendingChallenges, challenge)
		}
	}
	return pendingChallenges
}

// GetChallenge retrieves a challenge by its ID.
func (cs *ChallengeSubmission) GetChallenge(challengeID string) (*Challenge, error) {
	cs.mutex.Lock()
	defer cs.mutex.Unlock()

	challenge, exists := cs.challenges[challengeID]
	if !exists {
		return nil, errors.New("challenge does not exist")
	}
	return challenge, nil
}

// generateChallengeID generates a unique ID for a challenge.
func generateChallengeID(challenger, defendant, timestamp string) string {
	hash := sha256.Sum256([]byte(challenger + defendant + timestamp))
	return hex.EncodeToString(hash[:])
}

// ValidateChallengeEvidence validates the provided evidence.
func (cs *ChallengeSubmission) ValidateChallengeEvidence(evidence []string) (bool, error) {
	// Implement validation logic here.
	// This could involve checking the format, authenticity, and relevance of the evidence.
	// For this example, we'll assume all evidence is valid.
	if len(evidence) == 0 {
		return false, errors.New("no evidence provided")
	}
	return true, nil
}

// SubmitAdditionalEvidence allows for additional evidence to be submitted to an existing challenge.
func (cs *ChallengeSubmission) SubmitAdditionalEvidence(challengeID string, evidence []string) error {
	cs.mutex.Lock()
	defer cs.mutex.Unlock()

	challenge, exists := cs.challenges[challengeID]
	if !exists {
		return errors.New("challenge does not exist")
	}

	if challenge.Status != "Pending" {
		return errors.New("cannot submit evidence to a resolved challenge")
	}

	challenge.Evidence = append(challenge.Evidence, evidence...)
	return nil
}

// generateChallengeSummary generates a summary of the challenge for reporting purposes.
func (cs *ChallengeSubmission) GenerateChallengeSummary(challengeID string) (string, error) {
	cs.mutex.Lock()
	defer cs.mutex.Unlock()

	challenge, exists := cs.challenges[challengeID]
	if !exists {
		return "", errors.New("challenge does not exist")
	}

	summary := fmt.Sprintf("Challenge ID: %s\nChallenger: %s\nDefendant: %s\nStatus: %s\nSubmitted At: %s\nResolution Time: %s\nResult: %s\nEvidence: %v\n",
		challenge.ID, challenge.Challenger, challenge.Defendant, challenge.Status, challenge.SubmittedAt, challenge.ResolutionTime, challenge.Result, challenge.Evidence)
	return summary, nil
}
