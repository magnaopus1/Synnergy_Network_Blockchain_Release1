package challenge

import (
	"errors"
	"time"
	"sync"
)

// IncentiveModel represents the mechanism for managing incentives in the optimistic rollup system.
type IncentiveModel struct {
	challenges map[string]*ChallengeIncentive
	mutex      sync.Mutex
}

// ChallengeIncentive represents a single incentive tied to a challenge.
type ChallengeIncentive struct {
	ChallengeID      string
	Challenger       string
	Reward           float64
	Penalty          float64
	SubmittedAt      time.Time
	ResolvedAt       time.Time
	Status           string
}

// NewIncentiveModel initializes a new IncentiveModel system.
func NewIncentiveModel() *IncentiveModel {
	return &IncentiveModel{
		challenges: make(map[string]*ChallengeIncentive),
	}
}

// SubmitIncentive allows a user to submit a new challenge incentive.
func (im *IncentiveModel) SubmitIncentive(challengeID, challenger string, reward, penalty float64) (string, error) {
	im.mutex.Lock()
	defer im.mutex.Unlock()

	if _, exists := im.challenges[challengeID]; exists {
		return "", errors.New("incentive for this challenge already exists")
	}

	incentive := &ChallengeIncentive{
		ChallengeID: challengeID,
		Challenger:  challenger,
		Reward:      reward,
		Penalty:     penalty,
		SubmittedAt: time.Now(),
		Status:      "Pending",
	}
	im.challenges[challengeID] = incentive
	return challengeID, nil
}

// ResolveIncentive resolves an incentive with the given result.
func (im *IncentiveModel) ResolveIncentive(challengeID string, success bool) error {
	im.mutex.Lock()
	defer im.mutex.Unlock()

	incentive, exists := im.challenges[challengeID]
	if !exists {
		return errors.New("incentive does not exist")
	}

	if incentive.Status != "Pending" {
		return errors.New("incentive already resolved")
	}

	incentive.Status = "Resolved"
	incentive.ResolvedAt = time.Now()
	if success {
		incentive.Reward = incentive.Reward
	} else {
		incentive.Penalty = incentive.Penalty
	}
	return nil
}

// ListPendingIncentives lists all pending incentives.
func (im *IncentiveModel) ListPendingIncentives() []*ChallengeIncentive {
	im.mutex.Lock()
	defer im.mutex.Unlock()

	var pendingIncentives []*ChallengeIncentive
	for _, incentive := range im.challenges {
		if incentive.Status == "Pending" {
			pendingIncentives = append(pendingIncentives, incentive)
		}
	}
	return pendingIncentives
}

// GetIncentive retrieves an incentive by its challenge ID.
func (im *IncentiveModel) GetIncentive(challengeID string) (*ChallengeIncentive, error) {
	im.mutex.Lock()
	defer im.mutex.Unlock()

	incentive, exists := im.challenges[challengeID]
	if !exists {
		return nil, errors.New("incentive does not exist")
	}
	return incentive, nil
}

// AutomateIncentiveDistribution automatically distributes incentives based on predefined rules.
func (im *IncentiveModel) AutomateIncentiveDistribution() {
	for _, incentive := range im.ListPendingIncentives() {
		// Define the automated distribution logic here.
		// For example, this could involve evaluating the challenge result and distributing rewards or penalties.
		// This is a placeholder example.
		success := true // Placeholder for actual logic
		if err := im.ResolveIncentive(incentive.ChallengeID, success); err != nil {
			fmt.Println("Error resolving incentive:", err)
		}
	}
}

// MonitorIncentiveActivity monitors the activity of incentives and takes action if necessary.
func (im *IncentiveModel) MonitorIncentiveActivity() {
	for _, incentive := range im.ListPendingIncentives() {
		// Define the monitoring logic here.
		// This could involve checking the status of incentives and taking action if necessary.
		// This is a placeholder example.
		if time.Since(incentive.SubmittedAt) > 24*time.Hour {
			fmt.Println("Incentive pending for over 24 hours:", incentive.ChallengeID)
		}
	}
}
