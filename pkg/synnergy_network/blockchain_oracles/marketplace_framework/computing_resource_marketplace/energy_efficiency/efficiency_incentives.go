package energy_efficiency

import (
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"
)

// EfficiencyIncentive represents an incentive for efficient energy usage
type EfficiencyIncentive struct {
	ID           string
	Description  string
	Reward       int    // Reward points or tokens
	IssuedDate   time.Time
	ExpiryDate   time.Time
	IsActive     bool
	Participant  string
}

// EfficiencyIncentiveProgram manages efficiency incentives
type EfficiencyIncentiveProgram struct {
	mu         sync.Mutex
	incentives map[string]*EfficiencyIncentive
	participants map[string]int // Tracks rewards earned by participants
	transactions []Transaction
}

// Transaction represents a transaction of efficiency incentives
type Transaction struct {
	ID          string
	Participant string
	Amount      int
	Timestamp   time.Time
}

// NewEfficiencyIncentiveProgram initializes a new EfficiencyIncentiveProgram
func NewEfficiencyIncentiveProgram() *EfficiencyIncentiveProgram {
	return &EfficiencyIncentiveProgram{
		incentives:   make(map[string]*EfficiencyIncentive),
		participants: make(map[string]int),
		transactions: []Transaction{},
	}
}

// CreateIncentive creates a new efficiency incentive
func (eip *EfficiencyIncentiveProgram) CreateIncentive(description string, reward int, validityDays int, participant string) (*EfficiencyIncentive, error) {
	eip.mu.Lock()
	defer eip.mu.Unlock()

	id := generateID()
	incentive := &EfficiencyIncentive{
		ID:          id,
		Description: description,
		Reward:      reward,
		IssuedDate:  time.Now(),
		ExpiryDate:  time.Now().AddDate(0, 0, validityDays),
		IsActive:    true,
		Participant: participant,
	}

	eip.incentives[id] = incentive
	return incentive, nil
}

// RedeemIncentive redeems an efficiency incentive
func (eip *EfficiencyIncentiveProgram) RedeemIncentive(incentiveID, participant string) error {
	eip.mu.Lock()
	defer eip.mu.Unlock()

	incentive, exists := eip.incentives[incentiveID]
	if !exists {
		return errors.New("incentive not found")
	}

	if !incentive.IsActive {
		return errors.New("incentive is not active")
	}

	if incentive.Participant != participant {
		return errors.New("incentive not owned by the specified participant")
	}

	if incentive.ExpiryDate.Before(time.Now()) {
		incentive.IsActive = false
		return errors.New("incentive has expired")
	}

	incentive.IsActive = false
	eip.participants[participant] += incentiveReward

	transaction := Transaction{
		ID:          generateID(),
		Participant: participant,
		Amount:      incentive.Reward,
		Timestamp:   time.Now(),
	}
	eip.transactions = append(eip.transactions, transaction)
	return nil
}

// GetActiveIncentives returns the active incentives for a participant
func (eip *EfficiencyIncentiveProgram) GetActiveIncentives(participant string) ([]*EfficiencyIncentive, error) {
	eip.mu.Lock()
	defer eip.mu.Unlock()

	var activeIncentives []*EfficiencyIncentive
	for _, incentive := range eip.incentives {
		if incentive.Participant == participant && incentive.IsActive {
			activeIncentives = append(activeIncentives, incentive)
		}
	}
	return activeIncentives, nil
}

// GetParticipantRewards returns the total rewards earned by a participant
func (eip *EfficiencyIncentiveProgram) GetParticipantRewards(participant string) (int, error) {
	eip.mu.Lock()
	defer eip.mu.Unlock()

	rewards, exists := eip.participants[participant]
	if !exists {
		return 0, errors.New("no rewards found for the participant")
	}
	return rewards, nil
}

// GetTransactions returns the transaction history for a participant
func (eip *EfficiencyIncentiveProgram) GetTransactions(participant string) ([]Transaction, error) {
	eip.mu.Lock()
	defer eip.mu.Unlock()

	var transactions []Transaction
	for _, transaction := range eip.transactions {
		if transaction.Participant == participant {
			transactions = append(transactions, transaction)
		}
	}
	return transactions, nil
}

// BackupData backs up the current state of the efficiency incentive program
func (eip *EfficiencyIncentiveProgram) BackupData() (string, error) {
	eip.mu.Lock()
	defer eip.mu.Unlock()

	data := struct {
		Incentives   map[string]*EfficiencyIncentive
		Participants map[string]int
		Transactions []Transaction
	}{
		Incentives:   eip.incentives,
		Participants: eip.participants,
		Transactions: eip.transactions,
	}

	bytes, err := json.Marshal(data)
	if err != nil {
		return "", err
	}

	return string(bytes), nil
}

// RestoreData restores the state of the efficiency incentive program from a backup
func (eip *EfficiencyIncentiveProgram) RestoreData(data string) error {
	eip.mu.Lock()
	defer eip.mu.Unlock()

	var backup struct {
		Incentives   map[string]*EfficiencyIncentive
		Participants map[string]int
		Transactions []Transaction
	}

	err := json.Unmarshal([]byte(data), &backup)
	if err != nil {
		return err
	}

	eip.incentives = backup.Incentives
	eip.participants = backup.Participants
	eip.transactions = backup.Transactions
	return nil
}

// generateID generates a unique ID
func generateID() string {
	rand.Seed(time.Now().UnixNano())
	return fmt.Sprintf("%d", rand.Int())
}
