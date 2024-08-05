package energy_efficiency

import (
	"encoding/json"
	"errors"
	"log"
	"math/rand"
	"sync"
	"time"
)

// CarbonCredit represents a carbon credit in the marketplace
type CarbonCredit struct {
	ID          string
	Owner       string
	Amount      int // amount of CO2 offset in kilograms
	IssuedDate  time.Time
	ExpiryDate  time.Time
}

// CarbonOffsetProgram manages carbon offset initiatives and carbon credits
type CarbonOffsetProgram struct {
	mu             sync.Mutex
	credits        map[string]*CarbonCredit
	emissions      map[string]int // emissions tracked by user ID
	transactions   []Transaction
	verification   VerificationService
}

// Transaction represents a transaction of carbon credits
type Transaction struct {
	ID            string
	From          string
	To            string
	Amount        int
	Timestamp     time.Time
}

// VerificationService provides methods for verifying carbon credits
type VerificationService interface {
	Verify(credit *CarbonCredit) bool
}

// DefaultVerificationService is a basic implementation of VerificationService
type DefaultVerificationService struct {}

// Verify verifies a carbon credit
func (dvs *DefaultVerificationService) Verify(credit *CarbonCredit) bool {
	return credit.ExpiryDate.After(time.Now())
}

// NewCarbonOffsetProgram initializes a new CarbonOffsetProgram
func NewCarbonOffsetProgram() *CarbonOffsetProgram {
	return &CarbonOffsetProgram{
		credits:      make(map[string]*CarbonCredit),
		emissions:    make(map[string]int),
		transactions: []Transaction{},
		verification: &DefaultVerificationService{},
	}
}

// IssueCredit issues a new carbon credit to a user
func (cop *CarbonOffsetProgram) IssueCredit(owner string, amount int, validityYears int) (*CarbonCredit, error) {
	cop.mu.Lock()
	defer cop.mu.Unlock()

	id := generateID()
	credit := &CarbonCredit{
		ID:          id,
		Owner:       owner,
		Amount:      amount,
		IssuedDate:  time.Now(),
		ExpiryDate:  time.Now().AddDate(validityYears, 0, 0),
	}

	cop.credits[id] = credit
	return credit, nil
}

// TransferCredit transfers a carbon credit from one user to another
func (cop *CarbonOffsetProgram) TransferCredit(creditID, from, to string) error {
	cop.mu.Lock()
	defer cop.mu.Unlock()

	credit, exists := cop.credits[creditID]
	if !exists {
		return errors.New("carbon credit not found")
	}

	if credit.Owner != from {
		return errors.New("credit not owned by the specified user")
	}

	credit.Owner = to

	transaction := Transaction{
		ID:        generateID(),
		From:      from,
		To:        to,
		Amount:    credit.Amount,
		Timestamp: time.Now(),
	}
	cop.transactions = append(cop.transactions, transaction)
	return nil
}

// TrackEmissions tracks carbon emissions for a user
func (cop *CarbonOffsetProgram) TrackEmissions(userID string, amount int) {
	cop.mu.Lock()
	defer cop.mu.Unlock()

	cop.emissions[userID] += amount
}

// OffsetEmissions offsets emissions for a user using their carbon credits
func (cop *CarbonOffsetProgram) OffsetEmissions(userID string, amount int) error {
	cop.mu.Lock()
	defer cop.mu.Unlock()

	var totalOffset int
	for _, credit := range cop.credits {
		if credit.Owner == userID && cop.verification.Verify(credit) {
			if credit.Amount >= amount {
				credit.Amount -= amount
				totalOffset += amount
				break
			} else {
				amount -= credit.Amount
				totalOffset += credit.Amount
				credit.Amount = 0
			}
		}
	}

	if totalOffset < amount {
		return errors.New("not enough carbon credits to offset emissions")
	}

	cop.emissions[userID] -= totalOffset
	return nil
}

// GetCarbonCredits returns the carbon credits owned by a user
func (cop *CarbonOffsetProgram) GetCarbonCredits(userID string) ([]*CarbonCredit, error) {
	cop.mu.Lock()
	defer cop.mu.Unlock()

	var credits []*CarbonCredit
	for _, credit := range cop.credits {
		if credit.Owner == userID {
			credits = append(credits, credit)
		}
	}
	return credits, nil
}

// GetEmissions returns the tracked emissions for a user
func (cop *CarbonOffsetProgram) GetEmissions(userID string) (int, error) {
	cop.mu.Lock()
	defer cop.mu.Unlock()

	emissions, exists := cop.emissions[userID]
	if !exists {
		return 0, errors.New("no emissions tracked for the user")
	}
	return emissions, nil
}

// GetTransactions returns the transaction history for a user
func (cop *CarbonOffsetProgram) GetTransactions(userID string) ([]Transaction, error) {
	cop.mu.Lock()
	defer cop.mu.Unlock()

	var transactions []Transaction
	for _, transaction := range cop.transactions {
		if transaction.From == userID || transaction.To == userID {
			transactions = append(transactions, transaction)
		}
	}
	return transactions, nil
}

// BackupData backs up the current state of the carbon offset program
func (cop *CarbonOffsetProgram) BackupData() (string, error) {
	cop.mu.Lock()
	defer cop.mu.Unlock()

	data := struct {
		Credits      map[string]*CarbonCredit
		Emissions    map[string]int
		Transactions []Transaction
	}{
		Credits:      cop.credits,
		Emissions:    cop.emissions,
		Transactions: cop.transactions,
	}

	bytes, err := json.Marshal(data)
	if err != nil {
		return "", err
	}

	return string(bytes), nil
}

// RestoreData restores the state of the carbon offset program from a backup
func (cop *CarbonOffsetProgram) RestoreData(data string) error {
	cop.mu.Lock()
	defer cop.mu.Unlock()

	var backup struct {
		Credits      map[string]*CarbonCredit
		Emissions    map[string]int
		Transactions []Transaction
	}

	err := json.Unmarshal([]byte(data), &backup)
	if err != nil {
		return err
	}

	cop.credits = backup.Credits
	cop.emissions = backup.Emissions
	cop.transactions = backup.Transactions
	return nil
}

// generateID generates a unique ID
func generateID() string {
	rand.Seed(time.Now().UnixNano())
	return fmt.Sprintf("%d", rand.Int())
}

