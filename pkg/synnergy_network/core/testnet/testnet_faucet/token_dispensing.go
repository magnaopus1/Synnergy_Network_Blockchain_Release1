package testnet_faucet

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sync"
	"time"
	"math/big"
	"golang.org/x/crypto/scrypt"
)

// Constants for the faucet service
const (
	MaxRequestsPerHour = 5
	SYNNAmount         = 100
)

type FaucetService struct {
	mu            sync.Mutex
	requests      map[string][]time.Time
	userBalances  map[string]int
	dispenseLog   []DispenseRecord
}

type DispenseRecord struct {
	Address   string
	Amount    int
	Timestamp time.Time
}

// Initialize a new FaucetService
func NewFaucetService() *FaucetService {
	return &FaucetService{
		requests:     make(map[string][]time.Time),
		userBalances: make(map[string]int),
		dispenseLog:  []DispenseRecord{},
	}
}

// Validate the request rate to prevent abuse
func (fs *FaucetService) validateRequestRate(user string) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	requestTimes, exists := fs.requests[user]
	if !exists {
		fs.requests[user] = []time.Time{time.Now()}
		return nil
	}

	// Remove old requests
	oneHourAgo := time.Now().Add(-1 * time.Hour)
	newRequestTimes := []time.Time{}
	for _, t := range requestTimes {
		if t.After(oneHourAgo) {
			newRequestTimes = append(newRequestTimes, t)
		}
	}

	if len(newRequestTimes) >= MaxRequestsPerHour {
		return errors.New("request limit reached")
	}

	fs.requests[user] = append(newRequestTimes, time.Now())
	return nil
}

// Authenticate the user before dispensing tokens
func (fs *FaucetService) authenticateUser(user string, password string) error {
	hashedPassword, err := hashPassword(password)
	if err != nil {
		return err
	}

	// For demonstration, we assume the existence of a user database with stored hashed passwords
	// Here we simply check the hashed password matches a predetermined value
	storedHashedPassword := "hashed_password_example"

	if hashedPassword != storedHashedPassword {
		return errors.New("authentication failed")
	}
	return nil
}

// Dispense SYNN tokens to the user
func (fs *FaucetService) dispenseTokens(user string) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	err := fs.validateRequestRate(user)
	if err != nil {
		return err
	}

	fs.userBalances[user] += SYNNAmount
	fs.dispenseLog = append(fs.dispenseLog, DispenseRecord{
		Address:   user,
		Amount:    SYNNAmount,
		Timestamp: time.Now(),
	})

	return nil
}

// Generate a random string to be used as a user password salt
func generateRandomSalt() (string, error) {
	salt := make([]byte, 16)
	_, err := rand.Read(salt)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(salt), nil
}

// Hash the user password with Scrypt
func hashPassword(password string) (string, error) {
	salt, err := generateRandomSalt()
	if err != nil {
		return "", err
	}

	hashedPassword, err := scrypt.Key([]byte(password), []byte(salt), 16384, 8, 1, 32)
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(hashedPassword), nil
}

// Retrieve the balance of the user
func (fs *FaucetService) getBalance(user string) int {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	return fs.userBalances[user]
}

// Generate a unique user address
func generateUserAddress() (string, error) {
	address := make([]byte, 20)
	_, err := rand.Read(address)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(address), nil
}

// Create a new user with a unique address and initial balance
func (fs *FaucetService) createUser() (string, error) {
	address, err := generateUserAddress()
	if err != nil {
		return "", err
	}

	fs.mu.Lock()
	defer fs.mu.Unlock()

	fs.userBalances[address] = 0
	fs.requests[address] = []time.Time{}

	return address, nil
}

// Retrieve the dispensing logs
func (fs *FaucetService) getDispenseLog() []DispenseRecord {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	return fs.dispenseLog
}

// Generate a random amount of SYNN to be dispensed (for dynamic dispensing scenarios)
func generateRandomSYNNAmount() (int, error) {
	max := big.NewInt(200)
	amount, err := rand.Int(rand.Reader, max)
	if err != nil {
		return 0, err
	}
	return int(amount.Int64()) + 50, nil
}

// Example function to demonstrate dynamic dispensing
func (fs *FaucetService) dynamicDispenseTokens(user string) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	err := fs.validateRequestRate(user)
	if err != nil {
		return err
	}

	amount, err := generateRandomSYNNAmount()
	if err != nil {
		return err
	}

	fs.userBalances[user] += amount
	fs.dispenseLog = append(fs.dispenseLog, DispenseRecord{
		Address:   user,
		Amount:    amount,
		Timestamp: time.Now(),
	})

	return nil
}
