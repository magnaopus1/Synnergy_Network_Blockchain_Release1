package dynamic_incentives

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"os"
	"sync"

	"golang.org/x/crypto/argon2"
)

// Constants for dynamic incentive calculations
const (
	BaseDynamicReward  = 10.0
	MaxPerformanceScore = 100.0
)

// Reward structure
type Reward struct {
	DynamicIncentive float64 `json:"dynamic_incentive"`
}

// User structure
type User struct {
	ID             string  `json:"id"`
	Stake          float64 `json:"stake"`
	PerformanceScore float64 `json:"performance_score"`
}

// NetworkMetrics structure
type NetworkMetrics struct {
	PerformanceScore float64 `json:"performance_score"`
	TotalTransactionVolume float64 `json:"total_transaction_volume"`
}

// IncentiveSystem structure
type IncentiveSystem struct {
	mu              sync.Mutex
	Users           map[string]*User
	NetworkMetrics  NetworkMetrics
	TotalStake      float64
}

// NewIncentiveSystem initializes a new incentive system
func NewIncentiveSystem() *IncentiveSystem {
	return &IncentiveSystem{
		Users: make(map[string]*User),
	}
}

// AddUser adds a new user to the incentive system
func (is *IncentiveSystem) AddUser(id string, stake, performanceScore float64) {
	is.mu.Lock()
	defer is.mu.Unlock()
	is.Users[id] = &User{
		ID:              id,
		Stake:           stake,
		PerformanceScore: performanceScore,
	}
	is.TotalStake += stake
}

// CalculateDynamicIncentive calculates the dynamic incentive for a user
func (is *IncentiveSystem) CalculateDynamicIncentive(user *User) float64 {
	return BaseDynamicReward * (1 + user.PerformanceScore/MaxPerformanceScore)
}

// CalculateRewards calculates all types of rewards for a user
func (is *IncentiveSystem) CalculateRewards(userID string) (*Reward, error) {
	is.mu.Lock()
	defer is.mu.Unlock()
	user, exists := is.Users[userID]
	if !exists {
		return nil, errors.New("user not found")
	}

	dynamicIncentive := is.CalculateDynamicIncentive(user)

	return &Reward{
		DynamicIncentive: dynamicIncentive,
	}, nil
}

// Encrypt data using AES with Argon2 for key derivation
func Encrypt(data []byte, passphrase string) ([]byte, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}

	key := argon2.IDKey([]byte(passphrase), salt, 1, 64*1024, 4, 32)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return append(salt, ciphertext...), nil
}

// Decrypt data using AES with Argon2 for key derivation
func Decrypt(data []byte, passphrase string) ([]byte, error) {
	if len(data) < 16 {
		return nil, errors.New("ciphertext too short")
	}

	salt := data[:16]
	data = data[16:]

	key := argon2.IDKey([]byte(passphrase), salt, 1, 64*1024, 4, 32)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

// SerializeReward serializes the reward into a JSON string
func SerializeReward(reward *Reward) (string, error) {
	bytes, err := json.Marshal(reward)
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}

// DeserializeReward deserializes the reward from a JSON string
func DeserializeReward(data string) (*Reward, error) {
	var reward Reward
	err := json.Unmarshal([]byte(data), &reward)
	if err != nil {
		return nil, err
	}
	return &reward, nil
}

// SaveEncryptedReward saves the encrypted reward to a file
func SaveEncryptedReward(reward *Reward, passphrase, filepath string) error {
	data, err := SerializeReward(reward)
	if err != nil {
		return err
	}
	encryptedData, err := Encrypt([]byte(data), passphrase)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath, encryptedData, 0644)
}

// LoadEncryptedReward loads and decrypts the reward from a file
func LoadEncryptedReward(passphrase, filepath string) (*Reward, error) {
	encryptedData, err := os.ReadFile(filepath)
	if err != nil {
		return nil, err
	}
	data, err := Decrypt(encryptedData, passphrase)
	if err != nil {
		return nil, err
	}
	return DeserializeReward(string(data))
}

// UpdateNetworkMetrics updates the network performance metrics
func (is *IncentiveSystem) UpdateNetworkMetrics(performanceScore, totalTransactionVolume float64) {
	is.mu.Lock()
	defer is.mu.Unlock()
	is.NetworkMetrics.PerformanceScore = performanceScore
	is.NetworkMetrics.TotalTransactionVolume = totalTransactionVolume
}

// AdjustUserPerformanceScore adjusts the performance score of a user
func (is *IncentiveSystem) AdjustUserPerformanceScore(userID string, adjustment float64) error {
	is.mu.Lock()
	defer is.mu.Unlock()
	user, exists := is.Users[userID]
	if !exists {
		return errors.New("user not found")
	}
	user.PerformanceScore += adjustment
	if user.PerformanceScore > MaxPerformanceScore {
		user.PerformanceScore = MaxPerformanceScore
	} else if user.PerformanceScore < 0 {
		user.PerformanceScore = 0
	}
	return nil
}

// ListUsers returns a list of all users in the incentive system
func (is *IncentiveSystem) ListUsers() []*User {
	is.mu.Lock()
	defer is.mu.Unlock()
	users := []*User{}
	for _, user := range is.Users {
		users = append(users, user)
	}
	return users
}
