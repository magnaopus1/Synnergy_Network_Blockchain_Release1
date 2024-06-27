package behavioural_incentives

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"sync"
)

// Constants for incentive calculations
const (
	BaseReward   = 10.0
	MaxContributionScore = 100.0
)

// Reward structure
type Reward struct {
	BehavioralIncentive float64 `json:"behavioral_incentive"`
	DynamicIncentive    float64 `json:"dynamic_incentive"`
	TokenReward         float64 `json:"token_reward"`
}

// User structure
type User struct {
	ID               string  `json:"id"`
	ContributionScore float64 `json:"contribution_score"`
	Stake            float64 `json:"stake"`
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
func (is *IncentiveSystem) AddUser(id string, contributionScore, stake float64) {
	is.mu.Lock()
	defer is.mu.Unlock()
	is.Users[id] = &User{
		ID:               id,
		ContributionScore: contributionScore,
		Stake:            stake,
	}
	is.TotalStake += stake
}

// CalculateBehavioralIncentive calculates the behavioral incentive for a user
func (is *IncentiveSystem) CalculateBehavioralIncentive(user *User) float64 {
	return BaseReward * (1 + user.ContributionScore/MaxContributionScore)
}

// CalculateDynamicIncentive calculates the dynamic incentive for a user
func (is *IncentiveSystem) CalculateDynamicIncentive(user *User) float64 {
	return BaseReward * (1 + is.NetworkMetrics.PerformanceScore/MaxContributionScore)
}

// CalculateTokenReward calculates the token reward for a user
func (is *IncentiveSystem) CalculateTokenReward(user *User) float64 {
	return (user.Stake / is.TotalStake) * BaseReward
}

// CalculateRewards calculates all types of rewards for a user
func (is *IncentiveSystem) CalculateRewards(userID string) (*Reward, error) {
	is.mu.Lock()
	defer is.mu.Unlock()
	user, exists := is.Users[userID]
	if !exists {
		return nil, errors.New("user not found")
	}

	behavioralIncentive := is.CalculateBehavioralIncentive(user)
	dynamicIncentive := is.CalculateDynamicIncentive(user)
	tokenReward := is.CalculateTokenReward(user)

	return &Reward{
		BehavioralIncentive: behavioralIncentive,
		DynamicIncentive:    dynamicIncentive,
		TokenReward:         tokenReward,
	}, nil
}

// Encrypt data using AES
func Encrypt(data []byte, passphrase string) ([]byte, error) {
	block, _ := aes.NewCipher([]byte(passphrase))
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, data, nil), nil
}

// Decrypt data using AES
func Decrypt(data []byte, passphrase string) ([]byte, error) {
	block, err := aes.NewCipher([]byte(passphrase))
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
