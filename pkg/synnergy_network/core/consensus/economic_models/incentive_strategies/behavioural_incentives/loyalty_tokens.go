package behavioural_incentives

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

// Constants for loyalty token calculations
const (
	BaseLoyaltyReward = 5.0
	MaxLoyaltyScore   = 100.0
)

// LoyaltyToken structure
type LoyaltyToken struct {
	ID     string  `json:"id"`
	Amount float64 `json:"amount"`
}

// User structure
type User struct {
	ID             string  `json:"id"`
	ContributionScore float64 `json:"contribution_score"`
	Stake          float64 `json:"stake"`
	LoyaltyScore   float64 `json:"loyalty_score"`
	LoyaltyTokens  []LoyaltyToken
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
func (is *IncentiveSystem) AddUser(id string, contributionScore, stake, loyaltyScore float64) {
	is.mu.Lock()
	defer is.mu.Unlock()
	is.Users[id] = &User{
		ID:              id,
		ContributionScore: contributionScore,
		Stake:           stake,
		LoyaltyScore:    loyaltyScore,
		LoyaltyTokens:   []LoyaltyToken{},
	}
	is.TotalStake += stake
}

// CalculateLoyaltyReward calculates the loyalty reward for a user
func (is *IncentiveSystem) CalculateLoyaltyReward(user *User) float64 {
	return BaseLoyaltyReward * (1 + user.LoyaltyScore/MaxLoyaltyScore)
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
	loyaltyReward := is.CalculateLoyaltyReward(user)

	return &Reward{
		BehavioralIncentive: behavioralIncentive,
		DynamicIncentive:    dynamicIncentive,
		TokenReward:         tokenReward,
		LoyaltyReward:       loyaltyReward,
	}, nil
}

// GenerateLoyaltyToken generates a loyalty token for a user
func (is *IncentiveSystem) GenerateLoyaltyToken(userID string, amount float64) error {
	is.mu.Lock()
	defer is.mu.Unlock()
	user, exists := is.Users[userID]
	if !exists {
		return errors.New("user not found")
	}

	tokenID, err := generateTokenID()
	if err != nil {
		return err
	}

	loyaltyToken := LoyaltyToken{
		ID:     tokenID,
		Amount: amount,
	}

	user.LoyaltyTokens = append(user.LoyaltyTokens, loyaltyToken)
	return nil
}

// generateTokenID generates a unique token ID
func generateTokenID() (string, error) {
	nBig, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		return "", err
	}
	return nBig.String(), nil
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
