package staking_launchpad

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"golang.org/x/crypto/scrypt"
)

// StakingPool represents a staking pool with its parameters and participants.
type StakingPool struct {
	ID           string            `json:"id"`
	Name         string            `json:"name"`
	OwnerID      string            `json:"owner_id"`
	TotalStaked  float64           `json:"total_staked"`
	Participants map[string]float64 `json:"participants"`
	CreatedAt    time.Time         `json:"created_at"`
	UpdatedAt    time.Time         `json:"updated_at"`
	RewardRate   float64           `json:"reward_rate"`
	LockUpPeriod time.Duration     `json:"lock_up_period"`
}

// StakingPoolManager manages multiple staking pools.
type StakingPoolManager struct {
	pools map[string]*StakingPool
	lock  sync.Mutex
}

// NewStakingPoolManager creates a new instance of StakingPoolManager.
func NewStakingPoolManager() *StakingPoolManager {
	return &StakingPoolManager{
		pools: make(map[string]*StakingPool),
	}
}

// CreatePool creates a new staking pool.
func (manager *StakingPoolManager) CreatePool(name, ownerID string, rewardRate float64, lockUpPeriod time.Duration) (*StakingPool, error) {
	manager.lock.Lock()
	defer manager.lock.Unlock()

	id, err := generateUniqueID(name + ownerID)
	if err != nil {
		return nil, err
	}

	pool := &StakingPool{
		ID:           id,
		Name:         name,
		OwnerID:      ownerID,
		TotalStaked:  0,
		Participants: make(map[string]float64),
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
		RewardRate:   rewardRate,
		LockUpPeriod: lockUpPeriod,
	}

	manager.pools[id] = pool
	return pool, nil
}

// Stake allows a user to stake an amount in a pool.
func (manager *StakingPoolManager) Stake(poolID, userID string, amount float64) error {
	manager.lock.Lock()
	defer manager.lock.Unlock()

	pool, exists := manager.pools[poolID]
	if !exists {
		return errors.New("pool not found")
	}

	pool.TotalStaked += amount
	if _, ok := pool.Participants[userID]; !ok {
		pool.Participants[userID] = 0
	}
	pool.Participants[userID] += amount
	pool.UpdatedAt = time.Now()

	return nil
}

// Unstake allows a user to unstake an amount from a pool.
func (manager *StakingPoolManager) Unstake(poolID, userID string, amount float64) error {
	manager.lock.Lock()
	defer manager.lock.Unlock()

	pool, exists := manager.pools[poolID]
	if !exists {
		return errors.New("pool not found")
	}

	userStake, ok := pool.Participants[userID]
	if !ok || userStake < amount {
		return errors.New("insufficient staked amount")
	}

	pool.TotalStaked -= amount
	pool.Participants[userID] -= amount
	if pool.Participants[userID] == 0 {
		delete(pool.Participants, userID)
	}
	pool.UpdatedAt = time.Now()

	return nil
}

// DistributeRewards distributes rewards to all participants based on their stake.
func (manager *StakingPoolManager) DistributeRewards(poolID string) error {
	manager.lock.Lock()
	defer manager.lock.Unlock()

	pool, exists := manager.pools[poolID]
	if !exists {
		return errors.New("pool not found")
	}

	totalRewards := pool.TotalStaked * pool.RewardRate
	for userID, stake := range pool.Participants {
		reward := (stake / pool.TotalStaked) * totalRewards
		pool.Participants[userID] += reward
	}
	pool.UpdatedAt = time.Now()

	return nil
}

// generateUniqueID generates a unique ID using scrypt.
func generateUniqueID(input string) (string, error) {
	salt, err := generateSalt()
	if err != nil {
		return "", err
	}
	dk, err := scrypt.Key([]byte(input), salt, 32768, 8, 1, 32)
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256(dk)
	return hex.EncodeToString(hash[:]), nil
}

// generateSalt generates a salt for hashing.
func generateSalt() ([]byte, error) {
	salt := make([]byte, 16)
	_, err := rand.Read(salt)
	return salt, err
}

// Encryption and decryption utilities for additional security.
func encrypt(data []byte, passphrase string) ([]byte, error) {
	block, _ := aes.NewCipher([]byte(createHash(passphrase)))
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return ciphertext, nil
}

func decrypt(data []byte, passphrase string) ([]byte, error) {
	key := []byte(createHash(passphrase))
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

func createHash(key string) string {
	hash := sha256.New()
	hash.Write([]byte(key))
	return hex.EncodeToString(hash.Sum(nil))
}

// JSON utility functions.
func toJSON(v interface{}) ([]byte, error) {
	return json.Marshal(v)
}

func fromJSON(data []byte, v interface{}) error {
	return json.Unmarshal(data, v)
}

// Example CLI and SDK integration points.

func (manager *StakingPoolManager) CLIAddPool(name, ownerID string, rewardRate float64, lockUpPeriod time.Duration) {
	pool, err := manager.CreatePool(name, ownerID, rewardRate, lockUpPeriod)
	if err != nil {
		fmt.Println("Error creating pool:", err)
		return
	}
	fmt.Println("Pool created successfully:", pool)
}

func (manager *StakingPoolManager) CLIStake(poolID, userID string, amount float64) {
	err := manager.Stake(poolID, userID, amount)
	if err != nil {
		fmt.Println("Error staking:", err)
		return
	}
	fmt.Println("Staked successfully")
}

func (manager *StakingPoolManager) CLIUnstake(poolID, userID string, amount float64) {
	err := manager.Unstake(poolID, userID, amount)
	if err != nil {
		fmt.Println("Error unstaking:", err)
		return
	}
	fmt.Println("Unstaked successfully")
}

func (manager *StakingPoolManager) CLIDistributeRewards(poolID string) {
	err := manager.DistributeRewards(poolID)
	if err != nil {
		fmt.Println("Error distributing rewards:", err)
		return
	}
	fmt.Println("Rewards distributed successfully")
}

func (manager *StakingPoolManager) SDKAddPool(name, ownerID string, rewardRate float64, lockUpPeriod time.Duration) (*StakingPool, error) {
	return manager.CreatePool(name, ownerID, rewardRate, lockUpPeriod)
}

func (manager *StakingPoolManager) SDKStake(poolID, userID string, amount float64) error {
	return manager.Stake(poolID, userID, amount)
}

func (manager *StakingPoolManager) SDKUnstake(poolID, userID string, amount float64) error {
	return manager.Unstake(poolID, userID, amount)
}

func (manager *StakingPoolManager) SDKDistributeRewards(poolID string) error {
	return manager.DistributeRewards(poolID)
}
