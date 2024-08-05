package staking_yield_farming

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/scrypt"
)

// StakingPosition represents a staking position
type StakingPosition struct {
	ID           string
	Staker       string
	Amount       float64
	Reward       float64
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// FarmingPool represents a yield farming pool
type FarmingPool struct {
	ID           string
	Token        string
	TotalStaked  float64
	RewardRate   float64
	Stakers      map[string]StakingPosition
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// StakingManager manages staking and yield farming pools
type StakingManager struct {
	mu        sync.Mutex
	pools     map[string]FarmingPool
	secretKey string
}

// NewStakingManager initializes a new StakingManager
func NewStakingManager(secretKey string) *StakingManager {
	return &StakingManager{
		pools:     make(map[string]FarmingPool),
		secretKey: secretKey,
	}
}

// CreateFarmingPool creates a new yield farming pool
func (sm *StakingManager) CreateFarmingPool(token string, rewardRate float64) (string, error) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	id := generateID()
	pool := FarmingPool{
		ID:           id,
		Token:        token,
		TotalStaked:  0,
		RewardRate:   rewardRate,
		Stakers:      make(map[string]StakingPosition),
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	sm.pools[id] = pool
	log.Printf("Created farming pool: %+v", pool)
	return id, nil
}

// StakeTokens stakes tokens in the farming pool
func (sm *StakingManager) StakeTokens(poolID, staker string, amount float64) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	pool, exists := sm.pools[poolID]
	if !exists {
		return errors.New("pool not found")
	}

	position, exists := pool.Stakers[staker]
	if !exists {
		position = StakingPosition{
			ID:        generateID(),
			Staker:    staker,
			Amount:    0,
			Reward:    0,
			CreatedAt: time.Now(),
		}
	}
	position.Amount += amount
	position.UpdatedAt = time.Now()

	pool.TotalStaked += amount
	pool.Stakers[staker] = position
	pool.UpdatedAt = time.Now()

	sm.pools[poolID] = pool
	log.Printf("Staked %f tokens in pool: %+v", amount, pool)
	return nil
}

// UnstakeTokens unstakes tokens from the farming pool
func (sm *StakingManager) UnstakeTokens(poolID, staker string, amount float64) (float64, error) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	pool, exists := sm.pools[poolID]
	if !exists {
		return 0, errors.New("pool not found")
	}

	position, exists := pool.Stakers[staker]
	if !exists || position.Amount < amount {
		return 0, errors.New("insufficient staked amount")
	}

	reward := sm.calculateReward(position, pool.RewardRate)
	position.Amount -= amount
	position.Reward += reward
	position.UpdatedAt = time.Now()

	if position.Amount == 0 {
		delete(pool.Stakers, staker)
	} else {
		pool.Stakers[staker] = position
	}
	pool.TotalStaked -= amount
	pool.UpdatedAt = time.Now()

	sm.pools[poolID] = pool
	log.Printf("Unstaked %f tokens from pool: %+v, Reward: %f", amount, pool, reward)
	return reward, nil
}

// calculateReward calculates the reward based on the staked amount and reward rate
func (sm *StakingManager) calculateReward(position StakingPosition, rewardRate float64) float64 {
	duration := time.Since(position.CreatedAt).Hours() / 24 // Duration in days
	return position.Amount * rewardRate * duration
}

// GetPool returns the details of a farming pool
func (sm *StakingManager) GetPool(poolID string) (FarmingPool, error) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	pool, exists := sm.pools[poolID]
	if !exists {
		return FarmingPool{}, errors.New("pool not found")
	}

	return pool, nil
}

// Encrypt encrypts a message using AES encryption with Scrypt derived key
func (sm *StakingManager) Encrypt(message, secretKey string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}

	key, err := scrypt.Key([]byte(secretKey), salt, 1<<15, 8, 1, 32)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	ciphertext := make([]byte, aes.BlockSize+len(message))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], []byte(message))

	return hex.EncodeToString(salt) + ":" + hex.EncodeToString(ciphertext), nil
}

// Decrypt decrypts a message using AES encryption with Scrypt derived key
func (sm *StakingManager) Decrypt(encryptedMessage, secretKey string) (string, error) {
	parts := split(encryptedMessage, ":")
	if len(parts) != 2 {
		return "", errors.New("invalid encrypted message format")
	}

	salt, err := hex.DecodeString(parts[0])
	if err != nil {
		return "", err
	}

	ciphertext, err := hex.DecodeString(parts[1])
	if err != nil {
		return "", err
	}

	key, err := scrypt.Key([]byte(secretKey), salt, 1<<15, 8, 1, 32)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	if len(ciphertext) < aes.BlockSize {
		return "", errors.New("ciphertext too short")
	}

	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(ciphertext, ciphertext)

	return string(ciphertext), nil
}

func split(s string, sep string) []string {
	var parts []string
	var buf []rune
	for _, r := range s {
		if string(r) == sep {
			parts = append(parts, string(buf))
			buf = []rune{}
		} else {
			buf = append(buf, r)
		}
	}
	parts = append(parts, string(buf))
	return parts
}

// Hash generates a SHA-256 hash of the input string
func Hash(input string) string {
	hash := sha256.Sum256([]byte(input))
	return hex.EncodeToString(hash[:])
}

// generateID generates a unique identifier
func generateID() string {
	return hex.EncodeToString(randBytes(16))
}

// randBytes generates random bytes of the given length
func randBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}

// SecurePassword hashes a password using Argon2
func SecurePassword(password, salt string) string {
	hash := argon2.IDKey([]byte(password), []byte(salt), 1, 64*1024, 4, 32)
	return hex.EncodeToString(hash)
}

// VerifyPassword verifies a password against a hash using Argon2
func VerifyPassword(password, salt, hash string) bool {
	return SecurePassword(password, salt) == hash
}
