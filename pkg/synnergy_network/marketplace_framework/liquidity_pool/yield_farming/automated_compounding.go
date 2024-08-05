package yield_farming

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/shopspring/decimal"
	"golang.org/x/crypto/scrypt"
)

type User struct {
	Address string
	Balance decimal.Decimal
}

type Pool struct {
	Name           string
	StakedAmount   decimal.Decimal
	RewardRate     decimal.Decimal
	LastUpdateTime time.Time
	Users          map[string]*User
	Lock           sync.Mutex
}

// YieldFarmManager manages multiple yield farming pools
type YieldFarmManager struct {
	Pools map[string]*Pool
	Lock  sync.Mutex
}

// NewYieldFarmManager creates a new YieldFarmManager instance
func NewYieldFarmManager() *YieldFarmManager {
	return &YieldFarmManager{
		Pools: make(map[string]*Pool),
	}
}

// CreatePool creates a new yield farming pool
func (yf *YieldFarmManager) CreatePool(name string, rewardRate decimal.Decimal) error {
	yf.Lock.Lock()
	defer yf.Lock.Unlock()

	if _, exists := yf.Pools[name]; exists {
		return errors.New("pool already exists")
	}

	pool := &Pool{
		Name:           name,
		StakedAmount:   decimal.Zero,
		RewardRate:     rewardRate,
		LastUpdateTime: time.Now(),
		Users:          make(map[string]*User),
	}

	yf.Pools[name] = pool
	return nil
}

// Stake allows a user to stake tokens into a pool
func (yf *YieldFarmManager) Stake(poolName, userAddress string, amount decimal.Decimal) error {
	yf.Lock.Lock()
	defer yf.Lock.Unlock()

	pool, exists := yf.Pools[poolName]
	if !exists {
		return errors.New("pool not found")
	}

	pool.Lock.Lock()
	defer pool.Lock.Unlock()

	// Update rewards before staking
	yf.updatePoolRewards(pool)

	user, exists := pool.Users[userAddress]
	if !exists {
		user = &User{
			Address: userAddress,
			Balance: decimal.Zero,
		}
		pool.Users[userAddress] = user
	}

	user.Balance = user.Balance.Add(amount)
	pool.StakedAmount = pool.StakedAmount.Add(amount)
	return nil
}

// Unstake allows a user to unstake tokens from a pool
func (yf *YieldFarmManager) Unstake(poolName, userAddress string, amount decimal.Decimal) error {
	yf.Lock.Lock()
	defer yf.Lock.Unlock()

	pool, exists := yf.Pools[poolName]
	if !exists {
		return errors.New("pool not found")
	}

	pool.Lock.Lock()
	defer pool.Lock.Unlock()

	// Update rewards before unstaking
	yf.updatePoolRewards(pool)

	user, exists := pool.Users[userAddress]
	if !exists {
		return errors.New("user not found")
	}

	if user.Balance.LessThan(amount) {
		return errors.New("insufficient balance to unstake")
	}

	user.Balance = user.Balance.Sub(amount)
	pool.StakedAmount = pool.StakedAmount.Sub(amount)
	return nil
}

// CompoundRewards compounds the rewards for all users in a pool
func (yf *YieldFarmManager) CompoundRewards(poolName string) error {
	yf.Lock.Lock()
	defer yf.Lock.Unlock()

	pool, exists := yf.Pools[poolName]
	if !exists {
		return errors.New("pool not found")
	}

	pool.Lock.Lock()
	defer pool.Lock.Unlock()

	yf.updatePoolRewards(pool)
	return nil
}

// updatePoolRewards updates the rewards for all users in a pool based on the time elapsed
func (yf *YieldFarmManager) updatePoolRewards(pool *Pool) {
	now := time.Now()
	duration := now.Sub(pool.LastUpdateTime).Seconds()
	pool.LastUpdateTime = now

	rewardPerToken := pool.RewardRate.Mul(decimal.NewFromFloat(duration)).Div(pool.StakedAmount)
	for _, user := range pool.Users {
		user.Balance = user.Balance.Add(rewardPerToken.Mul(user.Balance))
	}
}

// generateSalt generates a random salt for hashing
func generateSalt() ([]byte, error) {
	salt := make([]byte, 16)
	_, err := rand.Read(salt)
	return salt, err
}

// hashPassword hashes a password using scrypt with a salt
func hashPassword(password, salt []byte) ([]byte, error) {
	return scrypt.Key(password, salt, 32768, 8, 1, 32)
}

// generateUniqueID generates a unique ID
func generateUniqueID(name string) (string, error) {
	randBytes := make([]byte, 16)
	if _, err := rand.Read(randBytes); err != nil {
		return "", err
	}

	hash := sha256.New()
	hash.Write([]byte(fmt.Sprintf("%s-%s", name, hex.EncodeToString(randBytes))))
	return hex.EncodeToString(hash.Sum(nil)), nil
}
