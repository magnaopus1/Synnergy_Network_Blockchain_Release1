package yield_farming

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sync"
	"time"

	"github.com/shopspring/decimal"
	"golang.org/x/crypto/scrypt"
)

// Tier represents a farming tier with its respective reward multiplier
type Tier struct {
	Name       string
	Multiplier decimal.Decimal
	LockPeriod time.Duration
}

// User represents a user participating in yield farming
type User struct {
	Address      string
	Balance      decimal.Decimal
	JoinedAt     time.Time
	CurrentTier  *Tier
}

// Pool represents a yield farming pool
type Pool struct {
	ID     string
	Name   string
	Users  map[string]*User
	Tiers  []*Tier
	Lock   sync.Mutex
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
func (manager *YieldFarmManager) CreatePool(name string, tiers []*Tier) (*Pool, error) {
	manager.Lock.Lock()
	defer manager.Lock.Unlock()

	id, err := generateUniqueID(name)
	if err != nil {
		return nil, err
	}

	pool := &Pool{
		ID:    id,
		Name:  name,
		Users: make(map[string]*User),
		Tiers: tiers,
	}

	manager.Pools[id] = pool
	return pool, nil
}

// AddUser adds a user to a pool
func (manager *YieldFarmManager) AddUser(poolID, userAddress string, initialBalance decimal.Decimal) error {
	manager.Lock.Lock()
	defer manager.Lock.Unlock()

	pool, exists := manager.Pools[poolID]
	if !exists {
		return errors.New("pool not found")
	}

	pool.Lock.Lock()
	defer pool.Lock.Unlock()

	if _, exists := pool.Users[userAddress]; exists {
		return errors.New("user already exists in the pool")
	}

	user := &User{
		Address:     userAddress,
		Balance:     initialBalance,
		JoinedAt:    time.Now(),
		CurrentTier: pool.Tiers[0], // Start at the lowest tier
	}

	pool.Users[userAddress] = user
	return nil
}

// PromoteUser promotes a user to a higher tier
func (manager *YieldFarmManager) PromoteUser(poolID, userAddress string) error {
	manager.Lock.Lock()
	defer manager.Lock.Unlock()

	pool, exists := manager.Pools[poolID]
	if !exists {
		return errors.New("pool not found")
	}

	pool.Lock.Lock()
	defer pool.Lock.Unlock()

	user, exists := pool.Users[userAddress]
	if !exists {
		return errors.New("user not found in the pool")
	}

	for i, tier := range pool.Tiers {
		if tier.Name == user.CurrentTier.Name && i < len(pool.Tiers)-1 {
			user.CurrentTier = pool.Tiers[i+1]
			return nil
		}
	}

	return errors.New("user is already at the highest tier")
}

// DemoteUser demotes a user to a lower tier
func (manager *YieldFarmManager) DemoteUser(poolID, userAddress string) error {
	manager.Lock.Lock()
	defer manager.Lock.Unlock()

	pool, exists := manager.Pools[poolID]
	if !exists {
		return errors.New("pool not found")
	}

	pool.Lock.Lock()
	defer pool.Lock.Unlock()

	user, exists := pool.Users[userAddress]
	if !exists {
		return errors.New("user not found in the pool")
	}

	for i, tier := range pool.Tiers {
		if tier.Name == user.CurrentTier.Name && i > 0 {
			user.CurrentTier = pool.Tiers[i-1]
			return nil
		}
	}

	return errors.New("user is already at the lowest tier")
}

// CalculateUserYield calculates the yield for a user based on their current tier
func (manager *YieldFarmManager) CalculateUserYield(poolID, userAddress string) (decimal.Decimal, error) {
	manager.Lock.Lock()
	defer manager.Lock.Unlock()

	pool, exists := manager.Pools[poolID]
	if !exists {
		return decimal.Zero, errors.New("pool not found")
	}

	pool.Lock.Lock()
	defer pool.Lock.Unlock()

	user, exists := pool.Users[userAddress]
	if !exists {
		return decimal.Zero, errors.New("user not found in the pool")
	}

	duration := time.Since(user.JoinedAt)
	interestRate := user.CurrentTier.Multiplier
	yield := user.Balance.Mul(interestRate).Mul(decimal.NewFromInt(int64(duration.Hours() / 24))) // Daily interest

	return yield, nil
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
