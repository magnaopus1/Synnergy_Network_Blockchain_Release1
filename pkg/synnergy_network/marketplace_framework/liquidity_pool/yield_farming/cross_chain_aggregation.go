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

type Chain struct {
	Name            string
	YieldFarmManager *YieldFarmManager
}

// CrossChainManager manages cross-chain yield farming operations
type CrossChainManager struct {
	Chains map[string]*Chain
	Lock   sync.Mutex
}

// NewCrossChainManager creates a new CrossChainManager instance
func NewCrossChainManager() *CrossChainManager {
	return &CrossChainManager{
		Chains: make(map[string]*Chain),
	}
}

// AddChain adds a new blockchain to the cross-chain manager
func (cc *CrossChainManager) AddChain(name string, yieldFarmManager *YieldFarmManager) error {
	cc.Lock.Lock()
	defer cc.Lock.Unlock()

	if _, exists := cc.Chains[name]; exists {
		return errors.New("chain already exists")
	}

	chain := &Chain{
		Name:            name,
		YieldFarmManager: yieldFarmManager,
	}

	cc.Chains[name] = chain
	return nil
}

// AggregateYields aggregates the yields from different chains for a user
func (cc *CrossChainManager) AggregateYields(userAddress string) (decimal.Decimal, error) {
	cc.Lock.Lock()
	defer cc.Lock.Unlock()

	totalYield := decimal.Zero
	for _, chain := range cc.Chains {
		chain.YieldFarmManager.Lock.Lock()
		for _, pool := range chain.YieldFarmManager.Pools {
			if user, exists := pool.Users[userAddress]; exists {
				chain.YieldFarmManager.updatePoolRewards(pool)
				totalYield = totalYield.Add(user.Balance)
			}
		}
		chain.YieldFarmManager.Lock.Unlock()
	}

	if totalYield.IsZero() {
		return decimal.Zero, errors.New("no yield found for the user across chains")
	}
	return totalYield, nil
}

// TransferYield transfers yield from one chain to another for a user
func (cc *CrossChainManager) TransferYield(fromChainName, toChainName, userAddress string, amount decimal.Decimal) error {
	cc.Lock.Lock()
	defer cc.Lock.Unlock()

	fromChain, exists := cc.Chains[fromChainName]
	if !exists {
		return errors.New("source chain not found")
	}

	toChain, exists := cc.Chains[toChainName]
	if !exists {
		return errors.New("destination chain not found")
	}

	fromChain.YieldFarmManager.Lock.Lock()
	defer fromChain.YieldFarmManager.Lock.Unlock()

	toChain.YieldFarmManager.Lock.Lock()
	defer toChain.YieldFarmManager.Lock.Unlock()

	// Deduct yield from the source chain
	for _, pool := range fromChain.YieldFarmManager.Pools {
		if user, exists := pool.Users[userAddress]; exists {
			fromChain.YieldFarmManager.updatePoolRewards(pool)
			if user.Balance.LessThan(amount) {
				return errors.New("insufficient yield balance to transfer")
			}
			user.Balance = user.Balance.Sub(amount)
			break
		}
	}

	// Add yield to the destination chain
	for _, pool := range toChain.YieldFarmManager.Pools {
		if user, exists := pool.Users[userAddress]; exists {
			toChain.YieldFarmManager.updatePoolRewards(pool)
			user.Balance = user.Balance.Add(amount)
			break
		} else {
			user = &User{
				Address: userAddress,
				Balance: amount,
			}
			pool.Users[userAddress] = user
			break
		}
	}

	return nil
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
