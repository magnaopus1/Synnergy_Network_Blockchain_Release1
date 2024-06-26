package syn223

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"sync"

	"synthron-blockchain/pkg/common"
)

// Token represents the structure of the SYN223 token.
type Token struct {
	ID        string
	BalanceOf map[string]uint64
	mutex     sync.RWMutex
	AllowedContracts map[string]bool // Contracts allowed to receive tokens.
}

// NewToken initializes a new SYN223 token with a specified initial supply.
func NewToken(initialSupply uint64) *Token {
	token := &Token{
		ID:               generateTokenID(),
		BalanceOf:        make(map[string]uint64),
		AllowedContracts: make(map[string]bool),
	}
	token.BalanceOf["creator"] = initialSupply // Assign all initial tokens to the creator.
	log.Printf("Created new SYN223 Token with ID: %s and initial supply: %d", token.ID, initialSupply)
	return token
}

func generateTokenID() string {
	hash := sha256.New()
	hash.Write([]byte("SYN223"))
	return hex.EncodeToString(hash.Sum(nil))
}

// Transfer attempts to transfer tokens from one account to another.
func (t *Token) Transfer(from, to string, amount uint64) error {
	t.mutex.Lock()
	defer t.mutex.Unlock()

	if t.BalanceOf[from] < amount {
		return fmt.Errorf("insufficient balance to transfer %d tokens from %s", amount, from)
	}
	if !t.AllowedContracts[to] && !common.IsRegularAddress(to) {
		return fmt.Errorf("transfer to non-allowed contract or non-contract address %s", to)
	}

	t.BalanceOf[from] -= amount
	t.BalanceOf[to] += amount
	log.Printf("Transferred %d tokens from %s to %s", amount, from, to)
	return nil
}

// AllowContract enables a contract to receive tokens.
func (t *Token) AllowContract(contractAddress string) {
	t.mutex.Lock()
	defer t.mutex.Unlock()

	t.AllowedContracts[contractAddress] = true
	log.Printf("Contract %s is now allowed to receive SYN223 tokens", contractAddress)
}

// RevokeContract disables a contract's ability to receive tokens.
func (t *Token) RevokeContract(contractAddress string) {
	t.mutex.Lock()
	defer t.mutex.Unlock()

	delete(t.AllowedContracts, contractAddress)
	log.Printf("Contract %s is now revoked from receiving SYN223 tokens", contractAddress)
}

// GetBalance returns the balance of the specified address.
func (t *Token) GetBalance(address string) uint64 {
	t.mutex.RLock()
	defer t.mutex.RUnlock()

	return t.BalanceOf[address]
}
