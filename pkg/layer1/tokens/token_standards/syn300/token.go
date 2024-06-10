package syn300

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"sync"
	"time"

	"synthron-blockchain/pkg/common"
)

// Token represents a governance token in the Synthron ecosystem, facilitating complex governance functionalities.
type Token struct {
	ID          string
	TotalSupply uint64
	BalanceOf   map[string]uint64
	VotingPower map[string]uint64
	Delegations map[string]string  // Maps a delegator's address to a delegate's address.
	Votes       map[string]map[string]uint64 // Maps proposal IDs to a map of voter addresses and their vote weights.
	mutex       sync.RWMutex
}

// NewToken initializes a new SYN300 governance token with a specified total supply.
func NewToken(totalSupply uint64) *Token {
	token := &Token{
		ID:          generateTokenID(),
		TotalSupply: totalSupply,
		BalanceOf:   make(map[string]uint64),
		VotingPower: make(map[string]uint64),
		Delegations: make(map[string]string),
		Votes:       make(map[string]map[string]uint64),
	}
	log.Printf("Created new SYN300 Token with ID: %s and Total Supply: %d", token.ID, token.TotalSupply)
	return token
}

func generateTokenID() string {
	hash := sha256.New()
	hash.Write([]byte(time.Now().String() + "SYN300"))
	return hex.EncodeToString(hash.Sum(nil))
}

func (t *Token) Mint(address string, amount uint64) error {
	t.mutex.Lock()
	defer t.mutex.Unlock()

	if t.TotalSupply+amount > t.TotalSupply { // Check for overflow
		t.BalanceOf[address] += amount
		t.TotalSupply += amount
		log.Printf("Minted %d SYN300 Tokens to %s", amount, address)
		return nil
	}
	return fmt.Errorf("minting would exceed the maximum supply of SYN300 Tokens")
}

func (t *Token) Transfer(from, to string, amount uint64) error {
	t.mutex.Lock()
	defer t.mutex.Unlock()

	if t.BalanceOf[from] < amount {
		return fmt.Errorf("insufficient balance to transfer %d SYN300 Tokens from %s", amount, from)
	}

	t.BalanceOf[from] -= amount
	t.BalanceOf[to] += amount
	log.Printf("Transferred %d SYN300 Tokens from %s to %s", amount, from, to)
	return nil
}

func (t *Token) Delegate(delegator, delegate string) error {
	t.mutex.Lock()
	defer t.mutex.Unlock()

	if t.BalanceOf[delegator] == 0 {
		return fmt.Errorf("delegator %s has no SYN300 Tokens to delegate", delegator)
	}

	t.Delegations[delegator] = delegate
	log.Printf("%s has delegated their voting power to %s", delegator, delegate)
	return nil
}

func (t *Token) Vote(voter, proposalID string, voteAmount uint64) error {
	t.mutex.Lock()
	defer t.mutex.Unlock()

	// Check if voter has delegated their voting power
	if delegate, ok := t.Delegations[voter]; ok {
		voter = delegate
	}

	if t.BalanceOf[voter] < voteAmount {
		return fmt.Errorf("%s has insufficient SYN300 Tokens to vote on proposal %s", voter, proposalID)
	}

	if _, exists := t.Votes[proposalID]; !exists {
		t.Votes[proposalID] = make(map[string]uint64)
	}

	t.Votes[proposalID][voter] += voteAmount
	log.Printf("%s voted with %d SYN300 Tokens on proposal %s", voter, voteAmount, proposalID)
	return nil
}

func (t *Token) GetBalance(address string) uint64 {
	t.mutex.RLock()
	defer t.mutex.RUnlock()

	balance := t.BalanceOf[address]
	log.Printf("Queried balance for %s: %d SYN300 Tokens", address, balance)
	return balance
}

func (t *Token) GetTotalSupply() uint64 {
	t.mutex.RLock()
	defer t.mutex.RUnlock()

	log.Printf("Queried total supply of SYN300 Tokens: %d", t.TotalSupply)
	return t.TotalSupply
}

// TallyVotes counts all votes for a specific proposal.
func (t *Token) TallyVotes(proposalID string) (uint64, error) {
	t.mutex.RLock()
	defer t.mutex.RUnlock()

	if votes, exists := t.Votes[proposalID]; exists {
		var totalVotes uint64
		for _, voteAmount := range votes {
			totalVotes += voteAmount
		}
		log.Printf("Total votes for proposal %s: %d", proposalID, totalVotes)
		return totalVotes, nil
	}
	return 0, fmt.Errorf("no votes recorded for proposal %s", proposalID)
}
