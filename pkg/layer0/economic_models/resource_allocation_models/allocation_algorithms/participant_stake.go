package allocation_algorithms

import (
	"errors"
	"fmt"
	"math/big"
	"sync"

	"github.com/synthron_blockchain_final/pkg/layer0/core/crypto"
	"github.com/synthron_blockchain_final/pkg/layer0/core/network"
	"github.com/synthron_blockchain_final/pkg/layer0/core/transaction"
)

// ParticipantStakeManager manages resource allocation based on participant stakes
type ParticipantStakeManager struct {
	mu         sync.Mutex
	participants map[string]*Participant
}

// Participant represents a network participant
type Participant struct {
	ID    string
	Stake *big.Int
}

// NewParticipantStakeManager initializes a new instance of ParticipantStakeManager
func NewParticipantStakeManager() *ParticipantStakeManager {
	return &ParticipantStakeManager{
		participants: make(map[string]*Participant),
	}
}

// AddParticipant adds a new participant to the network
func (psm *ParticipantStakeManager) AddParticipant(id string, stake *big.Int) {
	psm.mu.Lock()
	defer psm.mu.Unlock()
	psm.participants[id] = &Participant{
		ID:    id,
		Stake: stake,
	}
}

// UpdateStake updates the stake of an existing participant
func (psm *ParticipantStakeManager) UpdateStake(id string, newStake *big.Int) error {
	psm.mu.Lock()
	defer psm.mu.Unlock()
	participant, exists := psm.participants[id]
	if !exists {
		return errors.New("participant not found")
	}
	participant.Stake = newStake
	return nil
}

// GetStake retrieves the stake of a participant
func (psm *ParticipantStakeManager) GetStake(id string) (*big.Int, error) {
	psm.mu.Lock()
	defer psm.mu.Unlock()
	participant, exists := psm.participants[id]
	if !exists {
		return nil, errors.New("participant not found")
	}
	return participant.Stake, nil
}

// AllocateResources allocates resources to transactions based on participant stakes
func (psm *ParticipantStakeManager) AllocateResources(transactions []*transaction.Transaction) ([]*transaction.Transaction, error) {
	if len(transactions) == 0 {
		return nil, errors.New("no transactions to allocate resources for")
	}

	psm.mu.Lock()
	defer psm.mu.Unlock()

	// Sort transactions based on the stake of their participants
	sortedTransactions := psm.sortTransactionsByStake(transactions)

	return sortedTransactions, nil
}

func (psm *ParticipantStakeManager) sortTransactionsByStake(transactions []*transaction.Transaction) []*transaction.Transaction {
	// Placeholder: sort transactions by the stake of their participants
	// In real-world scenarios, additional factors like transaction value, sender reputation, etc., would be considered
	for i := 0; i < len(transactions); i++ {
		for j := i + 1; j < len(transactions); j++ {
			stakeI, _ := psm.GetStake(transactions[i].Sender)
			stakeJ, _ := psm.GetStake(transactions[j].Sender)
			if stakeI.Cmp(stakeJ) < 0 {
				transactions[i], transactions[j] = transactions[j], transactions[i]
			}
		}
	}
	return transactions
}

// Example use case
func main() {
	psm := NewParticipantStakeManager()
	psm.AddParticipant("user1", big.NewInt(1000))
	psm.AddParticipant("user2", big.NewInt(5000))
	psm.AddParticipant("user3", big.NewInt(3000))

	transactions := []*transaction.Transaction{
		{ID: "tx1", Sender: "user1", Fee: big.NewInt(100)},
		{ID: "tx2", Sender: "user2", Fee: big.NewInt(200)},
		{ID: "tx3", Sender: "user3", Fee: big.NewInt(150)},
	}

	allocatedTransactions, err := psm.AllocateResources(transactions)
	if err != nil {
		fmt.Println("Error allocating resources:", err)
		return
	}

	fmt.Println("Allocated transactions:")
	for _, tx := range allocatedTransactions {
		fmt.Printf("Transaction ID: %s, Sender: %s, Fee: %s\n", tx.ID, tx.Sender, tx.Fee.String())
	}

	stake, err := psm.GetStake("user2")
	if err != nil {
		fmt.Println("Error getting stake:", err)
		return
	}
	fmt.Printf("User2's stake: %s\n", stake.String())
}
