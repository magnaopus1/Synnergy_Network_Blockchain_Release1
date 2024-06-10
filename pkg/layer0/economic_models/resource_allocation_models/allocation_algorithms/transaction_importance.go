package allocation_algorithms

import (
	"errors"
	"math/big"
	"sync"

	"github.com/synthron_blockchain_final/pkg/layer0/core/transaction"
)

// TransactionImportanceManager manages resource allocation based on transaction importance
type TransactionImportanceManager struct {
	mu            sync.Mutex
	transactions  map[string]*TransactionDetail
	participants  map[string]*ParticipantDetail
}

// TransactionDetail represents the details of a transaction
type TransactionDetail struct {
	ID       string
	Value    *big.Int
	Sender   string
	Urgency  int
	Reputation int
}

// ParticipantDetail represents a participant in the network
type ParticipantDetail struct {
	ID       string
	Reputation int
}

// NewTransactionImportanceManager initializes a new instance of TransactionImportanceManager
func NewTransactionImportanceManager() *TransactionImportanceManager {
	return &TransactionImportanceManager{
		transactions: make(map[string]*TransactionDetail),
		participants: make(map[string]*ParticipantDetail),
	}
}

// AddTransaction adds a new transaction to be considered for resource allocation
func (tim *TransactionImportanceManager) AddTransaction(tx *transaction.Transaction, urgency int, reputation int) {
	tim.mu.Lock()
	defer tim.mu.Unlock()
	tim.transactions[tx.ID] = &TransactionDetail{
		ID:       tx.ID,
		Value:    tx.Value,
		Sender:   tx.Sender,
		Urgency:  urgency,
		Reputation: reputation,
	}
}

// AddParticipant adds a new participant to the network
func (tim *TransactionImportanceManager) AddParticipant(id string, reputation int) {
	tim.mu.Lock()
	defer tim.mu.Unlock()
	tim.participants[id] = &ParticipantDetail{
		ID:       id,
		Reputation: reputation,
	}
}

// UpdateTransaction updates the details of an existing transaction
func (tim *TransactionImportanceManager) UpdateTransaction(id string, urgency int, reputation int) error {
	tim.mu.Lock()
	defer tim.mu.Unlock()
	tx, exists := tim.transactions[id]
	if !exists {
		return errors.New("transaction not found")
	}
	tx.Urgency = urgency
	tx.Reputation = reputation
	return nil
}

// UpdateParticipant updates the details of an existing participant
func (tim *TransactionImportanceManager) UpdateParticipant(id string, reputation int) error {
	tim.mu.Lock()
	defer tim.mu.Unlock()
	participant, exists := tim.participants[id]
	if !exists {
		return errors.New("participant not found")
	}
	participant.Reputation = reputation
	return nil
}

// AllocateResources allocates resources to transactions based on their importance
func (tim *TransactionImportanceManager) AllocateResources() ([]*transaction.Transaction, error) {
	if len(tim.transactions) == 0 {
		return nil, errors.New("no transactions to allocate resources for")
	}

	tim.mu.Lock()
	defer tim.mu.Unlock()

	// Sort transactions based on their importance
	sortedTransactions := tim.sortTransactionsByImportance()

	return sortedTransactions, nil
}

func (tim *TransactionImportanceManager) sortTransactionsByImportance() []*transaction.Transaction {
	// Placeholder: sort transactions by importance (value, urgency, sender reputation, transaction reputation)
	// Real-world scenarios would require more sophisticated sorting mechanisms
	transactionList := make([]*transaction.Transaction, 0, len(tim.transactions))
	for _, txDetail := range tim.transactions {
		transactionList = append(transactionList, &transaction.Transaction{
			ID:     txDetail.ID,
			Value:  txDetail.Value,
			Sender: txDetail.Sender,
			Fee:    big.NewInt(0), // Placeholder, actual fee calculation would be more complex
		})
	}

	// Sort transactions by importance (value, urgency, sender reputation, transaction reputation)
	for i := 0; i < len(transactionList); i++ {
		for j := i + 1; j < len(transactionList); j++ {
			if tim.compareImportance(transactionList[i], transactionList[j]) < 0 {
				transactionList[i], transactionList[j] = transactionList[j], transactionList[i]
			}
		}
	}
	return transactionList
}

func (tim *TransactionImportanceManager) compareImportance(tx1, tx2 *transaction.Transaction) int {
	detail1 := tim.transactions[tx1.ID]
	detail2 := tim.transactions[tx2.ID]

	importance1 := new(big.Int).Add(detail1.Value, big.NewInt(int64(detail1.Urgency+detail1.Reputation)))
	importance2 := new(big.Int).Add(detail2.Value, big.NewInt(int64(detail2.Urgency+detail2.Reputation)))

	return importance1.Cmp(importance2)
}

// Example use case
func main() {
	tim := NewTransactionImportanceManager()

	tim.AddParticipant("user1", 100)
	tim.AddParticipant("user2", 200)
	tim.AddParticipant("user3", 150)

	tim.AddTransaction(&transaction.Transaction{ID: "tx1", Value: big.NewInt(1000), Sender: "user1"}, 10, 100)
	tim.AddTransaction(&transaction.Transaction{ID: "tx2", Value: big.NewInt(500), Sender: "user2"}, 20, 200)
	tim.AddTransaction(&transaction.Transaction{ID: "tx3", Value: big.NewInt(1500), Sender: "user3"}, 30, 150)

	allocatedTransactions, err := tim.AllocateResources()
	if err != nil {
		fmt.Println("Error allocating resources:", err)
		return
	}

	fmt.Println("Allocated transactions:")
	for _, tx := range allocatedTransactions {
		fmt.Printf("Transaction ID: %s, Sender: %s, Value: %s\n", tx.ID, tx.Sender, tx.Value.String())
	}

	reputation, err := tim.UpdateParticipant("user2", 250)
	if err != nil {
		fmt.Println("Error updating participant reputation:", err)
		return
	}
	fmt.Printf("User2's updated reputation: %d\n", reputation)
}
