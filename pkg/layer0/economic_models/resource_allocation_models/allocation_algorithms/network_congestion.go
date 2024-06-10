package allocation_algorithms

import (
	"errors"
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/synthron_blockchain_final/pkg/layer0/core/crypto"
	"github.com/synthron_blockchain_final/pkg/layer0/core/network"
	"github.com/synthron_blockchain_final/pkg/layer0/core/transaction"
)

type NetworkCongestionManager struct {
	mu             sync.Mutex
	currentLoad    int
	transactionFee *big.Int
	adjustmentRate *big.Int
}

func NewNetworkCongestionManager() *NetworkCongestionManager {
	return &NetworkCongestionManager{
		currentLoad:    0,
		transactionFee: big.NewInt(1000), // initial base fee
		adjustmentRate: big.NewInt(10),   // fee adjustment rate
	}
}

func (ncm *NetworkCongestionManager) MonitorNetworkLoad() {
	// Simulated network load monitoring
	for {
		ncm.mu.Lock()
		ncm.currentLoad = getNetworkLoad()
		ncm.adjustTransactionFee()
		ncm.mu.Unlock()
		time.Sleep(1 * time.Minute)
	}
}

func getNetworkLoad() int {
	// Placeholder for actual network load calculation
	// In a real-world scenario, this would gather data from network nodes
	return 50 + time.Now().Second()%50 // Simulate network load between 50 and 100
}

func (ncm *NetworkCongestionManager) adjustTransactionFee() {
	if ncm.currentLoad > 75 {
		ncm.transactionFee.Add(ncm.transactionFee, ncm.adjustmentRate)
	} else if ncm.currentLoad < 50 {
		ncm.transactionFee.Sub(ncm.transactionFee, ncm.adjustmentRate)
		if ncm.transactionFee.Cmp(big.NewInt(1000)) < 0 {
			ncm.transactionFee.Set(big.NewInt(1000)) // minimum base fee
		}
	}
	fmt.Printf("Adjusted transaction fee to: %s\n", ncm.transactionFee.String())
}

func (ncm *NetworkCongestionManager) GetCurrentLoad() int {
	ncm.mu.Lock()
	defer ncm.mu.Unlock()
	return ncm.currentLoad
}

func (ncm *NetworkCongestionManager) GetTransactionFee() *big.Int {
	ncm.mu.Lock()
	defer ncm.mu.Unlock()
	return new(big.Int).Set(ncm.transactionFee)
}

// AllocateResources allocates resources based on network congestion and transaction importance
func (ncm *NetworkCongestionManager) AllocateResources(transactions []*transaction.Transaction) ([]*transaction.Transaction, error) {
	if len(transactions) == 0 {
		return nil, errors.New("no transactions to allocate resources for")
	}

	ncm.mu.Lock()
	defer ncm.mu.Unlock()

	// Sort transactions based on importance (example: by transaction fee or urgency)
	sortedTransactions := sortTransactionsByImportance(transactions)

	// Allocate resources based on current network load
	var allocatedTransactions []*transaction.Transaction
	for _, tx := range sortedTransactions {
		if ncm.currentLoad < 75 {
			allocatedTransactions = append(allocatedTransactions, tx)
		} else if tx.Fee.Cmp(ncm.transactionFee) >= 0 {
			allocatedTransactions = append(allocatedTransactions, tx)
		}
	}

	return allocatedTransactions, nil
}

func sortTransactionsByImportance(transactions []*transaction.Transaction) []*transaction.Transaction {
	// Placeholder: sort transactions by fee (importance)
	// In real-world scenarios, additional factors like sender reputation, transaction urgency, etc., would be considered
	for i := 0; i < len(transactions); i++ {
		for j := i + 1; j < len(transactions); j++ {
			if transactions[i].Fee.Cmp(transactions[j].Fee) < 0 {
				transactions[i], transactions[j] = transactions[j], transactions[i]
			}
		}
	}
	return transactions
}

// Example use case
func main() {
	ncm := NewNetworkCongestionManager()
	go ncm.MonitorNetworkLoad()

	time.Sleep(2 * time.Minute) // Let the monitoring run for a while

	transactions := []*transaction.Transaction{
		{ID: "tx1", Fee: big.NewInt(1500)},
		{ID: "tx2", Fee: big.NewInt(1200)},
		{ID: "tx3", Fee: big.NewInt(900)},
	}

	allocatedTransactions, err := ncm.AllocateResources(transactions)
	if err != nil {
		fmt.Println("Error allocating resources:", err)
		return
	}

	fmt.Println("Allocated transactions:")
	for _, tx := range allocatedTransactions {
		fmt.Printf("Transaction ID: %s, Fee: %s\n", tx.ID, tx.Fee.String())
	}

	currentLoad := ncm.GetCurrentLoad()
	fmt.Printf("Current network load: %d\n", currentLoad)

	currentFee := ncm.GetTransactionFee()
	fmt.Printf("Current transaction fee: %s\n", currentFee.String())
}
