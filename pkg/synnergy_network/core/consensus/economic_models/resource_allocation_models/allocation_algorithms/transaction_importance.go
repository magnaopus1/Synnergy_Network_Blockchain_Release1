package allocation_algorithms

import (
	"errors"
	"sync"
)

// Transaction represents a blockchain transaction
type Transaction struct {
	ID       string
	Value    float64
	Priority int
	Size     int
}

// Network represents the entire network state
type Network struct {
	mu           sync.Mutex
	Transactions map[string]*Transaction
	Nodes        map[string]*Node
}

// Node represents a network participant
type Node struct {
	ID    string
	Stake int
}

// NewNetwork initializes a new Network
func NewNetwork() *Network {
	return &Network{
		Transactions: make(map[string]*Transaction),
		Nodes:        make(map[string]*Node),
	}
}

// AddTransaction adds a transaction to the network
func (n *Network) AddTransaction(id string, value float64, priority int, size int) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.Transactions[id] = &Transaction{
		ID:       id,
		Value:    value,
		Priority: priority,
		Size:     size,
	}
}

// RemoveTransaction removes a transaction from the network
func (n *Network) RemoveTransaction(id string) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	_, exists := n.Transactions[id]
	if !exists {
		return errors.New("transaction not found")
	}
	delete(n.Transactions, id)
	return nil
}

// CalculateTransactionImportance calculates the importance of a transaction
func (n *Network) CalculateTransactionImportance(id string) (float64, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	tx, exists := n.Transactions[id]
	if !exists {
		return 0, errors.New("transaction not found")
	}
	importance := (tx.Value + float64(tx.Priority)) / float64(tx.Size)
	return importance, nil
}

// PrioritizeTransactions sorts transactions based on their importance
func (n *Network) PrioritizeTransactions() []*Transaction {
	n.mu.Lock()
	defer n.mu.Unlock()
	var txs []*Transaction
	for _, tx := range n.Transactions {
		txs = append(txs, tx)
	}

	// Sort transactions by importance
	for i := range txs {
		for j := i + 1; j < len(txs); j++ {
			impI := (txs[i].Value + float64(txs[i].Priority)) / float64(txs[i].Size)
			impJ := (txs[j].Value + float64(txs[j].Priority)) / float64(txs[j].Size)
			if impI < impJ {
				txs[i], txs[j] = txs[j], txs[i]
			}
		}
	}

	return txs
}

// AllocateResourcesBasedOnImportance allocates resources to nodes based on transaction importance
func (n *Network) AllocateResourcesBasedOnImportance(totalResources int) map[string]int {
	n.mu.Lock()
	defer n.mu.Unlock()

	allocation := make(map[string]int)
	transactions := n.PrioritizeTransactions()
	if len(transactions) == 0 {
		return allocation
	}

	totalImportance := 0.0
	importanceMap := make(map[string]float64)

	for _, tx := range transactions {
		importance, _ := n.CalculateTransactionImportance(tx.ID)
		importanceMap[tx.ID] = importance
		totalImportance += importance
	}

	for _, tx := range transactions {
		importance := importanceMap[tx.ID]
		allocation[tx.ID] = int((importance / totalImportance) * float64(totalResources))
	}

	return allocation
}

// AddNode adds a node to the network
func (n *Network) AddNode(id string, stake int) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.Nodes[id] = &Node{
		ID:    id,
		Stake: stake,
	}
}

// RemoveNode removes a node from the network
func (n *Network) RemoveNode(id string) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	_, exists := n.Nodes[id]
	if !exists {
		return errors.New("node not found")
	}
	delete(n.Nodes, id)
	return nil
}

// GetNodeStake returns the current stake of a node
func (n *Network) GetNodeStake(id string) (int, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	node, exists := n.Nodes[id]
	if !exists {
		return 0, errors.New("node not found")
	}
	return node.Stake, nil
}

// ListNodes lists all nodes in the network
func (n *Network) ListNodes() []*Node {
	n.mu.Lock()
	defer n.mu.Unlock()
	nodes := []*Node{}
	for _, node := range n.Nodes {
		nodes = append(nodes, node)
	}
	return nodes
}

// AllocateResourcesBasedOnStake allocates resources to nodes based on their stakes
func (n *Network) AllocateResourcesBasedOnStake(totalResources int) map[string]int {
	n.mu.Lock()
	defer n.mu.Unlock()
	allocation := make(map[string]int)
	totalStake := 0

	for _, node := range n.Nodes {
		totalStake += node.Stake
	}

	for id, node := range n.Nodes {
		allocation[id] = int(float64(node.Stake) / float64(totalStake) * float64(totalResources))
	}

	return allocation
}
