// Package management provides functionalities and services for managing the Synnergy Network blockchain,
// including transaction processing for maintaining the ledger and ensuring the integrity of transactions.
package management

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/synnergy_network/pkg/synnergy_network/sidechains/node"
)

// Transaction represents a transaction in the Synnergy Network blockchain.
type Transaction struct {
	ID        string                 `json:"id"`
	From      string                 `json:"from"`
	To        string                 `json:"to"`
	Amount    float64                `json:"amount"`
	Timestamp time.Time              `json:"timestamp"`
	Signature string                 `json:"signature"`
	Data      map[string]interface{} `json:"data,omitempty"`
}

// Block represents a block in the blockchain.
type Block struct {
	Index        int           `json:"index"`
	Timestamp    time.Time     `json:"timestamp"`
	Transactions []Transaction `json:"transactions"`
	PrevHash     string        `json:"prevHash"`
	Hash         string        `json:"hash"`
	Nonce        int           `json:"nonce"`
}

// Blockchain represents the Synnergy Network blockchain.
type Blockchain struct {
	Blocks []Block `json:"blocks"`
}

// NewBlockchain creates a new Blockchain with the genesis block.
func NewBlockchain() *Blockchain {
	genesisBlock := Block{
		Index:        0,
		Timestamp:    time.Now(),
		Transactions: []Transaction{},
		PrevHash:     "0",
		Hash:         "",
		Nonce:        0,
	}
	genesisBlock.Hash = calculateBlockHash(genesisBlock)
	return &Blockchain{Blocks: []Block{genesisBlock}}
}

// AddBlock adds a new block to the blockchain.
func (bc *Blockchain) AddBlock(transactions []Transaction) error {
	prevBlock := bc.Blocks[len(bc.Blocks)-1]
	newBlock := Block{
		Index:        prevBlock.Index + 1,
		Timestamp:    time.Now(),
		Transactions: transactions,
		PrevHash:     prevBlock.Hash,
		Nonce:        0,
	}
	newBlock.Hash = calculateBlockHash(newBlock)
	bc.Blocks = append(bc.Blocks, newBlock)
	return nil
}

// IsValid checks if the blockchain is valid.
func (bc *Blockchain) IsValid() bool {
	for i := 1; i < len(bc.Blocks); i++ {
		prevBlock := bc.Blocks[i-1]
		currentBlock := bc.Blocks[i]

		if currentBlock.Hash != calculateBlockHash(currentBlock) {
			return false
		}
		if currentBlock.PrevHash != prevBlock.Hash {
			return false
		}
	}
	return true
}

// calculateBlockHash calculates the hash of a block.
func calculateBlockHash(block Block) string {
	record := fmt.Sprintf("%d%s%s%d", block.Index, block.Timestamp, block.PrevHash, block.Nonce)
	h := sha256.New()
	h.Write([]byte(record))
	return fmt.Sprintf("%x", h.Sum(nil))
}

// ProcessTransaction processes a new transaction and adds it to the blockchain.
func (bc *Blockchain) ProcessTransaction(transaction Transaction) error {
	if !validateTransaction(transaction) {
		return errors.New("invalid transaction")
	}

	transactions := append(bc.Blocks[len(bc.Blocks)-1].Transactions, transaction)
	return bc.AddBlock(transactions)
}

// validateTransaction validates the transaction.
func validateTransaction(transaction Transaction) bool {
	// TODO: Implement the actual transaction validation logic.
	return true
}

// SynchronizeTransactions synchronizes transactions across all nodes in the network.
func SynchronizeTransactions(transaction Transaction, nodes []string) error {
	for _, nodeURL := range nodes {
		if err := sendTransactionToNode(nodeURL, transaction); err != nil {
			log.Printf("failed to send transaction to node %s: %v", nodeURL, err)
		}
	}
	return nil
}

// sendTransactionToNode sends the transaction to the specified node.
func sendTransactionToNode(nodeURL string, transaction Transaction) error {
	data, err := json.Marshal(transaction)
	if err != nil {
		return fmt.Errorf("failed to marshal transaction: %v", err)
	}

	req, err := http.NewRequest("POST", fmt.Sprintf("%s/transaction", nodeURL), bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("failed to create HTTP request: %v", err)
	}

	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{
		Timeout: 10 * time.Second,
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send HTTP request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := ioutil.ReadAll(resp.Body)
		return fmt.Errorf("failed to synchronize transaction with node %s: %s", nodeURL, string(body))
	}

	return nil
}

// Example usage
func main() {
	bc := NewBlockchain()

	transaction := Transaction{
		ID:        "1",
		From:      "Alice",
		To:        "Bob",
		Amount:    10.0,
		Timestamp: time.Now(),
		Signature: "signature",
		Data:      map[string]interface{}{"description": "Payment for services"},
	}

	if err := bc.ProcessTransaction(transaction); err != nil {
		log.Fatalf("Failed to process transaction: %v", err)
	}

	log.Println("Transaction processed successfully")
}
