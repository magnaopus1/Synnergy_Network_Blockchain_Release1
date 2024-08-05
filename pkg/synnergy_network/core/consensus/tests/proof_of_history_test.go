package consensus

import (
	"crypto/sha256"
	"encoding/hex"
	"math/big"
	"testing"
	"time"
	"synnergy_network_blockchain/pkg/synnergy_network/core/common"
)

// Setup initial blockchain with a genesis block for testing
func setupBlockchain() *ProofOfHistory {
	poh := NewProofOfHistory()

	genesisBlock := common.Block{
		Index:               0,
		Timestamp:           time.Now().Unix(),
		PreviousHash:        "",
		Hash:                poh.calculateHash(Block{Index: 0, Timestamp: time.Now().Unix()}),
		CryptographicAnchor: poh.generateAnchor(""),
	}

	poh.blockchain = append(poh.blockchain, genesisBlock)
	return poh
}

// Test GenerateTimestamp function
func TestGenerateTimestamp(t *testing.T) {
	poh := setupBlockchain()
	tx := &common.Transaction{
		ID:        "1",
		Timestamp: time.Now().Unix(),
		Sender:    "Alice",
		Receiver:  "Bob",
		Amount:    10.0,
	}

	txHash, err := poh.GenerateTimestamp(tx)
	if err != nil {
		t.Fatalf("Failed to generate timestamp: %v", err)
	}

	hash := sha256.Sum256([]byte(tx.ID + tx.Sender + tx.Receiver + "10.000000"))
	expectedHash := hex.EncodeToString(hash[:])
	if txHash != expectedHash {
		t.Errorf("Expected hash %s, got %s", expectedHash, txHash)
	}
}

// Test ValidateTransaction function
func TestValidateTransaction(t *testing.T) {
	poh := setupBlockchain()
	tx := &common.Transaction{
		ID:        "1",
		Timestamp: time.Now().Unix(),
		Sender:    "Alice",
		Receiver:  "Bob",
		Amount:    10.0,
	}

	txHash, _ := poh.GenerateTimestamp(tx)

	err := poh.ValidateTransaction(tx, txHash)
	if err != nil {
		t.Fatalf("Transaction should be valid but got error: %v", err)
	}

	// Test with invalid transaction hash
	err = poh.ValidateTransaction(tx, "invalid_hash")
	if err == nil {
		t.Errorf("Expected error for invalid transaction hash, got nil")
	}
}

// Test Block Generation and Validation
func TestGenerateAndValidateBlock(t *testing.T) {
	poh := setupBlockchain()
	oldBlock := poh.blockchain[len(poh.blockchain)-1]

	newBlock, err := poh.generateBlock(oldBlock, "Block Data")
	if err != nil {
		t.Fatalf("Failed to generate block: %v", err)
	}

	if !poh.isBlockValid(newBlock, oldBlock) {
		t.Errorf("Block validation failed")
	}

	// Modify block and test invalidity
	newBlock.Index++
	if poh.isBlockValid(newBlock, oldBlock) {
		t.Errorf("Block validation should fail for modified block")
	}
}

// Test AddBlock function
func TestAddBlock(t *testing.T) {
	poh := setupBlockchain()
	oldBlock := poh.blockchain[len(poh.blockchain)-1]

	newBlock, err := poh.generateBlock(oldBlock, "Block Data")
	if err != nil {
		t.Fatalf("Failed to generate block: %v", err)
	}

	err = poh.addBlock(newBlock)
	if err != nil {
		t.Fatalf("Failed to add block: %v", err)
	}

	if len(poh.blockchain) != 2 {
		t.Errorf("Expected blockchain length 2, got %d", len(poh.blockchain))
	}

	// Test adding an invalid block
	invalidBlock := newBlock
	invalidBlock.Index++
	err = poh.addBlock(invalidBlock)
	if err == nil {
		t.Errorf("Expected error for adding invalid block, got nil")
	}
}

// Test RewardValidators function
func TestRewardValidators(t *testing.T) {
	poh := setupBlockchain()
	oldBlock := poh.blockchain[len(poh.blockchain)-1]

	tx := common.Transaction{
		ID:        "1",
		Timestamp: time.Now().Unix(),
		Sender:    "Alice",
		Receiver:  "Bob",
		Amount:    10.0,
	}

	newBlock, err := poh.generateBlock(oldBlock, "Block Data")
	if err != nil {
		t.Fatalf("Failed to generate block: %v", err)
	}
	newBlock.Transactions = append(newBlock.Transactions, tx)

	err = poh.addBlock(newBlock)
	if err != nil {
		t.Fatalf("Failed to add block: %v", err)
	}

	err = poh.RewardValidators()
	if err != nil {
		t.Fatalf("Failed to reward validators: %v", err)
	}

	if poh.rewards["Alice"].Cmp(big.NewInt(1000)) != 0 {
		t.Errorf("Expected reward 1000, got %v", poh.rewards["Alice"])
	}
}

// Test ProcessTransactions function
func TestProcessTransactions(t *testing.T) {
	poh := setupBlockchain()
	txs := []*common.Transaction{
		{
			ID:        "1",
			Timestamp: time.Now().Unix(),
			Sender:    "Alice",
			Receiver:  "Bob",
			Amount:    10.0,
		},
		{
			ID:        "2",
			Timestamp: time.Now().Unix(),
			Sender:    "Bob",
			Receiver:  "Charlie",
			Amount:    5.0,
		},
	}

	err := poh.ProcessTransactions(txs)
	if err != nil {
		t.Fatalf("Failed to process transactions: %v", err)
	}

	// Check the last block for transactions
	lastBlock := poh.blockchain[len(poh.blockchain)-1]
	if len(lastBlock.Transactions) != 2 {
		t.Errorf("Expected 2 transactions in the last block, got %d", len(lastBlock.Transactions))
	}
}

// Test the entire ProofOfHistory process
func TestProofOfHistoryProcess(t *testing.T) {
	poh := setupBlockchain()

	// Example transactions
	txs := []*common.Transaction{
		{
			ID:        "1",
			Timestamp: time.Now().Unix(),
			Sender:    "Alice",
			Receiver:  "Bob",
			Amount:    10.0,
		},
		{
			ID:        "2",
			Timestamp: time.Now().Unix(),
			Sender:    "Bob",
			Receiver:  "Charlie",
			Amount:    5.0,
		},
	}

	err := poh.ProcessTransactions(txs)
	if err != nil {
		t.Fatalf("Failed to process transactions: %v", err)
	}

	// Check if the new block is added
	if len(poh.blockchain) != 2 {
		t.Fatalf("Expected blockchain length 2, got %d", len(poh.blockchain))
	}

	// Check the last block for transactions
	lastBlock := poh.blockchain[len(poh.blockchain)-1]
	if len(lastBlock.Transactions) != 2 {
		t.Errorf("Expected 2 transactions in the last block, got %d", len(lastBlock.Transactions))
	}

	// Check rewards
	if poh.rewards["Alice"].Cmp(big.NewInt(1000)) != 0 {
		t.Errorf("Expected reward for Alice 1000, got %v", poh.rewards["Alice"])
	}

	if poh.rewards["Bob"].Cmp(big.NewInt(1000)) != 0 {
		t.Errorf("Expected reward for Bob 1000, got %v", poh.rewards["Bob"])
	}
}
