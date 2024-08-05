package consensus

import (
	"crypto/sha256"
	"encoding/hex"
	"math/big"
	"testing"
	"time"
	"synnergy_network_blockchain/pkg/synnergy_network/core/common"
)

// Setup initial PoS system for testing
func setupProofOfStake() *ProofOfStake {
	electionInterval := time.Second * 10
	slashingPenalty := big.NewInt(100)
	return NewProofOfStake(electionInterval, slashingPenalty)
}

// Test RegisterValidator function
func TestRegisterValidator(t *testing.T) {
	pos := setupProofOfStake()
	stake := big.NewInt(1000)
	pos.RegisterValidator("validator1", stake)

	if len(pos.Validators) != 1 {
		t.Errorf("Expected 1 validator, got %d", len(pos.Validators))
	}

	if pos.TotalStake.Cmp(stake) != 0 {
		t.Errorf("Expected total stake %d, got %d", stake, pos.TotalStake)
	}
}

// Test UnregisterValidator function
func TestUnregisterValidator(t *testing.T) {
	pos := setupProofOfStake()
	stake := big.NewInt(1000)
	pos.RegisterValidator("validator1", stake)
	pos.UnregisterValidator("validator1")

	if len(pos.Validators) != 0 {
		t.Errorf("Expected 0 validators, got %d", len(pos.Validators))
	}

	if pos.TotalStake.Cmp(big.NewInt(0)) != 0 {
		t.Errorf("Expected total stake 0, got %d", pos.TotalStake)
	}
}

// Test ProcessTransactions function
func TestProcessTransactions(t *testing.T) {
	pos := setupProofOfStake()
	tx := &common.Transaction{
		ID:   "tx1",
		From: "Alice",
		To:   "Bob",
		Amount: big.NewInt(10),
		Fee:    big.NewInt(1),
	}

	txs := []*common.Transaction{tx}
	err := pos.ProcessTransactions(txs)
	if err != nil {
		t.Fatalf("Failed to process transactions: %v", err)
	}
}

// Test ValidateBlock function
func TestValidateBlock(t *testing.T) {
	pos := setupProofOfStake()
	stake := big.NewInt(1000)
	pos.RegisterValidator("validator1", stake)
	pos.ElectValidators()

	block := &Block{
		Timestamp:    time.Now().Unix(),
		PreviousHash: []byte("previousHash"),
		Transactions: []*common.Transaction{},
	}

	valid := pos.ValidateBlock(block, "validator1")
	if !valid {
		t.Errorf("Expected block to be valid")
	}
}

// Test ElectValidators function
func TestElectValidators(t *testing.T) {
	pos := setupProofOfStake()
	stake1 := big.NewInt(1000)
	stake2 := big.NewInt(500)
	pos.RegisterValidator("validator1", stake1)
	pos.RegisterValidator("validator2", stake2)

	pos.ElectValidators()

	selectedCount := 0
	for _, validator := range pos.Validators {
		if validator.IsValidator {
			selectedCount++
		}
	}

	if selectedCount == 0 {
		t.Errorf("Expected at least one validator to be selected")
	}
}

// Test the entire Proof of Stake process
func TestProofOfStakeProcess(t *testing.T) {
	pos := setupProofOfStake()

	// Register validators
	stake1 := big.NewInt(1000)
	stake2 := big.NewInt(500)
	pos.RegisterValidator("validator1", stake1)
	pos.RegisterValidator("validator2", stake2)

	// Elect validators
	pos.ElectValidators()

	// Create and process transactions
	tx1 := &common.Transaction{
		ID:   "tx1",
		From: "Alice",
		To:   "Bob",
		Amount: big.NewInt(10),
		Fee:    big.NewInt(1),
	}
	tx2 := &common.Transaction{
		ID:   "tx2",
		From: "Bob",
		To:   "Charlie",
		Amount: big.NewInt(5),
		Fee:    big.NewInt(1),
	}
	txs := []*common.Transaction{tx1, tx2}
	err := pos.ProcessTransactions(txs)
	if err != nil {
		t.Fatalf("Failed to process transactions: %v", err)
	}

	// Validate a block
	block := &Block{
		Timestamp:    time.Now().Unix(),
		PreviousHash: []byte("previousHash"),
		Transactions: txs,
	}
	valid := pos.ValidateBlock(block, "validator1")
	if !valid {
		t.Errorf("Expected block to be valid")
	}

	// Check if the validator was rewarded
	validator1 := pos.Validators["validator1"]
	expectedStake := new(big.Int).Add(stake1, big.NewInt(100))
	if validator1.Stake.Cmp(expectedStake) != 0 {
		t.Errorf("Expected validator1 stake %d, got %d", expectedStake, validator1.Stake)
	}
}
