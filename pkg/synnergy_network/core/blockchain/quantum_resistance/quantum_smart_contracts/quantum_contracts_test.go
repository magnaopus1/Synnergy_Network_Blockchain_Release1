package quantum_smart_contracts

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"

	"golang.org/x/crypto/scrypt"
)

// TestQuantumSecureBlockchain tests the functionality of the QuantumSecureBlockchain.
func TestQuantumSecureBlockchain(t *testing.T) {
	salt := []byte("test_salt")
	quantumKey, err := GenerateQuantumKey("test_password", salt)
	if err != nil {
		t.Fatalf("Failed to generate quantum key: %v", err)
	}

	blockchain := NewQuantumSecureBlockchain()

	agent1 := &AutonomousAgent{
		ID:         "agent1",
		Owner:      "Alice",
		Code:       "SmartContractCode1",
		State:      "Initialized",
		QuantumKey: quantumKey,
	}

	agent2 := &AutonomousAgent{
		ID:         "agent2",
		Owner:      "Bob",
		Code:       "SmartContractCode2",
		State:      "Initialized",
		QuantumKey: quantumKey,
	}

	blockchain.RegisterAgent(agent1)
	blockchain.RegisterAgent(agent2)

	if len(blockchain.Agents) != 2 {
		t.Fatalf("Expected 2 agents, got %d", len(blockchain.Agents))
	}

	if err := blockchain.ExecuteAgent("agent1"); err != nil {
		t.Fatalf("Failed to execute agent1: %v", err)
	}

	if agent1.State != "Executed" {
		t.Fatalf("Expected agent1 state to be 'Executed', got %s", agent1.State)
	}

	transaction := "SampleTransactionData"
	signature, err := blockchain.SignTransaction("agent1", transaction)
	if err != nil {
		t.Fatalf("Failed to sign transaction: %v", err)
	}

	if !blockchain.ValidateAgentTransaction("agent1", transaction, signature) {
		t.Fatalf("Transaction validation failed")
	}

	exchangedKey, err := blockchain.QuantumKeyExchange("agent1", "agent2")
	if err != nil {
		t.Fatalf("Failed to exchange quantum keys: %v", err)
	}

	expectedExchangedKey := quantumKey + quantumKey
	if exchangedKey != expectedExchangedKey {
		t.Fatalf("Expected exchanged key %s, got %s", expectedExchangedKey, exchangedKey)
	}
}

// TestGenerateQuantumKey tests the GenerateQuantumKey function.
func TestGenerateQuantumKey(t *testing.T) {
	salt := []byte("test_salt")
	password := "test_password"
	key, err := GenerateQuantumKey(password, salt)
	if err != nil {
		t.Fatalf("Failed to generate quantum key: %v", err)
	}

	if len(key) == 0 {
		t.Fatalf("Expected non-empty key")
	}

	hash := sha256.Sum256([]byte(password + string(salt)))
	expectedKey := hex.EncodeToString(hash[:])
	if key == expectedKey {
		t.Fatalf("Generated key should not be the same as the expected non-quantum key")
	}
}

// TestSignTransaction tests the SignTransaction function.
func TestSignTransaction(t *testing.T) {
	salt := []byte("test_salt")
	quantumKey, err := GenerateQuantumKey("test_password", salt)
	if err != nil {
		t.Fatalf("Failed to generate quantum key: %v", err)
	}

	blockchain := NewQuantumSecureBlockchain()

	agent := &AutonomousAgent{
		ID:         "agent1",
		Owner:      "Alice",
		Code:       "SmartContractCode1",
		State:      "Initialized",
		QuantumKey: quantumKey,
	}

	blockchain.RegisterAgent(agent)

	transaction := "SampleTransactionData"
	signature, err := blockchain.SignTransaction("agent1", transaction)
	if err != nil {
		t.Fatalf("Failed to sign transaction: %v", err)
	}

	hash := sha256.Sum256([]byte(transaction))
	expectedSignature := hex.EncodeToString(hash[:])
	if signature != expectedSignature {
		t.Fatalf("Expected signature %s, got %s", expectedSignature, signature)
	}
}

// TestExecuteAgent tests the ExecuteAgent function.
func TestExecuteAgent(t *testing.T) {
	salt := []byte("test_salt")
	quantumKey, err := GenerateQuantumKey("test_password", salt)
	if err != nil {
		t.Fatalf("Failed to generate quantum key: %v", err)
	}

	blockchain := NewQuantumSecureBlockchain()

	agent := &AutonomousAgent{
		ID:         "agent1",
		Owner:      "Alice",
		Code:       "SmartContractCode1",
		State:      "Initialized",
		QuantumKey: quantumKey,
	}

	blockchain.RegisterAgent(agent)

	if err := blockchain.ExecuteAgent("agent1"); err != nil {
		t.Fatalf("Failed to execute agent: %v", err)
	}

	if agent.State != "Executed" {
		t.Fatalf("Expected agent state to be 'Executed', got %s", agent.State)
	}
}

// TestQuantumKeyExchange tests the QuantumKeyExchange function.
func TestQuantumKeyExchange(t *testing.T) {
	salt := []byte("test_salt")
	quantumKey1, err := GenerateQuantumKey("password1", salt)
	if err != nil {
		t.Fatalf("Failed to generate quantum key1: %v", err)
	}

	quantumKey2, err := GenerateQuantumKey("password2", salt)
	if err != nil {
		t.Fatalf("Failed to generate quantum key2: %v", err)
	}

	blockchain := NewQuantumSecureBlockchain()

	agent1 := &AutonomousAgent{
		ID:         "agent1",
		Owner:      "Alice",
		Code:       "SmartContractCode1",
		State:      "Initialized",
		QuantumKey: quantumKey1,
	}

	agent2 := &AutonomousAgent{
		ID:         "agent2",
		Owner:      "Bob",
		Code:       "SmartContractCode2",
		State:      "Initialized",
		QuantumKey: quantumKey2,
	}

	blockchain.RegisterAgent(agent1)
	blockchain.RegisterAgent(agent2)

	exchangedKey, err := blockchain.QuantumKeyExchange("agent1", "agent2")
	if err != nil {
		t.Fatalf("Failed to exchange quantum keys: %v", err)
	}

	expectedExchangedKey := quantumKey1 + quantumKey2
	if exchangedKey != expectedExchangedKey {
		t.Fatalf("Expected exchanged key %s, got %s", expectedExchangedKey, exchangedKey)
	}
}

func main() {
	salt := []byte("some_random_salt")
	quantumKey, err := GenerateQuantumKey("super_secret_password", salt)
	if err != nil {
		log.Fatalf("Failed to generate quantum key: %v", err)
	}

	blockchain := NewQuantumSecureBlockchain()

	agent1 := &AutonomousAgent{
		ID:         "agent1",
		Owner:      "Alice",
		Code:       "SmartContractCode1",
		State:      "Initialized",
		QuantumKey: quantumKey,
	}

	agent2 := &AutonomousAgent{
		ID:         "agent2",
		Owner:      "Bob",
		Code:       "SmartContractCode2",
		State:      "Initialized",
		QuantumKey: quantumKey,
	}

	blockchain.RegisterAgent(agent1)
	blockchain.RegisterAgent(agent2)

	if err := blockchain.ExecuteAgent("agent1"); err != nil {
		log.Fatalf("Failed to execute agent1: %v", err)
	}

	transaction := "SampleTransactionData"
	signature, err := blockchain.SignTransaction("agent1", transaction)
	if err != nil {
		log.Fatalf("Failed to sign transaction: %v", err)
	}

	if blockchain.ValidateAgentTransaction("agent1", transaction, signature) {
		log.Println("Transaction validated successfully.")
	} else {
		log.Println("Transaction validation failed.")
	}

	exchangedKey, err := blockchain.QuantumKeyExchange("agent1", "agent2")
	if err != nil {
		log.Fatalf("Failed to exchange quantum keys: %v", err)
	}
	log.Printf("Quantum key exchanged: %s", exchangedKey)
}
