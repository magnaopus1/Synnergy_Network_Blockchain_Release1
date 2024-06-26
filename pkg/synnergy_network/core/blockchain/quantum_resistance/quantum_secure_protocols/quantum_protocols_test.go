package quantum_secure_protocols

import (
	"crypto/sha256"
	"encoding/hex"
	"math/big"
	"testing"
	"time"
	"crypto/rand"
)

// TestBlockchain tests the creation and validation of a blockchain.
func TestBlockchain(t *testing.T) {
	nodes := []Node{
		{ID: "node1", Weight: 1},
		{ID: "node2", Weight: 2},
		{ID: "node3", Weight: 3},
	}

	blockchain := NewBlockchain(nodes)

	transactions := []Transaction{
		{ID: "1", Timestamp: time.Now(), Sender: "Alice", Receiver: "Bob", Amount: 1.0, Signature: "AliceSignature"},
		{ID: "2", Timestamp: time.Now(), Sender: "Bob", Receiver: "Charlie", Amount: 0.5, Signature: "BobSignature"},
	}
	if err := blockchain.AddBlock(transactions); err != nil {
		t.Fatalf("Failed to add block: %v", err)
	}

	if !blockchain.ValidateChain() {
		t.Error("Blockchain is invalid.")
	}
}

// TestEnhancedConsensusAlgorithm tests the quantum-resistant consensus mechanism.
func TestEnhancedConsensusAlgorithm(t *testing.T) {
	nodes := []Node{
		{ID: "node1", Weight: 1},
		{ID: "node2", Weight: 2},
		{ID: "node3", Weight: 3},
	}

	qrns := &QuantumRandomNumberService{}
	eca := NewEnhancedConsensusAlgorithm(nodes, qrns)

	leader, err := eca.SelectLeader()
	if err != nil {
		t.Fatalf("Failed to select leader: %v", err)
	}
	t.Logf("Leader selected: %s", leader.ID)

	rounds := 10
	leaders, err := eca.SimulateConsensus(rounds)
	if err != nil {
		t.Fatalf("Failed to simulate consensus: %v", err)
	}

	if len(leaders) != rounds {
		t.Errorf("Expected %d leaders, got %d", rounds, len(leaders))
	}
}

// TestQuantumRandomNumberService tests the quantum random number generation.
func TestQuantumRandomNumberService(t *testing.T) {
	qrns := &QuantumRandomNumberService{}
	max := int64(100)
	randomNumber, err := qrns.GenerateRandomNumber(max)
	if err != nil {
		t.Fatalf("Failed to generate random number: %v", err)
	}

	if randomNumber < 0 || randomNumber >= max {
		t.Errorf("Random number out of range: %d", randomNumber)
	}
}

// TestTransactionValidation tests the validation of transactions using quantum-resistant signatures.
func TestTransactionValidation(t *testing.T) {
	nodes := []Node{
		{ID: "node1", Weight: 1},
		{ID: "node2", Weight: 2},
		{ID: "node3", Weight: 3},
	}

	transaction := "SampleTransactionData"
	signatures := []Signature{
		SignTransaction(transaction, nodes[0]),
		SignTransaction(transaction, nodes[1]),
	}

	if !ValidateTransaction(transaction, signatures) {
		t.Error("Transaction validation failed.")
	}
}

// TestSignAndVerifySignature tests the signing and verification of transactions.
func TestSignAndVerifySignature(t *testing.T) {
	node := Node{ID: "node1", Weight: 1}
	transaction := "SampleTransactionData"

	signature := SignTransaction(transaction, node)
	if !VerifySignature(transaction, signature) {
		t.Error("Signature verification failed.")
	}
}

// calculateHash calculates the hash of a block.
func calculateHash(block Block) string {
	blockData := fmt.Sprintf("%d%s%v%s%d", block.Index, block.Timestamp, block.Transactions, block.PrevHash, block.Nonce)
	hash := sha256.Sum256([]byte(blockData))
	return hex.EncodeToString(hash[:])
}

// GenerateRandomNumber generates a quantum-resistant random number.
func (qrns *QuantumRandomNumberService) GenerateRandomNumber(max int64) (int64, error) {
	if max <= 0 {
		return 0, errors.New("max must be greater than 0")
	}
	n, err := rand.Int(rand.Reader, big.NewInt(max))
	if err != nil {
		return 0, err
	}
	return n.Int64(), nil
}

// SignTransaction signs a transaction with a quantum-resistant signature.
func SignTransaction(transaction string, signer Node) Signature {
	// Placeholder for quantum-resistant signature
	signature := Signature{
		SignerID: signer.ID,
		Signature: "QuantumResistantSignaturePlaceholder",
	}
	return signature
}

// VerifySignature verifies a quantum-resistant signature.
func VerifySignature(transaction string, signature Signature) bool {
	// Placeholder for quantum-resistant signature verification
	return signature.Signature == "QuantumResistantSignaturePlaceholder"
}

// ValidateTransaction validates a transaction with quantum-resistant signature.
func ValidateTransaction(transaction string, signatures []Signature) bool {
	for _, signature := range signatures {
		if !VerifySignature(transaction, signature) {
			return false
		}
	}
	return true
}

func main() {
	nodes := []Node{
		{ID: "node1", Weight: 1},
		{ID: "node2", Weight: 2},
		{ID: "node3", Weight: 3},
	}

	qrns := &QuantumRandomNumberService{}
	eca := NewEnhancedConsensusAlgorithm(nodes, qrns)
	blockchain := NewBlockchain(eca.Nodes)

	transactions := []Transaction{
		{ID: "1", Timestamp: time.Now(), Sender: "Alice", Receiver: "Bob", Amount: 1.0, Signature: "AliceSignature"},
		{ID: "2", Timestamp: time.Now(), Sender: "Bob", Receiver: "Charlie", Amount: 0.5, Signature: "BobSignature"},
	}
	if err := blockchain.AddBlock(transactions); err != nil {
		log.Fatalf("Failed to add block: %v", err)
	}

	if blockchain.ValidateChain() {
		log.Println("Blockchain is valid.")
	} else {
		log.Println("Blockchain is invalid.")
	}

	leader, err := eca.SelectLeader()
	if err != nil {
		log.Fatalf("Failed to select leader: %v", err)
	}
	log.Printf("Leader selected: %s", leader.ID)
}
