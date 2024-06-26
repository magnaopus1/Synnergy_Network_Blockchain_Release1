package zero_knowledge_proof_node_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/synnergy_network/zero_knowledge_proof_node"
)

func TestZeroKnowledgeProofNode_ProofGeneration(t *testing.T) {
	node := zero_knowledge_proof_node.NewZeroKnowledgeProofNode()
	node.SetProofGenerationFunction(zero_knowledge_proof_node.ProofGenerationFunction)

	transactionData := map[string]interface{}{
		"sender":    "Alice",
		"recipient": "Bob",
		"amount":    100,
	}

	proof, err := node.GenerateProof(transactionData)
	assert.NoError(t, err, "Proof generation should not produce an error")
	assert.NotNil(t, proof, "Proof should not be nil")
}

func TestZeroKnowledgeProofNode_ProofVerification(t *testing.T) {
	node := zero_knowledge_proof_node.NewZeroKnowledgeProofNode()
	node.SetProofGenerationFunction(zero_knowledge_proof_node.ProofGenerationFunction)
	node.SetProofVerificationFunction(zero_knowledge_proof_node.ProofVerificationFunction)

	transactionData := map[string]interface{}{
		"sender":    "Alice",
		"recipient": "Bob",
		"amount":    100,
	}

	proof, err := node.GenerateProof(transactionData)
	assert.NoError(t, err, "Proof generation should not produce an error")

	valid, err := node.VerifyProof(proof, transactionData)
	assert.NoError(t, err, "Proof verification should not produce an error")
	assert.True(t, valid, "Proof should be valid")
}

func TestZeroKnowledgeProofNode_InvalidProofVerification(t *testing.T) {
	node := zero_knowledge_proof_node.NewZeroKnowledgeProofNode()
	node.SetProofGenerationFunction(zero_knowledge_proof_node.ProofGenerationFunction)
	node.SetProofVerificationFunction(zero_knowledge_proof_node.ProofVerificationFunction)

	transactionData := map[string]interface{}{
		"sender":    "Alice",
		"recipient": "Bob",
		"amount":    100,
	}

	invalidTransactionData := map[string]interface{}{
		"sender":    "Alice",
		"recipient": "Charlie",
		"amount":    100,
	}

	proof, err := node.GenerateProof(transactionData)
	assert.NoError(t, err, "Proof generation should not produce an error")

	valid, err := node.VerifyProof(proof, invalidTransactionData)
	assert.NoError(t, err, "Proof verification should not produce an error")
	assert.False(t, valid, "Proof should be invalid for incorrect transaction data")
}

func TestZeroKnowledgeProofNode_Concurrency(t *testing.T) {
	node := zero_knowledge_proof_node.NewZeroKnowledgeProofNode()
	node.SetProofGenerationFunction(zero_knowledge_proof_node.ProofGenerationFunction)
	node.SetProofVerificationFunction(zero_knowledge_proof_node.ProofVerificationFunction)

	transactionData1 := map[string]interface{}{
		"sender":    "Alice",
		"recipient": "Bob",
		"amount":    100,
	}

	transactionData2 := map[string]interface{}{
		"sender":    "Charlie",
		"recipient": "Dave",
		"amount":    200,
	}

	var proof1, proof2 []byte
	var err1, err2 error
	done := make(chan bool)

	go func() {
		proof1, err1 = node.GenerateProof(transactionData1)
		done <- true
	}()

	go func() {
		proof2, err2 = node.GenerateProof(transactionData2)
		done <- true
	}()

	<-done
	<-done

	assert.NoError(t, err1, "Proof generation for transactionData1 should not produce an error")
	assert.NoError(t, err2, "Proof generation for transactionData2 should not produce an error")
	assert.NotNil(t, proof1, "Proof1 should not be nil")
	assert.NotNil(t, proof2, "Proof2 should not be nil")

	valid1, err := node.VerifyProof(proof1, transactionData1)
	assert.NoError(t, err, "Proof verification for transactionData1 should not produce an error")
	assert.True(t, valid1, "Proof1 should be valid")

	valid2, err := node.VerifyProof(proof2, transactionData2)
	assert.NoError(t, err, "Proof verification for transactionData2 should not produce an error")
	assert.True(t, valid2, "Proof2 should be valid")
}

func TestZeroKnowledgeProofNode_ProofStorage(t *testing.T) {
	node := zero_knowledge_proof_node.NewZeroKnowledgeProofNode()
	node.SetProofGenerationFunction(zero_knowledge_proof_node.ProofGenerationFunction)

	transactionData := map[string]interface{}{
		"sender":    "Alice",
		"recipient": "Bob",
		"amount":    100,
	}

	proof, err := node.GenerateProof(transactionData)
	assert.NoError(t, err, "Proof generation should not produce an error")
	assert.NotNil(t, proof, "Proof should not be nil")

	storedProof, exists := node.GetProof(generateProofID(transactionData))
	assert.True(t, exists, "Proof should be stored")
	assert.Equal(t, proof, storedProof, "Stored proof should match the generated proof")
}

func TestZeroKnowledgeProofNode_ProofGenerationTimeout(t *testing.T) {
	node := zero_knowledge_proof_node.NewZeroKnowledgeProofNode()
	node.SetProofGenerationFunction(func(data interface{}) ([]byte, error) {
		time.Sleep(2 * time.Second) // Simulate long proof generation
		return zero_knowledge_proof_node.ProofGenerationFunction(data)
	})

	transactionData := map[string]interface{}{
		"sender":    "Alice",
		"recipient": "Bob",
		"amount":    100,
	}

	done := make(chan bool)
	var err error
	go func() {
		_, err = node.GenerateProof(transactionData)
		done <- true
	}()

	select {
	case <-done:
		assert.NoError(t, err, "Proof generation should not produce an error despite the delay")
	case <-time.After(1 * time.Second):
		t.Error("Proof generation should not time out")
	}
}
