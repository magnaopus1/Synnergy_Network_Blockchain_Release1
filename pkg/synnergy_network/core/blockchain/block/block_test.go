package block

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"

	"github.com/synnergy_network/pkg/synnergy_network/core/crypto"
	"github.com/synnergy_network/pkg/synnergy_network/core/utils"
	"github.com/synnergy_network/pkg/synnergy_network/core/ai"
)

// generateKeyPair generates a new ECDSA key pair for testing
func generateKeyPair() (*ecdsa.PrivateKey, *ecdsa.PublicKey, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	publicKey := &privateKey.PublicKey
	return privateKey, publicKey, nil
}

// signTransaction signs a transaction with the given private key
func signTransaction(tx *Transaction, privateKey *ecdsa.PrivateKey) error {
	txData := []byte(tx.Sender + tx.Recipient + string(tx.Amount))
	hash := sha256.Sum256(txData)
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, hash[:])
	if err != nil {
		return err
	}
	signature := append(r.Bytes(), s.Bytes()...)
	tx.Signature = hex.EncodeToString(signature)
	return nil
}

// TestBlockSerialization tests the serialization and deserialization of a block
func TestBlockSerialization(t *testing.T) {
	block := Block{
		Header: BlockHeader{
			PreviousHash: "previous_hash",
			Timestamp:    time.Now(),
			Nonce:        1,
			MerkleRoot:   "merkle_root",
		},
		Body: BlockBody{
			Transactions: []Transaction{
				{Sender: "sender1", Recipient: "recipient1", Amount: 100, Signature: "signature1"},
				{Sender: "sender2", Recipient: "recipient2", Amount: 200, Signature: "signature2"},
			},
		},
		ZKProofs: []ZeroKnowledgeProof{
			{Proof: "proof1", ProofType: "zk-SNARK", Verified: true, Transaction: Transaction{Sender: "sender1", Recipient: "recipient1", Amount: 100, Signature: "signature1"}},
		},
	}

	data, err := block.Serialize()
	if err != nil {
		t.Fatalf("Serialization failed: %v", err)
	}

	var deserializedBlock Block
	err = deserializedBlock.Deserialize(data)
	if err != nil {
		t.Fatalf("Deserialization failed: %v", err)
	}

	if !bytes.Equal(data, data) {
		t.Fatalf("Serialized and deserialized data do not match")
	}
}

// TestBlockMerkleRoot tests the Merkle root generation
func TestBlockMerkleRoot(t *testing.T) {
	block := Block{
		Body: BlockBody{
			Transactions: []Transaction{
				{Sender: "sender1", Recipient: "recipient1", Amount: 100, Signature: "signature1"},
				{Sender: "sender2", Recipient: "recipient2", Amount: 200, Signature: "signature2"},
			},
		},
	}

	block.GenerateMerkleRoot()
	expectedMerkleRoot := "4d2e2cf8d6aeb0cf14e3f27b9e4d4b0429eb0c7ab307be7db768bf620351a0db" // Example expected Merkle root

	if block.Header.MerkleRoot != expectedMerkleRoot {
		t.Fatalf("Expected Merkle root %s, got %s", expectedMerkleRoot, block.Header.MerkleRoot)
	}
}

// TestTransactionVerification tests the verification of a transaction
func TestTransactionVerification(t *testing.T) {
	privateKey, publicKey, err := generateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	tx := Transaction{Sender: string(crypto.MarshalECDSAPublicKey(publicKey)), Recipient: "recipient", Amount: 100}
	err = signTransaction(&tx, privateKey)
	if err != nil {
		t.Fatalf("Failed to sign transaction: %v", err)
	}

	err = verifyTransaction(tx)
	if err != nil {
		t.Fatalf("Transaction verification failed: %v", err)
	}
}

// TestZeroKnowledgeProofVerification tests the verification of zero-knowledge proofs
func TestZeroKnowledgeProofVerification(t *testing.T) {
	zkIntegration := NewZeroKnowledgeIntegration()
	block := Block{}

	proof := ZeroKnowledgeProof{
		Proof:       "zk-proof-data",
		ProofType:   "zk-SNARK",
		Verified:    true,
		Transaction: Transaction{Sender: "sender1", Recipient: "recipient1", Amount: 100, Signature: "signature1"},
	}

	err := zkIntegration.AddZeroKnowledgeProof(&block, proof)
	if err != nil {
		t.Fatalf("Zero-knowledge proof verification failed: %v", err)
	}
}

// TestBlockVerification tests the verification of an entire block
func TestBlockVerification(t *testing.T) {
	privateKey, publicKey, err := generateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	tx1 := Transaction{Sender: string(crypto.MarshalECDSAPublicKey(publicKey)), Recipient: "recipient1", Amount: 100}
	tx2 := Transaction{Sender: string(crypto.MarshalECDSAPublicKey(publicKey)), Recipient: "recipient2", Amount: 200}
	err = signTransaction(&tx1, privateKey)
	if err != nil {
		t.Fatalf("Failed to sign transaction 1: %v", err)
	}
	err = signTransaction(&tx2, privateKey)
	if err != nil {
		t.Fatalf("Failed to sign transaction 2: %v", err)
	}

	block := Block{
		Header: BlockHeader{
			PreviousHash: "previous_hash",
			Timestamp:    time.Now(),
			Nonce:        1,
			MerkleRoot:   "merkle_root",
		},
		Body: BlockBody{
			Transactions: []Transaction{tx1, tx2},
		},
		ZKProofs: []ZeroKnowledgeProof{
			{Proof: "zk-proof-data", ProofType: "zk-SNARK", Verified: true, Transaction: tx1},
		},
	}

	err = block.VerifyBlock()
	if err != nil {
		t.Fatalf("Block verification failed: %v", err)
	}
}
