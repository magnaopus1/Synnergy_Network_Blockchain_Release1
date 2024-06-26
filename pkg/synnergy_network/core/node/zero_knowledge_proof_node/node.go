package zero_knowledge_proof_node

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/gob"
	"errors"
	"fmt"
	"io"
	"log"
	"sync"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/scrypt"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/backend"
)

type ZeroKnowledgeProofNode struct {
	mu               sync.Mutex
	proofs           map[string][]byte
	proofGeneration  func(interface{}) ([]byte, error)
	proofVerification func([]byte, interface{}) (bool, error)
}

func NewZeroKnowledgeProofNode() *ZeroKnowledgeProofNode {
	return &ZeroKnowledgeProofNode{
		proofs: make(map[string][]byte),
	}
}

func (zkp *ZeroKnowledgeProofNode) GenerateProof(transactionData interface{}) ([]byte, error) {
	zkp.mu.Lock()
	defer zkp.mu.Unlock()

	if zkp.proofGeneration == nil {
		return nil, errors.New("proof generation function is not set")
	}

	proof, err := zkp.proofGeneration(transactionData)
	if err != nil {
		return nil, fmt.Errorf("failed to generate proof: %w", err)
	}

	proofID := generateProofID(transactionData)
	zkp.proofs[proofID] = proof
	return proof, nil
}

func (zkp *ZeroKnowledgeProofNode) VerifyProof(proof []byte, transactionData interface{}) (bool, error) {
	zkp.mu.Lock()
	defer zkp.mu.Unlock()

	if zkp.proofVerification == nil {
		return false, errors.New("proof verification function is not set")
	}

	valid, err := zkp.proofVerification(proof, transactionData)
	if err != nil {
		return false, fmt.Errorf("failed to verify proof: %w", err)
	}
	return valid, nil
}

func (zkp *ZeroKnowledgeProofNode) SetProofGenerationFunction(f func(interface{}) ([]byte, error)) {
	zkp.mu.Lock()
	defer zkp.mu.Unlock()
	zkp.proofGeneration = f
}

func (zkp *ZeroKnowledgeProofNode) SetProofVerificationFunction(f func([]byte, interface{}) (bool, error)) {
	zkp.mu.Lock()
	defer zkp.mu.Unlock()
	zkp.proofVerification = f
}

func generateProofID(transactionData interface{}) string {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	err := enc.Encode(transactionData)
	if err != nil {
		log.Fatalf("failed to generate proof ID: %v", err)
	}
	return fmt.Sprintf("%x", mimc.NewMiMC().Sum(buf.Bytes()))
}

func generateArgon2Key(password, salt []byte) ([]byte, error) {
	return argon2.IDKey(password, salt, 1, 64*1024, 4, 32), nil
}

func generateScryptKey(password, salt []byte) ([]byte, error) {
	key, err := scrypt.Key(password, salt, 16384, 8, 1, 32)
	if err != nil {
		return nil, fmt.Errorf("failed to generate scrypt key: %w", err)
	}
	return key, nil
}

func encryptAESGCM(plaintext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher block: %w", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM mode: %w", err)
	}

	nonce := make([]byte, aesGCM.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	ciphertext := aesGCM.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

func decryptAESGCM(ciphertext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher block: %w", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM mode: %w", err)
	}

	nonceSize := aesGCM.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt ciphertext: %w", err)
	}

	return plaintext, nil
}

func proofGenerationFunction(transactionData interface{}) ([]byte, error) {
	var circuit r1cs.CS
	builder := r1cs.NewBuilder()
	if err := builder.LoadFromCircuit(&circuit); err != nil {
		return nil, fmt.Errorf("failed to load circuit: %w", err)
	}

	// Mock data for the example
	assignment := map[string]interface{}{
		"transactionData": transactionData,
	}

	proof, err := backend.Groth16Prove(circuit, assignment)
	if err != nil {
		return nil, fmt.Errorf("failed to generate proof: %w", err)
	}

	return proof, nil
}

func proofVerificationFunction(proof []byte, transactionData interface{}) (bool, error) {
	var circuit r1cs.CS
	builder := r1cs.NewBuilder()
	if err := builder.LoadFromCircuit(&circuit); err != nil {
		return false, fmt.Errorf("failed to load circuit: %w", err)
	}

	// Mock data for the example
	assignment := map[string]interface{}{
		"transactionData": transactionData,
	}

	valid, err := backend.Groth16Verify(circuit, proof, assignment)
	if err != nil {
		return false, fmt.Errorf("failed to verify proof: %w", err)
	}

	return valid, nil
}

func main() {
	node := NewZeroKnowledgeProofNode()
	node.SetProofGenerationFunction(proofGenerationFunction)
	node.SetProofVerificationFunction(proofVerificationFunction)

	transactionData := map[string]interface{}{
		"sender":    "Alice",
		"recipient": "Bob",
		"amount":    100,
	}

	proof, err := node.GenerateProof(transactionData)
	if err != nil {
		log.Fatalf("failed to generate proof: %v", err)
	}

	valid, err := node.VerifyProof(proof, transactionData)
	if err != nil {
		log.Fatalf("failed to verify proof: %v", err)
	}

	fmt.Printf("Proof is valid: %v\n", valid)
}
