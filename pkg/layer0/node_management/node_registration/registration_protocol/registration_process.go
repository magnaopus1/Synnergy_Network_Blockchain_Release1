package registration_protocol

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"log"
	"math/big"
	"sync"

	"github.com/synthron_blockchain_final/pkg/layer0/node_management/node_registration/identity_verification"
	"github.com/synthron_blockchain_final/pkg/layer0/node_management/node_registration/proof_of_work_challenge"
)

type NodeRegistration struct {
	mu              sync.Mutex
	registeredNodes map[string]*RegisteredNode
	powManager      *proof_of_work_challenge.PoWManager
}

type RegisteredNode struct {
	ID        string
	PublicKey *ecdsa.PublicKey
	Signature []byte
}

func NewNodeRegistration() *NodeRegistration {
	return &NodeRegistration{
		registeredNodes: make(map[string]*RegisteredNode),
		powManager:      proof_of_work_challenge.NewPoWManager(),
	}
}

func (nr *NodeRegistration) RegisterNode(nodeID string, publicKey *ecdsa.PublicKey, difficulty int) (*proof_of_work_challenge.PoWChallenge, error) {
	nr.mu.Lock()
	defer nr.mu.Unlock()

	if _, exists := nr.registeredNodes[nodeID]; exists {
		return nil, errors.New("node already registered")
	}

	// Create a new PoW challenge
	challenge, err := nr.powManager.CreateChallenge(nodeID, difficulty)
	if err != nil {
		return nil, err
	}

	return challenge, nil
}

func (nr *NodeRegistration) VerifyNodeRegistration(nodeID string, solution string, publicKey *ecdsa.PublicKey, signature []byte) error {
	nr.mu.Lock()
	defer nr.mu.Unlock()

	if _, exists := nr.registeredNodes[nodeID]; exists {
		return errors.New("node already registered")
	}

	if !nr.powManager.VerifySolution(nodeID, solution) {
		return errors.New("invalid PoW solution")
	}

	if !identity_verification.VerifyIdentity(nodeID, publicKey, signature) {
		return errors.New("identity verification failed")
	}

	nr.registeredNodes[nodeID] = &RegisteredNode{
		ID:        nodeID,
		PublicKey: publicKey,
		Signature: signature,
	}

	return nil
}

// SyncBlockchainData simulates blockchain data synchronization process for new nodes
func (nr *NodeRegistration) SyncBlockchainData(nodeID string) error {
	// Implement the actual data synchronization logic here
	// This could involve fetching the latest blockchain data from peers and verifying it
	fmt.Printf("Syncing blockchain data for node: %s\n", nodeID)
	return nil
}

// Helper function to sign data using a private key
func SignData(privateKey *ecdsa.PrivateKey, data []byte) ([]byte, error) {
	hash := sha256.Sum256(data)
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, hash[:])
	if err != nil {
		return nil, err
	}

	signature := append(r.Bytes(), s.Bytes()...)
	return signature, nil
}

// Example usage
func main() {
	nodeReg := NewNodeRegistration()
	nodeID := "node123"
	privateKey, err := ecdsa.GenerateKey(ecdsa.P256(), rand.Reader)
	if err != nil {
		log.Fatalf("Failed to generate key: %v", err)
	}

	difficulty := 20
	publicKey := &privateKey.PublicKey

	// Register a new node and get PoW challenge
	challenge, err := nodeReg.RegisterNode(nodeID, publicKey, difficulty)
	if err != nil {
		log.Fatalf("Failed to register node: %v", err)
	}

	// Solve the PoW challenge
	solution, err := challenge.Solve()
	if err != nil {
		log.Fatalf("Failed to solve PoW challenge: %v", err)
	}

	// Sign the node ID with the private key
	signature, err := SignData(privateKey, []byte(nodeID))
	if err != nil {
		log.Fatalf("Failed to sign data: %v", err)
	}

	// Verify and complete the registration
	err = nodeReg.VerifyNodeRegistration(nodeID, solution, publicKey, signature)
	if err != nil {
		log.Fatalf("Failed to verify node registration: %v", err)
	}

	// Sync blockchain data
	err = nodeReg.SyncBlockchainData(nodeID)
	if err != nil {
		log.Fatalf("Failed to sync blockchain data: %v", err)
	}

	fmt.Println("Node successfully registered and synchronized!")
}
