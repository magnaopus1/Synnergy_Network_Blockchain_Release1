package node_registration

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"time"

	"github.com/synthron_blockchain_final/pkg/layer0/node_management/node_discovery"
	"github.com/synthron_blockchain_final/pkg/layer0/node_management/node_health_check"
	"github.com/synthron_blockchain_final/pkg/layer0/node_management/proof_of_work_challenge"
	"github.com/synthron_blockchain_final/pkg/layer0/node_management/dynamic_registration"
	"github.com/synthron_blockchain_final/pkg/layer0/node_management/identity_verification"
)

type NodeRegistration struct {
	discovery         *node_discovery.NodeDiscovery
	healthCheck       *node_health_check.NodeHealthCheck
	powChallenge      *proof_of_work_challenge.PoWChallenge
	dynamicThresholds *dynamic_registration.DynamicRegistrationThresholds
	identityVerifier  *identity_verification.IdentityVerification
}

type Node struct {
	ID            string
	PublicKey     *ecdsa.PublicKey
	JoinedAt      time.Time
	Blockchain    []Block
	HealthMetrics node_health_check.NodeHealthMetrics
}

type Block struct {
	Index     int
	Timestamp string
	Data      string
	Hash      string
	PrevHash  string
}

func NewNodeRegistration(discovery *node_discovery.NodeDiscovery, healthCheck *node_health_check.NodeHealthCheck, powChallenge *proof_of_work_challenge.PoWChallenge, dynamicThresholds *dynamic_registration.DynamicRegistrationThresholds, identityVerifier *identity_verification.IdentityVerification) *NodeRegistration {
	return &NodeRegistration{
		discovery:         discovery,
		healthCheck:       healthCheck,
		powChallenge:      powChallenge,
		dynamicThresholds: dynamicThresholds,
		identityVerifier:  identityVerifier,
	}
}

func (nr *NodeRegistration) RegisterNode(nodeID string, publicKey *ecdsa.PublicKey) error {
	// Identity Verification
	if err := nr.identityVerifier.VerifyNodeIdentity(nodeID, publicKey); err != nil {
		return fmt.Errorf("identity verification failed: %v", err)
	}

	// Proof of Work Challenge
	if err := nr.powChallenge.SolvePoWChallenge(nodeID); err != nil {
		return fmt.Errorf("proof of work challenge failed: %v", err)
	}

	// Dynamic Registration Thresholds
	if err := nr.dynamicThresholds.AdjustThresholds(); err != nil {
		return fmt.Errorf("dynamic threshold adjustment failed: %v", err)
	}

	// Bootstrap the node
	if err := nr.discovery.BootstrapNode(nodeID); err != nil {
		return fmt.Errorf("node bootstrapping failed: %v", err)
	}

	// Initialize Node
	node := &Node{
		ID:         nodeID,
		PublicKey:  publicKey,
		JoinedAt:   time.Now(),
		Blockchain: []Block{},
	}

	// Sync Blockchain Data
	if err := nr.syncBlockchainData(node); err != nil {
		return fmt.Errorf("blockchain data sync failed: %v", err)
	}

	// Add to Node Discovery
	nr.discovery.AddNode(nodeID)

	return nil
}

func (nr *NodeRegistration) syncBlockchainData(node *Node) error {
	peers := nr.discovery.GetPeers(node.ID)
	if len(peers) == 0 {
		return errors.New("no peers found for synchronization")
	}

	latestBlockchain := nr.getLatestBlockchainFromPeers(peers)
	if latestBlockchain == nil {
		return errors.New("failed to get blockchain from peers")
	}

	node.Blockchain = latestBlockchain
	return nil
}

func (nr *NodeRegistration) getLatestBlockchainFromPeers(peers []string) []Block {
	var latestBlockchain []Block

	for _, peer := range peers {
		peerData, err := nr.fetchBlockchainFromPeer(peer)
		if err != nil {
			fmt.Printf("Failed to fetch blockchain from peer %s: %v\n", peer, err)
			continue
		}

		if len(peerData) > len(latestBlockchain) {
			latestBlockchain = peerData
		}
	}

	return latestBlockchain
}

func (nr *NodeRegistration) fetchBlockchainFromPeer(peerID string) ([]Block, error) {
	// Simulate fetching blockchain data from peer
	// In a real-world scenario, this would involve network calls to the peer node
	return []Block{
		{Index: 1, Timestamp: "2022-01-01T00:00:00Z", Data: "Genesis Block", Hash: "abcd1234", PrevHash: ""},
		{Index: 2, Timestamp: "2022-01-02T00:00:00Z", Data: "Block 2", Hash: "efgh5678", PrevHash: "abcd1234"},
	}, nil
}

func (nr *NodeRegistration) DisplayNodeData(nodeID string) {
	node, err := nr.discovery.GetNode(nodeID)
	if err != nil {
		fmt.Printf("Node %s not found\n", nodeID)
		return
	}

	fmt.Printf("Node ID: %s\n", nodeID)
	fmt.Printf("Blockchain Length: %d\n", len(node.Blockchain))
	fmt.Printf("Joined At: %s\n", node.JoinedAt)
	fmt.Printf("Health Stats: %+v\n", node.HealthMetrics)
}

// Main function to demonstrate the process
func main() {
	discovery := node_discovery.NewNodeDiscovery()
	healthCheck := node_health_check.NewNodeHealthCheck()
	powChallenge := proof_of_work_challenge.NewPoWChallenge()
	dynamicThresholds := dynamic_registration.NewDynamicRegistrationThresholds()
	identityVerifier := identity_verification.NewIdentityVerification()

	nodeRegistration := NewNodeRegistration(discovery, healthCheck, powChallenge, dynamicThresholds, identityVerifier)
	nodeID := "node123"
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		fmt.Printf("Error generating key: %v\n", err)
		return
	}
	publicKey := &privateKey.PublicKey

	err = nodeRegistration.RegisterNode(nodeID, publicKey)
	if err != nil {
		fmt.Printf("Error registering node: %v\n", err)
		return
	}

	nodeRegistration.DisplayNodeData(nodeID)
}
