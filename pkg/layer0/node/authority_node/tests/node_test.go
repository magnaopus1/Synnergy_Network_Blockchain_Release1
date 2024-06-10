package authority_node

import (
	"testing"
	"time"
	"github.com/stretchr/testify/assert"
	"math/big"
	"net/http"
	_ "net/http/pprof"
)

// Mock types for testing
type MockBlockchain struct {
	blocks []*Block
}

type MockNetwork struct {
	nodes []Node
}

type MockGovernance struct {
	proposals []*Proposal
}

// Helper function to create a test authority node
func createTestNode() *AuthorityNode {
	return &AuthorityNode{
		NodeID:     "test-node",
		PrivateKey: generatePrivateKey(),
		Blockchain: &MockBlockchain{},
		Network:    &MockNetwork{},
		Governance: &MockGovernance{},
	}
}

func TestNodeInitialization(t *testing.T) {
	node := createTestNode()
	assert.NotNil(t, node, "Node should be initialized")
	assert.Equal(t, "test-node", node.NodeID, "Node ID should be 'test-node'")
	assert.NotNil(t, node.PrivateKey, "Node should have a private key")
	assert.NotNil(t, node.Blockchain, "Node should have a blockchain instance")
	assert.NotNil(t, node.Network, "Node should have a network instance")
	assert.NotNil(t, node.Governance, "Node should have a governance instance")
}

func TestBlockProduction(t *testing.T) {
	node := createTestNode()
	block := node.ProduceBlock()
	assert.NotNil(t, block, "Block should be produced")
	assert.Equal(t, 1, len(node.Blockchain.blocks), "Blockchain should contain one block")
}

func TestTransactionValidation(t *testing.T) {
	node := createTestNode()
	tx := Transaction{
		From:   "addr1",
		To:     "addr2",
		Amount: big.NewInt(100),
	}
	valid := node.ValidateTransaction(&tx)
	assert.True(t, valid, "Transaction should be valid")
}

func TestGovernanceParticipation(t *testing.T) {
	node := createTestNode()
	proposal := Proposal{
		ID:       "proposal1",
		Content:  "Increase block size",
		Deadline: time.Now().Add(24 * time.Hour),
	}
	node.SubmitProposal(&proposal)
	assert.Equal(t, 1, len(node.Governance.proposals), "There should be one proposal")
	assert.Equal(t, "proposal1", node.Governance.proposals[0].ID, "Proposal ID should be 'proposal1'")
}

func TestNetworkSynchronization(t *testing.T) {
	node := createTestNode()
	node2 := createTestNode()
	node.Network.nodes = append(node.Network.nodes, node2)
	node2.Network.nodes = append(node2.Network.nodes, node)

	block := node.ProduceBlock()
	node.BroadcastBlock(block)

	time.Sleep(1 * time.Second) // Give some time for synchronization

	assert.Equal(t, len(node.Blockchain.blocks), len(node2.Blockchain.blocks), "Both nodes should have the same number of blocks")
}

func TestNodePerformance(t *testing.T) {
	go func() {
		http.ListenAndServe("localhost:6060", nil)
	}()
	node := createTestNode()
	start := time.Now()
	for i := 0; i < 1000; i++ {
		node.ProduceBlock()
	}
	elapsed := time.Since(start)
	assert.Less(t, elapsed.Seconds(), 60.0, "Block production for 1000 blocks should take less than 60 seconds")
}

func TestSecurityFeatures(t *testing.T) {
	node := createTestNode()
	encryptedData, err := encryptData(node.PrivateKey, []byte("sensitive data"))
	assert.Nil(t, err, "Data should be encrypted without error")
	assert.NotNil(t, encryptedData, "Encrypted data should not be nil")

	decryptedData, err := decryptData(node.PrivateKey, encryptedData)
	assert.Nil(t, err, "Data should be decrypted without error")
	assert.Equal(t, "sensitive data", string(decryptedData), "Decrypted data should match original")
}

func TestBackupAndRecovery(t *testing.T) {
	node := createTestNode()
	backupData := node.Backup()
	assert.NotNil(t, backupData, "Backup data should not be nil")

	recoveredNode := RecoverNodeFromBackup(backupData)
	assert.NotNil(t, recoveredNode, "Recovered node should not be nil")
	assert.Equal(t, node.NodeID, recoveredNode.NodeID, "Recovered node ID should match original")
}
