package validator_node

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Mock data for testing
var (
	testTransaction = []byte("testTransaction")
	testSignature   = []byte("testSignature")
	testBlock       = Block{
		Transactions: [][]byte{testTransaction},
		PrevHash:     []byte("prevHash"),
		Timestamp:    time.Now().Unix(),
	}
)

// Helper function to create a random transaction
func createRandomTransaction() []byte {
	tx := make([]byte, 256)
	_, err := rand.Read(tx)
	if err != nil {
		panic("failed to create random transaction")
	}
	return tx
}

// TestValidatorNode_ValidateTransaction tests the transaction validation logic
func TestValidatorNode_ValidateTransaction(t *testing.T) {
	node := NewValidatorNode()

	// Test valid transaction
	err := node.ValidateTransaction(testTransaction, testSignature)
	assert.NoError(t, err, "Valid transaction should not return an error")

	// Test invalid transaction
	invalidTx := createRandomTransaction()
	err = node.ValidateTransaction(invalidTx, []byte("invalidSignature"))
	assert.Error(t, err, "Invalid transaction should return an error")
}

// TestValidatorNode_CreateBlock tests the block creation logic
func TestValidatorNode_CreateBlock(t *testing.T) {
	node := NewValidatorNode()

	// Test block creation with valid transactions
	block, err := node.CreateBlock([][]byte{testTransaction})
	require.NoError(t, err, "Block creation should not return an error")
	assert.NotNil(t, block, "Block should be created")

	// Validate block fields
	assert.Equal(t, 1, len(block.Transactions), "Block should contain one transaction")
	assert.Equal(t, []byte("prevHash"), block.PrevHash, "Block previous hash should be 'prevHash'")
	assert.Less(t, block.Timestamp, time.Now().Unix()+1, "Block timestamp should be less than the current time")
}

// TestValidatorNode_PropagateBlock tests the block propagation logic
func TestValidatorNode_PropagateBlock(t *testing.T) {
	node := NewValidatorNode()
	peerNode := NewValidatorNode()

	// Simulate adding peer to node
	node.AddPeer(peerNode)

	// Test block propagation
	err := node.PropagateBlock(&testBlock)
	assert.NoError(t, err, "Block propagation should not return an error")

	// Validate peer received the block
	receivedBlock := peerNode.GetLastReceivedBlock()
	require.NotNil(t, receivedBlock, "Peer should receive the propagated block")
	assert.True(t, bytes.Equal(receivedBlock.Hash, testBlock.Hash), "Propagated block hash should match")
}

// TestValidatorNode_Consensus tests the consensus building logic
func TestValidatorNode_Consensus(t *testing.T) {
	node := NewValidatorNode()
	peerNode1 := NewValidatorNode()
	peerNode2 := NewValidatorNode()

	// Simulate adding peers
	node.AddPeer(peerNode1)
	node.AddPeer(peerNode2)

	// Test consensus voting
	blockHash := hex.EncodeToString(testBlock.Hash)
	err := node.VoteOnBlock(blockHash)
	assert.NoError(t, err, "Voting on block should not return an error")

	// Validate consensus state
	assert.True(t, node.HasReachedConsensus(blockHash), "Node should reach consensus on the block")
	assert.True(t, peerNode1.HasReachedConsensus(blockHash), "Peer 1 should reach consensus on the block")
	assert.True(t, peerNode2.HasReachedConsensus(blockHash), "Peer 2 should reach consensus on the block")
}

// TestValidatorNode_Security tests the security configurations and encryption mechanisms
func TestValidatorNode_Security(t *testing.T) {
	node := NewValidatorNode()

	// Test TLS encryption
	err := node.SetupTLS("/path/to/cert.pem", "/path/to/key.pem")
	assert.NoError(t, err, "Setting up TLS should not return an error")

	// Test multi-factor authentication
	err = node.SetupMFA("your_mfa_secret_here")
	assert.NoError(t, err, "Setting up MFA should not return an error")

	// Test data encryption
	plaintext := []byte("testData")
	ciphertext, err := node.EncryptData(plaintext)
	assert.NoError(t, err, "Encrypting data should not return an error")

	decryptedData, err := node.DecryptData(ciphertext)
	assert.NoError(t, err, "Decrypting data should not return an error")
	assert.True(t, bytes.Equal(plaintext, decryptedData), "Decrypted data should match the original plaintext")
}

// TestValidatorNode_BackupAndRecovery tests the backup and data recovery mechanisms
func TestValidatorNode_BackupAndRecovery(t *testing.T) {
	node := NewValidatorNode()

	// Test data backup
	err := node.BackupData("/path/to/backup")
	assert.NoError(t, err, "Backing up data should not return an error")

	// Simulate data loss
	node.DataStore = nil

	// Test data recovery
	err = node.RecoverData("/path/to/backup")
	assert.NoError(t, err, "Recovering data should not return an error")
	assert.NotNil(t, node.DataStore, "Data store should be restored")
}

// TestValidatorNode_RewardDistribution tests the reward distribution logic
func TestValidatorNode_RewardDistribution(t *testing.T) {
	node := NewValidatorNode()

	// Simulate staking and reward calculation
	node.StakeAmount = 1000000
	node.CalculateReward()

	// Validate rewards
	assert.Equal(t, 100, node.Reward, "Reward should be correctly calculated based on the stake amount and network parameters")
}

// TestValidatorNode_PerformanceOptimization tests performance tuning and optimization settings
func TestValidatorNode_PerformanceOptimization(t *testing.T) {
	node := NewValidatorNode()

	// Test performance tuning
	err := node.OptimizeNodePerformance()
	assert.NoError(t, err, "Optimizing node performance should not return an error")

	// Validate cache settings
	assert.Equal(t, 100000, node.CacheSettings.MaxItems, "Cache max items should be set correctly")
	assert.Equal(t, 10*time.Minute, node.CacheSettings.ExpirationTime, "Cache expiration time should be set correctly")
}

// TestValidatorNode_GovernanceParticipation tests the governance participation functionality
func TestValidatorNode_GovernanceParticipation(t *testing.T) {
	node := NewValidatorNode()

	// Simulate governance voting
	err := node.ParticipateInGovernance("proposalID")
	assert.NoError(t, err, "Participating in governance should not return an error")

	// Validate governance state
	assert.True(t, node.HasVotedOnProposal("proposalID"), "Node should have voted on the governance proposal")
}
