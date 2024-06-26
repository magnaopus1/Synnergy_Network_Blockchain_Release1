package mining_node

import (
	"testing"
	"time"
	"math/big"
	"github.com/stretchr/testify/assert"
)

func TestInitializeNode(t *testing.T) {
	node := NewMiningNode()
	err := node.Initialize()
	assert.Nil(t, err, "Node initialization should not produce an error")
	assert.NotNil(t, node.Blockchain, "Blockchain should be initialized")
	assert.NotNil(t, node.Network, "Network should be initialized")
}

func TestSolvePuzzle(t *testing.T) {
	node := NewMiningNode()
	err := node.Initialize()
	assert.Nil(t, err, "Node initialization should not produce an error")

	// Create a mock block with a simple puzzle
	block := Block{
		PreviousHash: "0000000000000000000",
		Data:         "test data",
		Difficulty:   1,
		Nonce:        0,
	}

	startTime := time.Now()
	err = node.SolvePuzzle(&block)
	duration := time.Since(startTime)

	assert.Nil(t, err, "Solving puzzle should not produce an error")
	assert.True(t, block.Nonce > 0, "Nonce should be greater than 0 after solving puzzle")
	assert.True(t, duration.Seconds() < 60, "Puzzle should be solved in under 60 seconds")
}

func TestValidateTransaction(t *testing.T) {
	node := NewMiningNode()
	err := node.Initialize()
	assert.Nil(t, err, "Node initialization should not produce an error")

	// Create a mock transaction
	tx := Transaction{
		From:   "address1",
		To:     "address2",
		Amount: big.NewInt(100),
		Fee:    big.NewInt(1),
		Nonce:  1,
	}

	err = node.ValidateTransaction(tx)
	assert.Nil(t, err, "Valid transaction should not produce an error")
}

func TestAddBlock(t *testing.T) {
	node := NewMiningNode()
	err := node.Initialize()
	assert.Nil(t, err, "Node initialization should not produce an error")

	// Create and solve a mock block
	block := Block{
		PreviousHash: "0000000000000000000",
		Data:         "test data",
		Difficulty:   1,
		Nonce:        0,
	}
	err = node.SolvePuzzle(&block)
	assert.Nil(t, err, "Solving puzzle should not produce an error")

	err = node.AddBlock(&block)
	assert.Nil(t, err, "Adding block should not produce an error")
	assert.Equal(t, node.Blockchain.LastBlock().Hash, block.Hash, "Last block hash should match the added block hash")
}

func TestNetworkSync(t *testing.T) {
	node := NewMiningNode()
	err := node.Initialize()
	assert.Nil(t, err, "Node initialization should not produce an error")

	// Mock network synchronization
	err = node.SyncNetwork()
	assert.Nil(t, err, "Network synchronization should not produce an error")
	assert.True(t, node.Network.IsSynchronized(), "Network should be synchronized")
}

func TestEconomicIncentives(t *testing.T) {
	node := NewMiningNode()
	err := node.Initialize()
	assert.Nil(t, err, "Node initialization should not produce an error")

	initialBalance := big.NewInt(1000)
	node.Wallet.SetBalance(initialBalance)

	// Simulate mining a block
	block := Block{
		PreviousHash: "0000000000000000000",
		Data:         "test data",
		Difficulty:   1,
		Nonce:        0,
		Reward:       big.NewInt(50),
	}
	err = node.SolvePuzzle(&block)
	assert.Nil(t, err, "Solving puzzle should not produce an error")

	err = node.AddBlock(&block)
	assert.Nil(t, err, "Adding block should not produce an error")

	expectedBalance := big.NewInt(1050)
	assert.Equal(t, expectedBalance, node.Wallet.GetBalance(), "Wallet balance should reflect block reward")
}

func TestSecurityProtocols(t *testing.T) {
	node := NewMiningNode()
	err := node.Initialize()
	assert.Nil(t, err, "Node initialization should not produce an error")

	// Mock security protocol check
	assert.True(t, node.Security.FirewallEnabled, "Firewall should be enabled")
	assert.True(t, node.Security.VPNEnabled, "VPN should be enabled")
	assert.True(t, node.Security.EncryptionEnabled, "Encryption should be enabled")
}
