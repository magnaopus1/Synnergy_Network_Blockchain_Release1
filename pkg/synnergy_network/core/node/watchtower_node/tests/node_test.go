package tests

import (
	"testing"
	"github.com/stretchr/testify/assert"
	"github.com/synthron_blockchain/pkg/layer0/node/watchtower_node"
	"github.com/synthron_blockchain/pkg/layer0/node/utils"
)

func TestWatchtowerNodeInitialization(t *testing.T) {
	config := watchtower_node.Config{
		NodeName:   "synthron_watchtower",
		LogLevel:   "info",
		DataDir:    "/var/lib/synthron/watchtower/data",
		LogDir:     "/var/lib/synthron/watchtower/logs",
		Port:       8080,
	}
	node, err := watchtower_node.NewWatchtowerNode(config)
	assert.NoError(t, err)
	assert.NotNil(t, node)
}

func TestWatchtowerNodeStartStop(t *testing.T) {
	config := watchtower_node.Config{
		NodeName:   "synthron_watchtower",
		LogLevel:   "info",
		DataDir:    "/var/lib/synthron/watchtower/data",
		LogDir:     "/var/lib/synthron/watchtower/logs",
		Port:       8080,
	}
	node, err := watchtower_node.NewWatchtowerNode(config)
	assert.NoError(t, err)
	assert.NotNil(t, node)

	err = node.Start()
	assert.NoError(t, err)

	err = node.Stop()
	assert.NoError(t, err)
}

func TestContinuousMonitoring(t *testing.T) {
	config := watchtower_node.Config{
		NodeName:   "synthron_watchtower",
		LogLevel:   "info",
		DataDir:    "/var/lib/synthron/watchtower/data",
		LogDir:     "/var/lib/synthron/watchtower/logs",
		Port:       8080,
	}
	node, err := watchtower_node.NewWatchtowerNode(config)
	assert.NoError(t, err)
	assert.NotNil(t, node)

	go func() {
		err = node.Start()
		assert.NoError(t, err)
	}()

	utils.WaitForServerToStart("127.0.0.1", 8080, 5)

	transaction := utils.GenerateTestTransaction()
	err = utils.SendTransaction(transaction)
	assert.NoError(t, err)

	// Add your logic to check if the transaction is being monitored correctly
	// Example: Check logs or internal node status

	err = node.Stop()
	assert.NoError(t, err)
}

func TestSmartContractEnforcement(t *testing.T) {
	config := watchtower_node.Config{
		NodeName:   "synthron_watchtower",
		LogLevel:   "info",
		DataDir:    "/var/lib/synthron/watchtower/data",
		LogDir:     "/var/lib/synthron/watchtower/logs",
		Port:       8080,
	}
	node, err := watchtower_node.NewWatchtowerNode(config)
	assert.NoError(t, err)
	assert.NotNil(t, node)

	go func() {
		err = node.Start()
		assert.NoError(t, err)
	}()

	utils.WaitForServerToStart("127.0.0.1", 8080, 5)

	contract := utils.GenerateTestSmartContract()
	err = utils.DeploySmartContract(contract)
	assert.NoError(t, err)

	// Add your logic to verify smart contract enforcement
	// Example: Check logs or node status for contract enforcement

	err = node.Stop()
	assert.NoError(t, err)
}

func TestLightningNetworkGuardianship(t *testing.T) {
	config := watchtower_node.Config{
		NodeName:   "synthron_watchtower",
		LogLevel:   "info",
		DataDir:    "/var/lib/synthron/watchtower/data",
		LogDir:     "/var/lib/synthron/watchtower/logs",
		Port:       8080,
	}
	node, err := watchtower_node.NewWatchtowerNode(config)
	assert.NoError(t, err)
	assert.NotNil(t, node)

	go func() {
		err = node.Start()
		assert.NoError(t, err)
	}()

	utils.WaitForServerToStart("127.0.0.1", 8080, 5)

	channel := utils.GenerateTestLNChannel()
	err = utils.OpenLNChannel(channel)
	assert.NoError(t, err)

	// Add your logic to check LN channel guardianship
	// Example: Verify if the channel is monitored and updated correctly

	err = node.Stop()
	assert.NoError(t, err)
}

func TestConflictResolution(t *testing.T) {
	config := watchtower_node.Config{
		NodeName:   "synthron_watchtower",
		LogLevel:   "info",
		DataDir:    "/var/lib/synthron/watchtower/data",
		LogDir:     "/var/lib/synthron/watchtower/logs",
		Port:       8080,
	}
	node, err := watchtower_node.NewWatchtowerNode(config)
	assert.NoError(t, err)
	assert.NotNil(t, node)

	go func() {
		err = node.Start()
		assert.NoError(t, err)
	}()

	utils.WaitForServerToStart("127.0.0.1", 8080, 5)

	transaction1 := utils.GenerateTestTransaction()
	transaction2 := utils.GenerateConflictingTransaction(transaction1)
	err = utils.SendTransaction(transaction1)
	assert.NoError(t, err)
	err = utils.SendTransaction(transaction2)
	assert.NoError(t, err)

	// Add your logic to verify conflict resolution
	// Example: Check logs or node status for conflict resolution details

	err = node.Stop()
	assert.NoError(t, err)
}

func TestProactiveAlertSystems(t *testing.T) {
	config := watchtower_node.Config{
		NodeName:   "synthron_watchtower",
		LogLevel:   "info",
		DataDir:    "/var/lib/synthron/watchtower/data",
		LogDir:     "/var/lib/synthron/watchtower/logs",
		Port:       8080,
	}
	node, err := watchtower_node.NewWatchtowerNode(config)
	assert.NoError(t, err)
	assert.NotNil(t, node)

	go func() {
		err = node.Start()
		assert.NoError(t, err)
	}()

	utils.WaitForServerToStart("127.0.0.1", 8080, 5)

	// Simulate conditions that would trigger an alert
	err = utils.SimulateConditionForAlert()
	assert.NoError(t, err)

	// Add your logic to verify proactive alerts
	// Example: Check logs or alert system for notifications

	err = node.Stop()
	assert.NoError(t, err)
}
