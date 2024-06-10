package staking_node_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/synthron_blockchain_final/pkg/layer0/node/staking_node"
)

func TestNodeInitialization(t *testing.T) {
	node, err := staking_node.NewStakingNode("test-node", "config.toml")
	assert.NoError(t, err, "Failed to initialize staking node")
	assert.NotNil(t, node, "Node should not be nil after initialization")
}

func TestStakeAmount(t *testing.T) {
	node, err := staking_node.NewStakingNode("test-node", "config.toml")
	assert.NoError(t, err, "Failed to initialize staking node")
	
	expectedStake := 100000
	node.SetStakeAmount(expectedStake)
	assert.Equal(t, expectedStake, node.GetStakeAmount(), "Stake amount should match the expected value")
}

func TestTransactionValidation(t *testing.T) {
	node, err := staking_node.NewStakingNode("test-node", "config.toml")
	assert.NoError(t, err, "Failed to initialize staking node")
	
	validTransaction := staking_node.Transaction{ID: "tx1", Amount: 100}
	invalidTransaction := staking_node.Transaction{ID: "", Amount: 0}

	assert.True(t, node.ValidateTransaction(validTransaction), "Valid transaction should be validated successfully")
	assert.False(t, node.ValidateTransaction(invalidTransaction), "Invalid transaction should not be validated")
}

func TestBlockCreation(t *testing.T) {
	node, err := staking_node.NewStakingNode("test-node", "config.toml")
	assert.NoError(t, err, "Failed to initialize staking node")
	
	transactions := []staking_node.Transaction{
		{ID: "tx1", Amount: 100},
		{ID: "tx2", Amount: 200},
	}
	block, err := node.CreateBlock(transactions)
	assert.NoError(t, err, "Block creation should not fail")
	assert.NotNil(t, block, "Created block should not be nil")
	assert.Equal(t, len(transactions), len(block.Transactions), "Block should contain the same number of transactions")
}

func TestBlockConfirmation(t *testing.T) {
	node, err := staking_node.NewStakingNode("test-node", "config.toml")
	assert.NoError(t, err, "Failed to initialize staking node")
	
	transactions := []staking_node.Transaction{
		{ID: "tx1", Amount: 100},
		{ID: "tx2", Amount: 200},
	}
	block, err := node.CreateBlock(transactions)
	assert.NoError(t, err, "Block creation should not fail")
	
	confirmed := node.ConfirmBlock(block)
	assert.True(t, confirmed, "Block should be confirmed successfully")
}

func TestRewardDistribution(t *testing.T) {
	node, err := staking_node.NewStakingNode("test-node", "config.toml")
	assert.NoError(t, err, "Failed to initialize staking node")
	
	node.SetStakeAmount(100000)
	node.DistributeRewards()
	
	expectedRewards := node.GetStakeAmount() * 0.01 // Assuming 1% reward rate for the test
	assert.Equal(t, expectedRewards, node.GetRewards(), "Rewards should match the expected value")
}

func TestSecurityProtocols(t *testing.T) {
	node, err := staking_node.NewStakingNode("test-node", "config.toml")
	assert.NoError(t, err, "Failed to initialize staking node")
	
	assert.True(t, node.CheckEncryption(), "Encryption should be enabled")
	assert.True(t, node.CheckBiometricAccess(), "Biometric access should be enabled")
}

func TestAutoUpdates(t *testing.T) {
	node, err := staking_node.NewStakingNode("test-node", "config.toml")
	assert.NoError(t, err, "Failed to initialize staking node")
	
	node.EnableAutoUpdates(true)
	assert.True(t, node.AreAutoUpdatesEnabled(), "Auto updates should be enabled")
}

func TestBackupAndRestore(t *testing.T) {
	node, err := staking_node.NewStakingNode("test-node", "config.toml")
	assert.NoError(t, err, "Failed to initialize staking node")
	
	err = node.PerformBackup()
	assert.NoError(t, err, "Backup should be performed without errors")
	
	err = node.RestoreFromBackup()
	assert.NoError(t, err, "Restore should be performed without errors")
}

func TestComplianceMonitoring(t *testing.T) {
	node, err := staking_node.NewStakingNode("test-node", "config.toml")
	assert.NoError(t, err, "Failed to initialize staking node")
	
	assert.True(t, node.RunComplianceChecks(), "Compliance checks should pass")
}

func TestRegularAudits(t *testing.T) {
	node, err := staking_node.NewStakingNode("test-node", "config.toml")
	assert.NoError(t, err, "Failed to initialize staking node")
	
	lastAudit := node.GetLastAuditTime()
	node.PerformAudit()
	
	assert.True(t, node.GetLastAuditTime().After(lastAudit), "Audit time should be updated after performing audit")
}

func TestMonitoring(t *testing.T) {
	node, err := staking_node.NewStakingNode("test-node", "config.toml")
	assert.NoError(t, err, "Failed to initialize staking node")
	
	node.EnableMonitoring(true)
	assert.True(t, node.IsMonitoringEnabled(), "Monitoring should be enabled")
	
	monitoringData := node.GetMonitoringData()
	assert.NotNil(t, monitoringData, "Monitoring data should not be nil")
	assert.Greater(t, len(monitoringData), 0, "Monitoring data should contain entries")
}

func TestNodeLifecycle(t *testing.T) {
	node, err := staking_node.NewStakingNode("test-node", "config.toml")
	assert.NoError(t, err, "Failed to initialize staking node")
	
	err = node.Start()
	assert.NoError(t, err, "Node should start without errors")
	assert.True(t, node.IsRunning(), "Node should be running")
	
	err = node.Stop()
	assert.NoError(t, err, "Node should stop without errors")
	assert.False(t, node.IsRunning(), "Node should not be running")
}

func TestRealWorldScenarios(t *testing.T) {
	node, err := staking_node.NewStakingNode("test-node", "config.toml")
	assert.NoError(t, err, "Failed to initialize staking node")
	
	// Simulate real-world transaction validation
	transactions := generateRealWorldTransactions(1000)
	block, err := node.CreateBlock(transactions)
	assert.NoError(t, err, "Block creation should not fail in real-world scenario")
	assert.True(t, node.ConfirmBlock(block), "Block should be confirmed in real-world scenario")
}

// Helper function to generate real-world transactions for testing
func generateRealWorldTransactions(count int) []staking_node.Transaction {
	transactions := make([]staking_node.Transaction, count)
	for i := 0; i < count; i++ {
		transactions[i] = staking_node.Transaction{
			ID:     fmt.Sprintf("tx%d", i+1),
			Amount: float64(i + 1),
		}
	}
	return transactions
}
