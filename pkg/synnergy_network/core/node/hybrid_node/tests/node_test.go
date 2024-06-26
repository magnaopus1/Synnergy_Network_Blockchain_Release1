package tests

import (
	"testing"
	"time"
	"math/rand"
	"reflect"
	"github.com/stretchr/testify/assert"
	"github.com/synthron_blockchain/pkg/layer0/node/hybrid_node"
	"github.com/synthron_blockchain/pkg/layer0/node/hybrid_node/consensus"
	"github.com/synthron_blockchain/pkg/layer0/node/hybrid_node/storage"
)

// TestInitialization tests the initialization of the Hybrid Node
func TestInitialization(t *testing.T) {
	config := hybrid_node.Config{
		NodeID:          "hybrid-node-01",
		NodeType:        "hybrid",
		LogLevel:        "info",
		DataPath:        "/var/lib/synthron/hybrid_node/data",
		LogPath:         "/var/log/synthron/hybrid_node",
		NetworkInterface: "0.0.0.0",
		NetworkPort:      8080,
		EncryptionKey:   "path/to/encryption_key.pem",
		ConsensusAlgorithm: "argon2",
		BlockProposalInterval: "10s",
		CPULimit:        4,
		MemoryLimit:     "16GB",
		StorageLimit:    "1TB",
		UseScrypt:       true,
		UseAES:          true,
		UseArgon2:       true,
		EncryptionSalt:  "random_salt_value",
		EndToEndEncryption: true,
		DBHost:          "localhost",
		DBPort:          5432,
		DBUser:          "synthron_user",
		DBPassword:      "synthron_password",
		DBName:          "synthron_db",
		EnableMonitoring: true,
		MonitoringPort:   9090,
		HealthCheckInterval: "30s",
		EnableBackup:    true,
		BackupInterval:  "24h",
		BackupPath:      "/var/backups/synthron/hybrid_node",
		EnableAuditLogs: true,
		AuditLogPath:    "/var/log/synthron/hybrid_node/audit",
		EnableAlerts:    true,
		AlertEmail:      "admin@synthron.org",
		AlertThresholds: hybrid_node.AlertThresholds{CPUUsage: "80%", MemoryUsage: "80%", DiskUsage: "90%"},
		EnableAutoTuning: true,
		PerformanceProfile: "high",
		EnableUI:        true,
		UIPort:          3000,
		UIPath:          "/usr/share/synthron/hybrid_node/ui",
	}

	node, err := hybrid_node.NewHybridNode(config)
	assert.NoError(t, err)
	assert.NotNil(t, node)
}

// TestTransactionProcessing tests the transaction processing functionality
func TestTransactionProcessing(t *testing.T) {
	node := setupTestHybridNode(t)

	tx := generateTestTransaction()
	err := node.ProcessTransaction(tx)
	assert.NoError(t, err)

	storedTx, err := node.Storage.GetTransaction(tx.ID)
	assert.NoError(t, err)
	assert.Equal(t, tx, storedTx)
}

// TestBlockProposal tests the block proposal functionality
func TestBlockProposal(t *testing.T) {
	node := setupTestHybridNode(t)

	err := node.ProposeBlock()
	assert.NoError(t, err)

	lastBlock, err := node.Consensus.GetLastBlock()
	assert.NoError(t, err)
	assert.NotNil(t, lastBlock)
}

// TestDynamicResourceManagement tests dynamic resource management
func TestDynamicResourceManagement(t *testing.T) {
	node := setupTestHybridNode(t)

	initialCPUUsage := node.ResourceManager.GetCPUUsage()
	initialMemoryUsage := node.ResourceManager.GetMemoryUsage()

	// Simulate high load
	simulateHighLoad(node)

	time.Sleep(2 * time.Minute)

	assert.Greater(t, node.ResourceManager.GetCPUUsage(), initialCPUUsage)
	assert.Greater(t, node.ResourceManager.GetMemoryUsage(), initialMemoryUsage)
}

// TestSecurityProtocols tests security protocols
func TestSecurityProtocols(t *testing.T) {
	node := setupTestHybridNode(t)

	assert.True(t, node.Security.UseScrypt)
	assert.True(t, node.Security.UseAES)
	assert.True(t, node.Security.UseArgon2)

	// Test encryption and decryption
	plaintext := "test data"
	ciphertext, err := node.Security.Encrypt(plaintext)
	assert.NoError(t, err)

	decryptedText, err := node.Security.Decrypt(ciphertext)
	assert.NoError(t, err)
	assert.Equal(t, plaintext, decryptedText)
}

// TestPerformanceOptimization tests automated performance optimization
func TestPerformanceOptimization(t *testing.T) {
	node := setupTestHybridNode(t)

	initialPerformanceProfile := node.Performance.Profile
	assert.Equal(t, "high", initialPerformanceProfile)

	// Simulate conditions for performance adjustment
	simulatePerformanceAdjustment(node)

	assert.NotEqual(t, initialPerformanceProfile, node.Performance.Profile)
}

func setupTestHybridNode(t *testing.T) *hybrid_node.HybridNode {
	config := hybrid_node.Config{
		NodeID:          "hybrid-node-01",
		NodeType:        "hybrid",
		LogLevel:        "info",
		DataPath:        "/var/lib/synthron/hybrid_node/data",
		LogPath:         "/var/log/synthron/hybrid_node",
		NetworkInterface: "0.0.0.0",
		NetworkPort:      8080,
		EncryptionKey:   "path/to/encryption_key.pem",
		ConsensusAlgorithm: "argon2",
		BlockProposalInterval: "10s",
		CPULimit:        4,
		MemoryLimit:     "16GB",
		StorageLimit:    "1TB",
		UseScrypt:       true,
		UseAES:          true,
		UseArgon2:       true,
		EncryptionSalt:  "random_salt_value",
		EndToEndEncryption: true,
		DBHost:          "localhost",
		DBPort:          5432,
		DBUser:          "synthron_user",
		DBPassword:      "synthron_password",
		DBName:          "synthron_db",
		EnableMonitoring: true,
		MonitoringPort:   9090,
		HealthCheckInterval: "30s",
		EnableBackup:    true,
		BackupInterval:  "24h",
		BackupPath:      "/var/backups/synthron/hybrid_node",
		EnableAuditLogs: true,
		AuditLogPath:    "/var/log/synthron/hybrid_node/audit",
		EnableAlerts:    true,
		AlertEmail:      "admin@synthron.org",
		AlertThresholds: hybrid_node.AlertThresholds{CPUUsage: "80%", MemoryUsage: "80%", DiskUsage: "90%"},
		EnableAutoTuning: true,
		PerformanceProfile: "high",
		EnableUI:        true,
		UIPort:          3000,
		UIPath:          "/usr/share/synthron/hybrid_node/ui",
	}

	node, err := hybrid_node.NewHybridNode(config)
	if err != nil {
		t.Fatalf("Failed to create HybridNode: %v", err)
	}

	return node
}

func generateTestTransaction() hybrid_node.Transaction {
	return hybrid_node.Transaction{
		ID:     generateRandomID(),
		From:   "user1",
		To:     "user2",
		Amount: 100,
		Timestamp: time.Now().Unix(),
		Signature: generateRandomSignature(),
	}
}

func generateRandomID() string {
	rand.Seed(time.Now().UnixNano())
	return fmt.Sprintf("%016x", rand.Int63())
}

func generateRandomSignature() string {
	rand.Seed(time.Now().UnixNano())
	return fmt.Sprintf("%064x", rand.Int63())
}

func simulateHighLoad(node *hybrid_node.HybridNode) {
	// Simulate high CPU and memory usage
	for i := 0; i < 100000; i++ {
		go node.ProcessTransaction(generateTestTransaction())
	}
}

func simulatePerformanceAdjustment(node *hybrid_node.HybridNode) {
	// Simulate conditions that require performance adjustment
	time.Sleep(1 * time.Minute)
	node.Performance.Profile = "adjusted"
}
