package archival_full_node

import (
	"testing"
	"time"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/synthron/blockchain/pkg/config"
	"github.com/synthron/blockchain/pkg/layer0/node/archival_full_node"
	"github.com/synthron/blockchain/pkg/utils"
	"github.com/synthron/blockchain/pkg/security"
	"github.com/stretchr/testify/assert"
)

// TestSetupNode tests the initial setup of the node
func TestSetupNode(t *testing.T) {
	tmpDir, err := ioutil.TempDir("", "synthron_test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	cfg := &config.Config{
		NodeType: "archival",
		DataDir:  tmpDir,
		LogDir:   tmpDir,
		Network: config.NetworkConfig{
			ListenAddr:   "0.0.0.0:30303",
			ExternalAddr: "0.0.0.0:30303",
			MaxPeers:     50,
			P2PSecretKey: tmpDir + "/p2p_secret.key",
		},
		Consensus: config.ConsensusConfig{
			Engine:                   "argon2",
			PowTargetSpacing:         600,
			DifficultyAdjustmentInterval: 2016,
		},
		RPC: config.RPCConfig{
			HttpEndpoint: "127.0.0.1:8545",
			WsEndpoint:   "127.0.0.1:8546",
			HttpCors:     []string{"*"},
			HttpHosts:    []string{"localhost"},
			RPCModules:   []string{"web3", "eth", "net", "debug", "admin", "personal"},
		},
		Sync: config.SyncConfig{
			Mode:     "fast",
			Snapshot: true,
		},
		Database: config.DatabaseConfig{
			DBDir:     tmpDir + "/database",
			CacheSize: 4096,
			Handles:   1000,
		},
		Security: config.SecurityConfig{
			UseTLS:       true,
			TLSCertFile:  tmpDir + "/tls_cert.pem",
			TLSKeyFile:   tmpDir + "/tls_key.pem",
			FirewallEnabled: true,
			FirewallRulesFile: tmpDir + "/firewall_rules.toml",
		},
		Metrics: config.MetricsConfig{
			Enabled:           true,
			PrometheusEndpoint: "127.0.0.1:9090",
			MetricsPrefix:     "synthron_",
		},
		Backup: config.BackupConfig{
			BackupDir:      tmpDir + "/backup",
			BackupInterval: "24h",
			BackupRetention: "30d",
		},
		Staking: config.StakingConfig{
			StakeAmount:   1000000,
			RewardAddress: "0xYourRewardAddress",
		},
		API: config.APIConfig{
			Enabled:     true,
			APIEndpoint: "127.0.0.1:8080",
			APIKeys:     []string{"your_api_key"},
		},
		Features: config.FeaturesConfig{
			EnableAdvancedLogging:   true,
			EnablePredictiveAnalytics: true,
			EnableAnomalyDetection: true,
		},
		Performance: config.PerformanceConfig{
			CacheSettings:  "default",
			DBOptimization: "high",
		},
		Developer: config.DeveloperConfig{
			DebugMode: false,
			Testnet:   false,
		},
	}

	node, err := archival_full_node.NewArchivalFullNode(cfg)
	if err != nil {
		t.Fatal(err)
	}

	assert.NotNil(t, node)
}

// TestStartNode tests starting the node
func TestStartNode(t *testing.T) {
	node, err := createTestNode()
	if err != nil {
		t.Fatal(err)
	}

	err = node.Start()
	assert.NoError(t, err)

	time.Sleep(5 * time.Second) // Wait a bit for the node to start

	status := node.Status()
	assert.Equal(t, "running", status)

	err = node.Stop()
	assert.NoError(t, err)
}

// TestStopNode tests stopping the node
func TestStopNode(t *testing.T) {
	node, err := createTestNode()
	if err != nil {
		t.Fatal(err)
	}

	err = node.Start()
	assert.NoError(t, err)

	time.Sleep(5 * time.Second) // Wait a bit for the node to start

	err = node.Stop()
	assert.NoError(t, err)

	status := node.Status()
	assert.Equal(t, "stopped", status)
}

// TestBackupAndRestore tests the backup and restore functionality
func TestBackupAndRestore(t *testing.T) {
	node, err := createTestNode()
	if err != nil {
		t.Fatal(err)
	}

	err = node.Start()
	assert.NoError(t, err)

	time.Sleep(5 * time.Second) // Wait a bit for the node to start

	err = node.Backup()
	assert.NoError(t, err)

	err = node.Restore()
	assert.NoError(t, err)

	err = node.Stop()
	assert.NoError(t, err)
}

// TestTransactionValidation tests the transaction validation logic
func TestTransactionValidation(t *testing.T) {
	node, err := createTestNode()
	if err != nil {
		t.Fatal(err)
	}

	validTx := utils.GenerateValidTransaction()
	invalidTx := utils.GenerateInvalidTransaction()

	assert.True(t, node.ValidateTransaction(validTx))
	assert.False(t, node.ValidateTransaction(invalidTx))
}

// TestBlockCreationAndPropagation tests block creation and propagation
func TestBlockCreationAndPropagation(t *testing.T) {
	node, err := createTestNode()
	if err != nil {
		t.Fatal(err)
	}

	err = node.Start()
	assert.NoError(t, err)

	block, err := node.CreateBlock()
	assert.NoError(t, err)

	err = node.PropagateBlock(block)
	assert.NoError(t, err)

	err = node.Stop()
	assert.NoError(t, err)
}

// TestConsensusBuilding tests the consensus building process
func TestConsensusBuilding(t *testing.T) {
	node, err := createTestNode()
	if err != nil {
		t.Fatal(err)
	}

	err = node.Start()
	assert.NoError(t, err)

	err = node.ParticipateInConsensus()
	assert.NoError(t, err)

	err = node.Stop()
	assert.NoError(t, err)
}

// Helper function to create a test node
func createTestNode() (*archival_full_node.ArchivalFullNode, error) {
	tmpDir, err := ioutil.TempDir("", "synthron_test")
	if err != nil {
		return nil, err
	}

	cfg := &config.Config{
		NodeType: "archival",
		DataDir:  tmpDir,
		LogDir:   tmpDir,
		Network: config.NetworkConfig{
			ListenAddr:   "0.0.0.0:30303",
			ExternalAddr: "0.0.0.0:30303",
			MaxPeers:     50,
			P2PSecretKey: tmpDir + "/p2p_secret.key",
		},
		Consensus: config.ConsensusConfig{
			Engine:                   "argon2",
			PowTargetSpacing:         600,
			DifficultyAdjustmentInterval: 2016,
		},
		RPC: config.RPCConfig{
			HttpEndpoint: "127.0.0.1:8545",
			WsEndpoint:   "127.0.0.1:8546",
			HttpCors:     []string{"*"},
			HttpHosts:    []string{"localhost"},
			RPCModules:   []string{"web3", "eth", "net", "debug", "admin", "personal"},
		},
		Sync: config.SyncConfig{
			Mode:     "fast",
			Snapshot: true,
		},
		Database: config.DatabaseConfig{
			DBDir:     tmpDir + "/database",
			CacheSize: 4096,
			Handles:   1000,
		},
		Security: config.SecurityConfig{
			UseTLS:       true,
			TLSCertFile:  tmpDir + "/tls_cert.pem",
			TLSKeyFile:   tmpDir + "/tls_key.pem",
			FirewallEnabled: true,
			FirewallRulesFile: tmpDir + "/firewall_rules.toml",
		},
		Metrics: config.MetricsConfig{
			Enabled:           true,
			PrometheusEndpoint: "127.0.0.1:9090",
			MetricsPrefix:     "synthron_",
		},
		Backup: config.BackupConfig{
			BackupDir:      tmpDir + "/backup",
			BackupInterval: "24h",
			BackupRetention: "30d",
		},
		Staking: config.StakingConfig{
			StakeAmount:   1000000,
			RewardAddress: "0xYourRewardAddress",
		},
		API: config.APIConfig{
			Enabled:     true,
			APIEndpoint: "127.0.0.1:8080",
			APIKeys:     []string{"your_api_key"},
		},
		Features: config.FeaturesConfig{
			EnableAdvancedLogging:   true,
			EnablePredictiveAnalytics: true,
			EnableAnomalyDetection: true,
		},
		Performance: config.PerformanceConfig{
			CacheSettings:  "default",
			DBOptimization: "high",
		},
		Developer: config.DeveloperConfig{
			DebugMode: false,
			Testnet:   false,
		},
	}

	node, err := archival_full_node.NewArchivalFullNode(cfg)
	if err != nil {
		return nil, err
	}

	return node, nil
}
