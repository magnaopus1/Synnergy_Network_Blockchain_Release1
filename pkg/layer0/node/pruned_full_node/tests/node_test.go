package pruned_full_node_test

import (
	"testing"
	"time"
	"encoding/json"
	"os"
	"path/filepath"
	"github.com/synthron/synthron_blockchain/pkg/layer0/node/pruned_full_node"
	"github.com/stretchr/testify/assert"
	"github.com/synthron/synthron_blockchain/pkg/layer0/utilities/encryption"
)

const (
	configPath      = "/tmp/pruned_full_node_config.json"
	storagePath     = "/tmp/pruned_full_node_data"
	backupPath      = "/tmp/pruned_full_node_backup"
	consensusState  = "/tmp/pruned_full_node_consensus_state"
	historicalData  = "/tmp/pruned_full_node_historical_data"
	healthCheckAddr = "127.0.0.1:8080"
	metricsAddr     = "127.0.0.1:9090"
)

func TestPrunedFullNodeInitialization(t *testing.T) {
	config := pruned_full_node.Config{
		Network: pruned_full_node.NetworkConfig{
			ListenAddress: "0.0.0.0:8545",
			BootstrapNodes: []string{
				"node1.synthron.network:8545",
				"node2.synthron.network:8545",
			},
			MaxPeers: 50,
		},
		Logging: pruned_full_node.LoggingConfig{
			Level: "info",
			File:  "/var/log/pruned_full_node.log",
		},
		Storage: pruned_full_node.StorageConfig{
			Path:                storagePath,
			PruneBlocksOlderThan: 100000,
			PruneInterval:       1000,
		},
		Consensus: pruned_full_node.ConsensusConfig{
			Algorithm: "argon2",
			StateFile: consensusState,
		},
		Security: pruned_full_node.SecurityConfig{
			EnableTLS:       true,
			TLSCertFile:     "/etc/synthron/tls/cert.pem",
			TLSKeyFile:      "/etc/synthron/tls/key.pem",
			EnableMFA:       true,
			MFAConfigFile:   "/etc/synthron/mfa_config.json",
		},
		Performance: pruned_full_node.PerformanceConfig{
			MaxThreads: 8,
			CacheSize:  "2GB",
		},
		Monitoring: pruned_full_node.MonitoringConfig{
			EnableHealthCheck: true,
			HealthCheckAddress: healthCheckAddr,
			EnableMetrics:     true,
			MetricsEndpoint:   metricsAddr,
		},
		Backup: pruned_full_node.BackupConfig{
			BackupPath:         backupPath,
			BackupFrequency:    "daily",
			BackupRetentionDays: 30,
		},
		Incentives: pruned_full_node.IncentivesConfig{
			EnableIncentives:        true,
			RewardPerBlock:          10.0,
			UptimeBonusPercentage:   5.0,
		},
		Features: pruned_full_node.FeaturesConfig{
			EnableHistoricalData: true,
			HistoricalDataPath:   historicalData,
		},
		Debug: pruned_full_node.DebugConfig{
			EnableDebug:    false,
			DebugLogLevel:  "debug",
		},
		Notifications: pruned_full_node.NotificationsConfig{
			EnableNotifications: true,
			NotificationEndpoint: "http://notifications.synthron.network:8000",
		},
		Updates: pruned_full_node.UpdatesConfig{
			AutoUpdate:          true,
			UpdateCheckInterval: 24,
		},
		App: pruned_full_node.AppConfig{
			NodeName:      "PrunedFullNode1",
			OperatorEmail: "operator@synthron.network",
		},
	}

	data, err := json.MarshalIndent(config, "", "  ")
	assert.NoError(t, err)
	err = os.WriteFile(configPath, data, 0644)
	assert.NoError(t, err)

	node, err := pruned_full_node.NewPrunedFullNode(configPath)
	assert.NoError(t, err)
	assert.NotNil(t, node)

	assert.Equal(t, node.Config.Network.ListenAddress, config.Network.ListenAddress)
	assert.Equal(t, node.Config.Storage.Path, config.Storage.Path)
	assert.Equal(t, node.Config.Consensus.Algorithm, config.Consensus.Algorithm)

	// Test the encryption settings
	enc, err := encryption.NewEncryptionManager(config.Security.TLSCertFile, config.Security.TLSKeyFile)
	assert.NoError(t, err)
	assert.NotNil(t, enc)
}

func TestPrunedFullNodeOperations(t *testing.T) {
	config := pruned_full_node.Config{
		Storage: pruned_full_node.StorageConfig{
			Path: storagePath,
		},
		Consensus: pruned_full_node.ConsensusConfig{
			StateFile: consensusState,
		},
	}

	node, err := pruned_full_node.NewPrunedFullNode(configPath)
	assert.NoError(t, err)
	assert.NotNil(t, node)

	err = node.Start()
	assert.NoError(t, err)

	time.Sleep(2 * time.Second)

	status, err := node.Status()
	assert.NoError(t, err)
	assert.Equal(t, "running", status)

	err = node.Stop()
	assert.NoError(t, err)

	status, err = node.Status()
	assert.NoError(t, err)
	assert.Equal(t, "stopped", status)
}

func TestPrunedFullNodeBackupAndRestore(t *testing.T) {
	config := pruned_full_node.Config{
		Storage: pruned_full_node.StorageConfig{
			Path: storagePath,
		},
		Backup: pruned_full_node.BackupConfig{
			BackupPath: backupPath,
		},
	}

	node, err := pruned_full_node.NewPrunedFullNode(configPath)
	assert.NoError(t, err)
	assert.NotNil(t, node)

	err = node.Backup()
	assert.NoError(t, err)

	backupFile := filepath.Join(backupPath, "backup_20220101.zip")
	_, err = os.Stat(backupFile)
	assert.NoError(t, err)

	err = node.Restore(backupFile)
	assert.NoError(t, err)
}
