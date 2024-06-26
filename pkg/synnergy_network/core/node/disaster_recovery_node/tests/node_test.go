package tests

import (
	"testing"
	"time"
	"os"
	"io/ioutil"
	"encoding/json"
	"path/filepath"

	"github.com/stretchr/testify/assert"
	"github.com/synthron_blockchain/pkg/layer0/node/disaster_recovery_node"
)

// Test Configuration
const configPath = "../config.toml"

// Helper function to create a temporary directory for testing
func createTempDir(t *testing.T) string {
	dir, err := ioutil.TempDir("", "disaster_recovery_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %s", err)
	}
	return dir
}

// Helper function to cleanup a directory
func cleanupTempDir(t *testing.T, dir string) {
	err := os.RemoveAll(dir)
	if err != nil {
		t.Fatalf("Failed to clean up temp dir: %s", err)
	}
}

// TestLoadConfig verifies that the configuration file loads correctly
func TestLoadConfig(t *testing.T) {
	config, err := disaster_recovery_node.LoadConfig(configPath)
	assert.NoError(t, err, "Failed to load config")
	assert.NotNil(t, config, "Config should not be nil")
}

// TestBackupCreation verifies that backups are created correctly
func TestBackupCreation(t *testing.T) {
	tempDir := createTempDir(t)
	defer cleanupTempDir(t, tempDir)

	config := &disaster_recovery_node.Config{
		DataDir:       tempDir,
		BackupDir:     tempDir,
		Incremental:   true,
		BackupInterval: time.Minute * 1,
	}

	node := disaster_recovery_node.NewNode(config)
	err := node.CreateBackup()
	assert.NoError(t, err, "Backup creation failed")

	files, err := ioutil.ReadDir(tempDir)
	assert.NoError(t, err, "Failed to read backup dir")
	assert.True(t, len(files) > 0, "Backup dir should contain files")
}

// TestRestore verifies that backups can be restored correctly
func TestRestore(t *testing.T) {
	tempDir := createTempDir(t)
	defer cleanupTempDir(t, tempDir)

	config := &disaster_recovery_node.Config{
		DataDir:   tempDir,
		BackupDir: tempDir,
	}

	node := disaster_recovery_node.NewNode(config)
	err := node.CreateBackup()
	assert.NoError(t, err, "Backup creation failed")

	err = node.RestoreBackup()
	assert.NoError(t, err, "Restore failed")
}

// TestGeographicalRedundancy ensures backups are stored in multiple locations
func TestGeographicalRedundancy(t *testing.T) {
	tempDir1 := createTempDir(t)
	defer cleanupTempDir(t, tempDir1)

	tempDir2 := createTempDir(t)
	defer cleanupTempDir(t, tempDir2)

	config := &disaster_recovery_node.Config{
		DataDir:   tempDir1,
		BackupDir: tempDir1,
		RedundantBackupDirs: []string{tempDir2},
	}

	node := disaster_recovery_node.NewNode(config)
	err := node.CreateBackup()
	assert.NoError(t, err, "Backup creation failed")

	files1, err := ioutil.ReadDir(tempDir1)
	assert.NoError(t, err, "Failed to read primary backup dir")
	assert.True(t, len(files1) > 0, "Primary backup dir should contain files")

	files2, err := ioutil.ReadDir(tempDir2)
	assert.NoError(t, err, "Failed to read redundant backup dir")
	assert.True(t, len(files2) > 0, "Redundant backup dir should contain files")
}

// TestBackupIntegrity verifies the integrity of backup files
func TestBackupIntegrity(t *testing.T) {
	tempDir := createTempDir(t)
	defer cleanupTempDir(t, tempDir)

	config := &disaster_recovery_node.Config{
		DataDir:   tempDir,
		BackupDir: tempDir,
	}

	node := disaster_recovery_node.NewNode(config)
	err := node.CreateBackup()
	assert.NoError(t, err, "Backup creation failed")

	backupFiles, err := filepath.Glob(filepath.Join(tempDir, "*.bak"))
	assert.NoError(t, err, "Failed to find backup files")
	assert.True(t, len(backupFiles) > 0, "Should find backup files")

	for _, file := range backupFiles {
		data, err := ioutil.ReadFile(file)
		assert.NoError(t, err, "Failed to read backup file")
		assert.True(t, len(data) > 0, "Backup file should contain data")
	}
}

// TestAIAnomalyDetection ensures AI anomaly detection works correctly
func TestAIAnomalyDetection(t *testing.T) {
	tempDir := createTempDir(t)
	defer cleanupTempDir(t, tempDir)

	config := &disaster_recovery_node.Config{
		DataDir:           tempDir,
		BackupDir:         tempDir,
		EnableAIDetection: true,
	}

	node := disaster_recovery_node.NewNode(config)
	err := node.CreateBackup()
	assert.NoError(t, err, "Backup creation failed")

	anomalyDetected, err := node.DetectAnomalies()
	assert.NoError(t, err, "Anomaly detection failed")
	assert.False(t, anomalyDetected, "No anomalies should be detected in fresh backup")
}

// TestSelfHealingMechanism verifies the self-healing mechanism for backups
func TestSelfHealingMechanism(t *testing.T) {
	tempDir := createTempDir(t)
	defer cleanupTempDir(t, tempDir)

	config := &disaster_recovery_node.Config{
		DataDir:          tempDir,
		BackupDir:        tempDir,
		EnableSelfHealing: true,
	}

	node := disaster_recovery_node.NewNode(config)
	err := node.CreateBackup()
	assert.NoError(t, err, "Backup creation failed")

	// Simulate corruption
	backupFiles, err := filepath.Glob(filepath.Join(tempDir, "*.bak"))
	assert.NoError(t, err, "Failed to find backup files")
	assert.True(t, len(backupFiles) > 0, "Should find backup files")

	err = ioutil.WriteFile(backupFiles[0], []byte("corrupted data"), 0644)
	assert.NoError(t, err, "Failed to corrupt backup file")

	err = node.SelfHeal()
	assert.NoError(t, err, "Self-healing failed")

	// Verify integrity after healing
	for _, file := range backupFiles {
		data, err := ioutil.ReadFile(file)
		assert.NoError(t, err, "Failed to read backup file")
		assert.NotContains(t, string(data), "corrupted data", "Backup file should be healed")
	}
}
