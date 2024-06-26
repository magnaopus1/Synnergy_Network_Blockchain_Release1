package main

import (
    "testing"
    "time"
    "os"
    "log"
    "crypto/sha256"
    "encoding/hex"

    "github.com/stretchr/testify/assert"
    "github.com/synthron/pkg/layer0/node/energy_efficient_node"
)

// TestNodeInitialization tests the initialization of an Energy-Efficient Node
func TestNodeInitialization(t *testing.T) {
    node, err := energy_efficient_node.NewNode("energy_efficient_node_001", "config.toml")
    assert.NoError(t, err, "Node initialization should not return an error")
    assert.NotNil(t, node, "Node should be initialized")
}

// TestLoadConfiguration tests loading the configuration file
func TestLoadConfiguration(t *testing.T) {
    config, err := energy_efficient_node.LoadConfig("config.toml")
    assert.NoError(t, err, "Loading configuration should not return an error")
    assert.NotNil(t, config, "Configuration should be loaded")
}

// TestStartNode tests starting the node
func TestStartNode(t *testing.T) {
    node, err := energy_efficient_node.NewNode("energy_efficient_node_001", "config.toml")
    assert.NoError(t, err, "Node initialization should not return an error")

    err = node.Start()
    assert.NoError(t, err, "Starting the node should not return an error")
}

// TestStopNode tests stopping the node
func TestStopNode(t *testing.T) {
    node, err := energy_efficient_node.NewNode("energy_efficient_node_001", "config.toml")
    assert.NoError(t, err, "Node initialization should not return an error")

    err = node.Start()
    assert.NoError(t, err, "Starting the node should not return an error")

    err = node.Stop()
    assert.NoError(t, err, "Stopping the node should not return an error")
}

// TestEncryptDecrypt tests the encryption and decryption methods
func TestEncryptDecrypt(t *testing.T) {
    plaintext := "This is a test string"
    key := sha256.Sum256([]byte("testkey"))

    encrypted, err := energy_efficient_node.Encrypt(plaintext, hex.EncodeToString(key[:]))
    assert.NoError(t, err, "Encryption should not return an error")
    assert.NotEmpty(t, encrypted, "Encrypted string should not be empty")

    decrypted, err := energy_efficient_node.Decrypt(encrypted, hex.EncodeToString(key[:]))
    assert.NoError(t, err, "Decryption should not return an error")
    assert.Equal(t, plaintext, decrypted, "Decrypted string should match the original plaintext")
}

// TestMonitorEnergyUsage tests the energy usage monitoring system
func TestMonitorEnergyUsage(t *testing.T) {
    node, err := energy_efficient_node.NewNode("energy_efficient_node_001", "config.toml")
    assert.NoError(t, err, "Node initialization should not return an error")

    err = node.Start()
    assert.NoError(t, err, "Starting the node should not return an error")

    usage, err := node.MonitorEnergyUsage()
    assert.NoError(t, err, "Monitoring energy usage should not return an error")
    assert.Greater(t, usage, 0.0, "Energy usage should be greater than zero")

    err = node.Stop()
    assert.NoError(t, err, "Stopping the node should not return an error")
}

// TestUpdateSoftware tests the software update functionality
func TestUpdateSoftware(t *testing.T) {
    node, err := energy_efficient_node.NewNode("energy_efficient_node_001", "config.toml")
    assert.NoError(t, err, "Node initialization should not return an error")

    err = node.CheckForUpdates()
    assert.NoError(t, err, "Checking for updates should not return an error")

    updated, err := node.UpdateSoftware()
    assert.NoError(t, err, "Updating software should not return an error")
    assert.True(t, updated, "Software should be updated")
}

// TestBackupData tests the data backup functionality
func TestBackupData(t *testing.T) {
    node, err := energy_efficient_node.NewNode("energy_efficient_node_001", "config.toml")
    assert.NoError(t, err, "Node initialization should not return an error")

    err = node.BackupData()
    assert.NoError(t, err, "Backing up data should not return an error")

    backupPath := node.Config.BackupDirectory
    _, err = os.Stat(backupPath)
    assert.False(t, os.IsNotExist(err), "Backup file should exist")
}

func main() {
    // Run the tests
    log.Println("Starting node tests")
    err := testing.Main(func(_ string, _ []string) (bool, error) { return true, nil }, nil, nil, nil)
    if err != nil {
        log.Fatalf("Error running tests: %v", err)
    }
    log.Println("Node tests completed")
}
