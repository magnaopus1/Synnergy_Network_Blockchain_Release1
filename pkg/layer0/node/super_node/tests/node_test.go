// node_test.go

package super_node

import (
    "crypto/tls"
    "crypto/x509"
    "encoding/pem"
    "io/ioutil"
    "log"
    "net/http"
    "os"
    "testing"
    "time"

    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
)

func TestSuperNodeInitialization(t *testing.T) {
    config := LoadConfig("config.toml")
    node := NewSuperNode(config)
    require.NotNil(t, node, "SuperNode should be initialized")
}

func TestSuperNodeStart(t *testing.T) {
    config := LoadConfig("config.toml")
    node := NewSuperNode(config)
    err := node.Start()
    require.NoError(t, err, "SuperNode should start without error")
    defer node.Stop()

    assert.True(t, node.IsRunning(), "SuperNode should be running")
}

func TestSuperNodeStop(t *testing.T) {
    config := LoadConfig("config.toml")
    node := NewSuperNode(config)
    err := node.Start()
    require.NoError(t, err, "SuperNode should start without error")

    err = node.Stop()
    require.NoError(t, err, "SuperNode should stop without error")
    assert.False(t, node.IsRunning(), "SuperNode should not be running")
}

func TestTransactionRouting(t *testing.T) {
    config := LoadConfig("config.toml")
    node := NewSuperNode(config)
    err := node.Start()
    require.NoError(t, err, "SuperNode should start without error")
    defer node.Stop()

    tx := NewTransaction("sender", "receiver", 10)
    err = node.RouteTransaction(tx)
    require.NoError(t, err, "Transaction should be routed without error")
}

func TestSmartContractExecution(t *testing.T) {
    config := LoadConfig("config.toml")
    node := NewSuperNode(config)
    err := node.Start()
    require.NoError(t, err, "SuperNode should start without error")
    defer node.Stop()

    sc := NewSmartContract("test_contract", "execute")
    result, err := node.ExecuteSmartContract(sc)
    require.NoError(t, err, "Smart contract should execute without error")
    assert.Equal(t, "success", result, "Smart contract execution should return 'success'")
}

func TestDataStorage(t *testing.T) {
    config := LoadConfig("config.toml")
    node := NewSuperNode(config)
    err := node.Start()
    require.NoError(t, err, "SuperNode should start without error")
    defer node.Stop()

    data := []byte("test data")
    err = node.StoreData("test_key", data)
    require.NoError(t, err, "Data should be stored without error")

    storedData, err := node.GetData("test_key")
    require.NoError(t, err, "Data should be retrieved without error")
    assert.Equal(t, data, storedData, "Retrieved data should match stored data")
}

func TestAdvancedPrivacyFeatures(t *testing.T) {
    config := LoadConfig("config.toml")
    node := NewSuperNode(config)
    err := node.Start()
    require.NoError(t, err, "SuperNode should start without error")
    defer node.Stop()

    tx := NewTransaction("sender", "receiver", 10)
    tx.EnablePrivacy()
    err = node.RouteTransaction(tx)
    require.NoError(t, err, "Private transaction should be routed without error")
}

func TestTLSConfiguration(t *testing.T) {
    certFile := "server.crt"
    keyFile := "server.key"

    // Load server certificate and key
    cert, err := tls.LoadX509KeyPair(certFile, keyFile)
    require.NoError(t, err, "Server certificate and key should load without error")

    // Create a new TLS Config
    tlsConfig := &tls.Config{
        Certificates: []tls.Certificate{cert},
    }

    // Check if TLS Config is valid
    assert.NotNil(t, tlsConfig, "TLS Config should be initialized")
    assert.Len(t, tlsConfig.Certificates, 1, "TLS Config should contain one certificate")
}

func TestDataEncryption(t *testing.T) {
    data := []byte("sensitive data")
    key := []byte("encryptionkey123")

    encryptedData, err := EncryptData(data, key)
    require.NoError(t, err, "Data should be encrypted without error")

    decryptedData, err := DecryptData(encryptedData, key)
    require.NoError(t, err, "Data should be decrypted without error")
    assert.Equal(t, data, decryptedData, "Decrypted data should match original data")
}

func TestBackupAndRecovery(t *testing.T) {
    config := LoadConfig("config.toml")
    node := NewSuperNode(config)
    err := node.Start()
    require.NoError(t, err, "SuperNode should start without error")
    defer node.Stop()

    err = node.PerformBackup()
    require.NoError(t, err, "Backup should complete without error")

    err = node.RestoreFromBackup()
    require.NoError(t, err, "Node should restore from backup without error")
}
