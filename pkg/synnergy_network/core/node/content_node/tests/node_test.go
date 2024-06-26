package tests

import (
    "testing"
    "os"
    "path/filepath"
    "sync"
    "time"
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "crypto/rsa"
    "crypto/sha256"
    "crypto/x509"
    "encoding/base64"
    "encoding/pem"
    "errors"
    "io"
    "io/ioutil"
    "log"
    "github.com/synnergy/content_node" // Replace with actual import path
)

var (
    testDir = filepath.Join(os.TempDir(), "content_node_test")
    once sync.Once
)

func setup() {
    os.MkdirAll(testDir, os.ModePerm)
}

func teardown() {
    os.RemoveAll(testDir)
}

func TestMain(m *testing.M) {
    once.Do(setup)
    code := m.Run()
    teardown()
    os.Exit(code)
}

func TestStoreAndRetrieveContent(t *testing.T) {
    node := content_node.NewContentNode(testDir)

    testData := []byte("test data for content node")
    contentID, err := node.StoreContent(testData)
    if err != nil {
        t.Fatalf("Failed to store content: %v", err)
    }

    retrievedData, err := node.RetrieveContent(contentID)
    if err != nil {
        t.Fatalf("Failed to retrieve content: %v", err)
    }

    if string(retrievedData) != string(testData) {
        t.Fatalf("Data mismatch. Got %s, expected %s", string(retrievedData), string(testData))
    }
}

func TestEncryptionAndDecryption(t *testing.T) {
    testData := []byte("this is a secret")
    key := make([]byte, 32)
    if _, err := rand.Read(key); err != nil {
        t.Fatalf("Failed to generate encryption key: %v", err)
    }

    encryptedData, err := encryptData(testData, key)
    if err != nil {
        t.Fatalf("Failed to encrypt data: %v", err)
    }

    decryptedData, err := decryptData(encryptedData, key)
    if err != nil {
        t.Fatalf("Failed to decrypt data: %v", err)
    }

    if string(decryptedData) != string(testData) {
        t.Fatalf("Data mismatch. Got %s, expected %s", string(decryptedData), string(testData))
    }
}

func encryptData(data, key []byte) ([]byte, error) {
    block, err := aes.NewCipher(key)
    if err != nil {
        return nil, err
    }

    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return nil, err
    }

    nonce := make([]byte, gcm.NonceSize())
    if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
        return nil, err
    }

    ciphertext := gcm.Seal(nonce, nonce, data, nil)
    return ciphertext, nil
}

func decryptData(data, key []byte) ([]byte, error) {
    block, err := aes.NewCipher(key)
    if err != nil {
        return nil, err
    }

    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return nil, err
    }

    if len(data) < gcm.NonceSize() {
        return nil, errors.New("malformed ciphertext")
    }

    nonce, ciphertext := data[:gcm.NonceSize()], data[gcm.NonceSize():]
    return gcm.Open(nil, nonce, ciphertext, nil)
}

func TestBackupAndRecovery(t *testing.T) {
    node := content_node.NewContentNode(testDir)

    testData := []byte("backup data")
    contentID, err := node.StoreContent(testData)
    if err != nil {
        t.Fatalf("Failed to store content: %v", err)
    }

    backupPath := filepath.Join(testDir, "backup")
    err = node.BackupContent(backupPath)
    if err != nil {
        t.Fatalf("Failed to backup content: %v", err)
    }

    err = node.RestoreContent(backupPath)
    if err != nil {
        t.Fatalf("Failed to restore content: %v", err)
    }

    retrievedData, err := node.RetrieveContent(contentID)
    if err != nil {
        t.Fatalf("Failed to retrieve content after recovery: %v", err)
    }

    if string(retrievedData) != string(testData) {
        t.Fatalf("Data mismatch after recovery. Got %s, expected %s", string(retrievedData), string(testData))
    }
}

func TestContentNodePerformance(t *testing.T) {
    node := content_node.NewContentNode(testDir)

    start := time.Now()
    for i := 0; i < 1000; i++ {
        testData := []byte("performance test data " + string(i))
        _, err := node.StoreContent(testData)
        if err != nil {
            t.Fatalf("Failed to store content: %v", err)
        }
    }
    duration := time.Since(start)

    if duration > time.Minute {
        t.Fatalf("Performance test took too long: %v", duration)
    }
}

func TestContentNodeSecurity(t *testing.T) {
    node := content_node.NewContentNode(testDir)

    testData := []byte("secure data")
    contentID, err := node.StoreContent(testData)
    if err != nil {
        t.Fatalf("Failed to store content: %v", err)
    }

    err = node.EncryptContent(contentID)
    if err != nil {
        t.Fatalf("Failed to encrypt content: %v", err)
    }

    err = node.DecryptContent(contentID)
    if err != nil {
        t.Fatalf("Failed to decrypt content: %v", err)
    }

    retrievedData, err := node.RetrieveContent(contentID)
    if err != nil {
        t.Fatalf("Failed to retrieve content after decryption: %v", err)
    }

    if string(retrievedData) != string(testData) {
        t.Fatalf("Data mismatch after decryption. Got %s, expected %s", string(retrievedData), string(testData))
    }
}
