package peg

import (
    "fmt"
    "sync"
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "encoding/hex"
    "io"
    "errors"
    "time"
    "log"
)

// RedundancyProtocol is a structure to manage redundancy and fault tolerance in the blockchain network
type RedundancyProtocol struct {
    replicas       map[string]string  // maps asset IDs to their replicas
    replicaCount   int                // number of replicas for each asset
    mu             sync.Mutex
    alertChannel   chan string        // channel to send alerts
    aesKey         []byte             // key for AES encryption
}

// NewRedundancyProtocol creates a new instance of RedundancyProtocol
func NewRedundancyProtocol(aesKey string, replicaCount int) *RedundancyProtocol {
    key, err := hex.DecodeString(aesKey)
    if err != nil {
        log.Fatalf("Failed to decode AES key: %v", err)
    }
    return &RedundancyProtocol{
        replicas:     make(map[string]string),
        replicaCount: replicaCount,
        alertChannel: make(chan string, 100),
        aesKey:       key,
    }
}

// AddAssetReplica adds a replica for a specific asset
func (rp *RedundancyProtocol) AddAssetReplica(assetID string, replicaID string) {
    rp.mu.Lock()
    defer rp.mu.Unlock()
    rp.replicas[assetID] = replicaID
    rp.alertChannel <- fmt.Sprintf("Replica added for asset %s with replica ID %s", assetID, replicaID)
}

// RemoveAssetReplica removes a replica for a specific asset
func (rp *RedundancyProtocol) RemoveAssetReplica(assetID string) {
    rp.mu.Lock()
    defer rp.mu.Unlock()
    delete(rp.replicas, assetID)
    rp.alertChannel <- fmt.Sprintf("Replica removed for asset %s", assetID)
}

// MonitorReplicas continuously monitors the replicas for consistency
func (rp *RedundancyProtocol) MonitorReplicas() {
    for {
        rp.mu.Lock()
        for assetID, replicaID := range rp.replicas {
            // Simulated consistency check logic
            consistent := rp.checkReplicaConsistency(assetID, replicaID)
            if !consistent {
                rp.alertChannel <- fmt.Sprintf("Replica inconsistency detected for asset %s with replica ID %s", assetID, replicaID)
            }
        }
        rp.mu.Unlock()
        time.Sleep(1 * time.Minute) // adjust the monitoring interval as needed
    }
}

// checkReplicaConsistency simulates checking the consistency of a replica
func (rp *RedundancyProtocol) checkReplicaConsistency(assetID string, replicaID string) bool {
    // Implement real consistency check logic here
    // For now, returning a simulated consistency check result
    return true // Simulated consistent state
}

// EncryptData encrypts the data using AES
func (rp *RedundancyProtocol) EncryptData(plaintext string) (string, error) {
    block, err := aes.NewCipher(rp.aesKey)
    if err != nil {
        return "", err
    }
    ciphertext := make([]byte, aes.BlockSize+len(plaintext))
    iv := ciphertext[:aes.BlockSize]
    if _, err := io.ReadFull(rand.Reader, iv); err != nil {
        return "", err
    }
    stream := cipher.NewCFBEncrypter(block, iv)
    stream.XORKeyStream(ciphertext[aes.BlockSize:], []byte(plaintext))
    return hex.EncodeToString(ciphertext), nil
}

// DecryptData decrypts the data using AES
func (rp *RedundancyProtocol) DecryptData(ciphertext string) (string, error) {
    data, err := hex.DecodeString(ciphertext)
    if err != nil {
        return "", err
    }
    block, err := aes.NewCipher(rp.aesKey)
    if err != nil {
        return "", err
    }
    if len(data) < aes.BlockSize {
        return "", errors.New("ciphertext too short")
    }
    iv := data[:aes.BlockSize]
    data = data[aes.BlockSize:]
    stream := cipher.NewCFBDecrypter(block, iv)
    stream.XORKeyStream(data, data)
    return string(data), nil
}

// LogRedundancyData logs the redundancy data to the appropriate sink
func (rp *RedundancyProtocol) LogRedundancyData() {
    for alert := range rp.alertChannel {
        log.Printf("ALERT: %s", alert)
        // Additional logging logic can be added here, e.g., sending to a remote server
    }
}

// main function to initialize and run the redundancy protocol
func main() {
    aesKey := "6368616e676520746869732070617373" // Example AES key (must be 32 bytes for AES-256)
    rp := NewRedundancyProtocol(aesKey, 3) // Initialize with 3 replicas per asset

    rp.AddAssetReplica("asset1", "replica1")
    rp.AddAssetReplica("asset2", "replica2")

    go rp.MonitorReplicas()
    go rp.LogRedundancyData()

    for alert := range rp.alertChannel {
        fmt.Println(alert)
    }
}
