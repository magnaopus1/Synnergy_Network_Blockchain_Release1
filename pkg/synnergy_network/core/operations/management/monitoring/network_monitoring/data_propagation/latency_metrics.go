package datapro

import (
    "fmt"
    "log"
    "time"
    "encoding/json"
    "net/http"
    "sync"
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "io"
    "golang.org/x/crypto/argon2"
    "golang.org/x/crypto/scrypt"
)

// LatencyMetrics stores the latency data for network nodes.
type LatencyMetrics struct {
    NodeID       string        `json:"node_id"`
    Latency      time.Duration `json:"latency"`
    Timestamp    time.Time     `json:"timestamp"`
    EncryptedData []byte       `json:"encrypted_data,omitempty"`
}

// LatencyDataManager manages latency data for nodes.
type LatencyDataManager struct {
    sync.RWMutex
    Metrics      map[string][]LatencyMetrics
    AESKey       []byte
    ScryptSalt   []byte
}

// NewLatencyDataManager initializes a new LatencyDataManager with encryption keys.
func NewLatencyDataManager() (*LatencyDataManager, error) {
    aesKey := make([]byte, 32)
    _, err := rand.Read(aesKey)
    if err != nil {
        return nil, fmt.Errorf("failed to generate AES key: %v", err)
    }

    scryptSalt := make([]byte, 32)
    _, err = rand.Read(scryptSalt)
    if err != nil {
        return nil, fmt.Errorf("failed to generate Scrypt salt: %v", err)
    }

    return &LatencyDataManager{
        Metrics:    make(map[string][]LatencyMetrics),
        AESKey:     aesKey,
        ScryptSalt: scryptSalt,
    }, nil
}

// RecordLatency records the latency for a node.
func (manager *LatencyDataManager) RecordLatency(nodeID string, latency time.Duration) error {
    manager.Lock()
    defer manager.Unlock()

    encryptedData, err := manager.encryptLatencyData(nodeID, latency)
    if err != nil {
        return fmt.Errorf("failed to encrypt latency data: %v", err)
    }

    metric := LatencyMetrics{
        NodeID:    nodeID,
        Latency:   latency,
        Timestamp: time.Now(),
        EncryptedData: encryptedData,
    }

    manager.Metrics[nodeID] = append(manager.Metrics[nodeID], metric)
    return nil
}

// GetLatency retrieves the latency data for a node.
func (manager *LatencyDataManager) GetLatency(nodeID string) ([]LatencyMetrics, error) {
    manager.RLock()
    defer manager.RUnlock()

    metrics, exists := manager.Metrics[nodeID]
    if !exists {
        return nil, fmt.Errorf("no latency data for node %s", nodeID)
    }

    return metrics, nil
}

// Encrypt latency data using AES.
func (manager *LatencyDataManager) encryptLatencyData(nodeID string, latency time.Duration) ([]byte, error) {
    data := fmt.Sprintf("NodeID: %s, Latency: %v", nodeID, latency)
    block, err := aes.NewCipher(manager.AESKey)
    if err != nil {
        return nil, err
    }

    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return nil, err
    }

    nonce := make([]byte, gcm.NonceSize())
    if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
        return nil, err
    }

    encrypted := gcm.Seal(nonce, nonce, []byte(data), nil)
    return encrypted, nil
}

// Decrypt latency data using AES.
func (manager *LatencyDataManager) decryptLatencyData(encryptedData []byte) (string, error) {
    block, err := aes.NewCipher(manager.AESKey)
    if err != nil {
        return "", err
    }

    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return "", err
    }

    nonceSize := gcm.NonceSize()
    if len(encryptedData) < nonceSize {
        return "", fmt.Errorf("ciphertext too short")
    }

    nonce, ciphertext := encryptedData[:nonceSize], encryptedData[nonceSize:]
    decrypted, err := gcm.Open(nil, nonce, ciphertext, nil)
    if err != nil {
        return "", err
    }

    return string(decrypted), nil
}

// HTTP handler to record latency.
func (manager *LatencyDataManager) RecordLatencyHandler(w http.ResponseWriter, r *http.Request) {
    var data struct {
        NodeID  string        `json:"node_id"`
        Latency time.Duration `json:"latency"`
    }

    err := json.NewDecoder(r.Body).Decode(&data)
    if err != nil {
        http.Error(w, "Invalid request payload", http.StatusBadRequest)
        return
    }

    err = manager.RecordLatency(data.NodeID, data.Latency)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    w.WriteHeader(http.StatusOK)
}

// HTTP handler to retrieve latency.
func (manager *LatencyDataManager) GetLatencyHandler(w http.ResponseWriter, r *http.Request) {
    nodeID := r.URL.Query().Get("node_id")
    if nodeID == "" {
        http.Error(w, "Node ID is required", http.StatusBadRequest)
        return
    }

    metrics, err := manager.GetLatency(nodeID)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(metrics)
}

func main() {
    manager, err := NewLatencyDataManager()
    if err != nil {
        log.Fatalf("Failed to initialize latency data manager: %v", err)
    }

    http.HandleFunc("/record-latency", manager.RecordLatencyHandler)
    http.HandleFunc("/get-latency", manager.GetLatencyHandler)

    log.Println("Starting server on :8080")
    log.Fatal(http.ListenAndServe(":8080", nil))
}
