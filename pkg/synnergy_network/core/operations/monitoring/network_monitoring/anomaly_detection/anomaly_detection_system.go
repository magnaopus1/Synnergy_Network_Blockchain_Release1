package anomaly_detection

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "crypto/sha256"
    "encoding/base64"
    "errors"
    "io"
    "log"
    "time"

    "github.com/synnergy-network/pkg/layer0/monitoring/network_monitoring/utils"
    "golang.org/x/crypto/scrypt"
)

// AnomalyDetectionSystem handles anomaly detection within the blockchain network
type AnomalyDetectionSystem struct {
    nodes       []Node
    dataChannel chan NetworkData
    anomalyLogs []AnomalyLog
    key         []byte
}

// Node represents a node in the network
type Node struct {
    ID       string
    Address  string
    LastSeen time.Time
}

// NetworkData represents data collected from the network
type NetworkData struct {
    NodeID       string
    Timestamp    time.Time
    Metric       string
    Value        float64
    AnomalyScore float64
}

// AnomalyLog stores information about detected anomalies
type AnomalyLog struct {
    NodeID    string
    Timestamp time.Time
    Metric    string
    Value     float64
    Score     float64
}

// NewAnomalyDetectionSystem creates a new anomaly detection system
func NewAnomalyDetectionSystem(key string) (*AnomalyDetectionSystem, error) {
    k, err := generateKey(key)
    if err != nil {
        return nil, err
    }

    return &AnomalyDetectionSystem{
        nodes:       make([]Node, 0),
        dataChannel: make(chan NetworkData),
        anomalyLogs: make([]AnomalyLog, 0),
        key:         k,
    }, nil
}

// AddNode adds a new node to the monitoring system
func (ads *AnomalyDetectionSystem) AddNode(node Node) {
    ads.nodes = append(ads.nodes, node)
}

// CollectData collects network data from a node
func (ads *AnomalyDetectionSystem) CollectData(data NetworkData) {
    ads.dataChannel <- data
}

// StartMonitoring starts the monitoring process
func (ads *AnomalyDetectionSystem) StartMonitoring() {
    go func() {
        for data := range ads.dataChannel {
            if ads.isAnomaly(data) {
                ads.logAnomaly(data)
            }
        }
    }()
}

// isAnomaly determines if the provided data represents an anomaly
func (ads *AnomalyDetectionSystem) isAnomaly(data NetworkData) bool {
    // Implement a machine learning algorithm to detect anomalies
    // For simplicity, we will use a threshold-based detection here
    if data.AnomalyScore > 0.8 {
        return true
    }
    return false
}

// logAnomaly logs detected anomalies
func (ads *AnomalyDetectionSystem) logAnomaly(data NetworkData) {
    ads.anomalyLogs = append(ads.anomalyLogs, AnomalyLog{
        NodeID:    data.NodeID,
        Timestamp: data.Timestamp,
        Metric:    data.Metric,
        Value:     data.Value,
        Score:     data.AnomalyScore,
    })
    log.Printf("Anomaly detected: NodeID=%s, Metric=%s, Value=%.2f, Score=%.2f\n", data.NodeID, data.Metric, data.Value, data.AnomalyScore)
}

// EncryptData encrypts data using AES
func (ads *AnomalyDetectionSystem) EncryptData(plainText string) (string, error) {
    block, err := aes.NewCipher(ads.key)
    if err != nil {
        return "", err
    }

    aesGCM, err := cipher.NewGCM(block)
    if err != nil {
        return "", err
    }

    nonce := make([]byte, aesGCM.NonceSize())
    if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
        return "", err
    }

    cipherText := aesGCM.Seal(nonce, nonce, []byte(plainText), nil)
    return base64.StdEncoding.EncodeToString(cipherText), nil
}

// DecryptData decrypts data using AES
func (ads *AnomalyDetectionSystem) DecryptData(cipherText string) (string, error) {
    data, err := base64.StdEncoding.DecodeString(cipherText)
    if err != nil {
        return "", err
    }

    block, err := aes.NewCipher(ads.key)
    if err != nil {
        return "", err
    }

    aesGCM, err := cipher.NewGCM(block)
    if err != nil {
        return "", err
    }

    nonceSize := aesGCM.NonceSize()
    if len(data) < nonceSize {
        return "", errors.New("ciphertext too short")
    }

    nonce, cipherText := data[:nonceSize], data[nonceSize:]
    plainText, err := aesGCM.Open(nil, nonce, cipherText, nil)
    if err != nil {
        return "", err
    }

    return string(plainText), nil
}

// generateKey generates a key from a passphrase using scrypt
func generateKey(passphrase string) ([]byte, error) {
    salt := make([]byte, 16)
    _, err := io.ReadFull(rand.Reader, salt)
    if err != nil {
        return nil, err
    }

    key, err := scrypt.Key([]byte(passphrase), salt, 32768, 8, 1, 32)
    if err != nil {
        return nil, err
    }

    return key, nil
}
