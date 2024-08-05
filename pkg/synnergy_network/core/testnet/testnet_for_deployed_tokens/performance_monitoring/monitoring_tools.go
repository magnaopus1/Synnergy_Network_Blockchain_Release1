package performance_monitoring

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "crypto/sha256"
    "encoding/hex"
    "errors"
    "fmt"
    "io"
    "log"
    "sync"
    "time"

    "github.com/synnergy_network_blockchain/pkg/synnergy_network/core/testnet/common"
)

// PerformanceMetrics struct holds various performance metrics for the blockchain
type PerformanceMetrics struct {
    TransactionThroughput float64
    ConfirmationTimes     []time.Duration
    ResourceUtilization   map[string]float64
    mu                    sync.RWMutex
}

// Alert struct holds information about alerts triggered by the monitoring tools
type Alert struct {
    Timestamp   time.Time
    Description string
    Severity    string
}

// MonitoringTools struct holds metrics and alert channels for real-time monitoring
type MonitoringTools struct {
    Metrics  PerformanceMetrics
    Alerts   []Alert
    AlertCh  chan Alert
    StopCh   chan struct{}
}

// NewMonitoringTools initializes a new MonitoringTools instance
func NewMonitoringTools() *MonitoringTools {
    return &MonitoringTools{
        Metrics: PerformanceMetrics{
            ResourceUtilization: make(map[string]float64),
        },
        Alerts:  make([]Alert, 0),
        AlertCh: make(chan Alert, 100),
        StopCh:  make(chan struct{}),
    }
}

// StartMonitoring begins monitoring performance metrics and processing alerts
func (mt *MonitoringTools) StartMonitoring() {
    go func() {
        for {
            select {
            case alert := <-mt.AlertCh:
                mt.Metrics.mu.Lock()
                mt.Alerts = append(mt.Alerts, alert)
                mt.Metrics.mu.Unlock()
                log.Printf("New alert: %s", alert.Description)
            case <-mt.StopCh:
                return
            }
        }
    }()
}

// StopMonitoring stops the monitoring process
func (mt *MonitoringTools) StopMonitoring() {
    close(mt.StopCh)
}

// AddMetric adds a new performance metric and triggers alerts if necessary
func (mt *MonitoringTools) AddMetric(metricType string, value float64) {
    mt.Metrics.mu.Lock()
    defer mt.Metrics.mu.Unlock()

    switch metricType {
    case "TransactionThroughput":
        mt.Metrics.TransactionThroughput = value
    case "ConfirmationTimes":
        mt.Metrics.ConfirmationTimes = append(mt.Metrics.ConfirmationTimes, time.Duration(value))
    default:
        mt.Metrics.ResourceUtilization[metricType] = value
    }

    if value > 80 { // Example threshold
        mt.AlertCh <- Alert{
            Timestamp:   time.Now(),
            Description: fmt.Sprintf("%s metric exceeds threshold: %.2f", metricType, value),
            Severity:    "High",
        }
    }
}

// GenerateReport generates a detailed report of the current performance metrics and alerts
func (mt *MonitoringTools) GenerateReport() string {
    mt.Metrics.mu.RLock()
    defer mt.Metrics.mu.RUnlock()

    report := "Performance Metrics Report\n"
    report += fmt.Sprintf("Transaction Throughput: %.2f TPS\n", mt.Metrics.TransactionThroughput)
    report += "Confirmation Times: "
    for _, ct := range mt.Metrics.ConfirmationTimes {
        report += fmt.Sprintf("%s, ", ct.String())
    }
    report += "\nResource Utilization:\n"
    for resource, usage := range mt.Metrics.ResourceUtilization {
        report += fmt.Sprintf("%s: %.2f%%\n", resource, usage)
    }
    report += "Alerts:\n"
    for _, alert := range mt.Alerts {
        report += fmt.Sprintf("[%s] %s - %s\n", alert.Timestamp.String(), alert.Severity, alert.Description)
    }
    return report
}

// Encryption functions using AES for securing report data

// generateKey creates a new SHA-256 hash key based on the given password
func generateKey(password string) []byte {
    hash := sha256.Sum256([]byte(password))
    return hash[:]
}

// encrypt encrypts the given data using AES and the provided passphrase
func encrypt(data, passphrase string) (string, error) {
    block, err := aes.NewCipher(generateKey(passphrase))
    if err != nil {
        return "", err
    }
    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return "", err
    }
    nonce := make([]byte, gcm.NonceSize())
    if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
        return "", err
    }
    ciphertext := gcm.Seal(nonce, nonce, []byte(data), nil)
    return hex.EncodeToString(ciphertext), nil
}

// decrypt decrypts the given encrypted data using AES and the provided passphrase
func decrypt(data, passphrase string) (string, error) {
    block, err := aes.NewCipher(generateKey(passphrase))
    if err != nil {
        return "", err
    }
    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return "", err
    }
    enc, err := hex.DecodeString(data)
    if err != nil {
        return "", err
    }
    nonceSize := gcm.NonceSize()
    nonce, ciphertext := enc[:nonceSize], enc[nonceSize:]
    plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
    if err != nil {
        return "", err
    }
    return string(plaintext), nil
}

// MonitorResourceUsage monitors the CPU, memory, and bandwidth usage
func (mt *MonitoringTools) MonitorResourceUsage() {
    ticker := time.NewTicker(5 * time.Second)
    go func() {
        for {
            select {
            case <-ticker.C:
                // Simulate resource usage metrics collection
                cpuUsage := common.GetCPUUsage()
                memoryUsage := common.GetMemoryUsage()
                bandwidthUsage := common.GetBandwidthUsage()

                mt.AddMetric("CPU", cpuUsage)
                mt.AddMetric("Memory", memoryUsage)
                mt.AddMetric("Bandwidth", bandwidthUsage)
            case <-mt.StopCh:
                ticker.Stop()
                return
            }
        }
    }()
}

// common package functions for simulating resource usage metrics collection
package common

import (
    "math/rand"
    "time"
)

func GetCPUUsage() float64 {
    rand.Seed(time.Now().UnixNano())
    return rand.Float64() * 100
}

func GetMemoryUsage() float64 {
    rand.Seed(time.Now().UnixNano())
    return rand.Float64() * 100
}

func GetBandwidthUsage() float64 {
    rand.Seed(time.Now().UnixNano())
    return rand.Float64() * 100
}
