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
)

type PerformanceMetrics struct {
    TransactionThroughput float64
    ConfirmationTimes     []time.Duration
    ResourceUtilization   map[string]float64
}

type Alert struct {
    Timestamp   time.Time
    Description string
    Severity    string
}

type Dashboard struct {
    Metrics  PerformanceMetrics
    Alerts   []Alert
    mu       sync.RWMutex
    AlertCh  chan Alert
    StopCh   chan struct{}
}

func NewDashboard() *Dashboard {
    return &Dashboard{
        Metrics: PerformanceMetrics{
            ResourceUtilization: make(map[string]float64),
        },
        Alerts:  make([]Alert, 0),
        AlertCh: make(chan Alert, 100),
        StopCh:  make(chan struct{}),
    }
}

func (d *Dashboard) StartMonitoring() {
    go func() {
        for {
            select {
            case alert := <-d.AlertCh:
                d.mu.Lock()
                d.Alerts = append(d.Alerts, alert)
                d.mu.Unlock()
                log.Printf("New alert: %s", alert.Description)
            case <-d.StopCh:
                return
            }
        }
    }()
}

func (d *Dashboard) StopMonitoring() {
    close(d.StopCh)
}

func (d *Dashboard) AddMetric(metricType string, value float64) {
    d.mu.Lock()
    defer d.mu.Unlock()

    switch metricType {
    case "TransactionThroughput":
        d.Metrics.TransactionThroughput = value
    case "ConfirmationTimes":
        d.Metrics.ConfirmationTimes = append(d.Metrics.ConfirmationTimes, time.Duration(value))
    default:
        d.Metrics.ResourceUtilization[metricType] = value
    }

    if value > 80 { // Example threshold
        d.AlertCh <- Alert{
            Timestamp:   time.Now(),
            Description: fmt.Sprintf("%s metric exceeds threshold: %.2f", metricType, value),
            Severity:    "High",
        }
    }
}

func (d *Dashboard) GenerateReport() string {
    d.mu.RLock()
    defer d.mu.RUnlock()

    report := "Performance Metrics Report\n"
    report += fmt.Sprintf("Transaction Throughput: %.2f TPS\n", d.Metrics.TransactionThroughput)
    report += "Confirmation Times: "
    for _, ct := range d.Metrics.ConfirmationTimes {
        report += fmt.Sprintf("%s, ", ct.String())
    }
    report += "\nResource Utilization:\n"
    for resource, usage := range d.Metrics.ResourceUtilization {
        report += fmt.Sprintf("%s: %.2f%%\n", resource, usage)
    }
    report += "Alerts:\n"
    for _, alert := range d.Alerts {
        report += fmt.Sprintf("[%s] %s - %s\n", alert.Timestamp.String(), alert.Severity, alert.Description)
    }
    return report
}

// Encryption functions using AES
func generateKey(password string) []byte {
    hash := sha256.Sum256([]byte(password))
    return hash[:]
}

func encrypt(data, passphrase string) (string, error) {
    block, _ := aes.NewCipher(generateKey(passphrase))
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

func main() {
    dashboard := NewDashboard()
    dashboard.StartMonitoring()

    // Simulating metrics addition
    dashboard.AddMetric("TransactionThroughput", 150)
    dashboard.AddMetric("ConfirmationTimes", 1.2)
    dashboard.AddMetric("CPU", 85.0)
    dashboard.AddMetric("Memory", 75.5)

    // Generate report
    report := dashboard.GenerateReport()
    fmt.Println(report)

    // Encrypt and Decrypt example
    passphrase := "securepassphrase"
    encrypted, err := encrypt(report, passphrase)
    if err != nil {
        log.Fatalf("Failed to encrypt report: %v", err)
    }
    fmt.Printf("Encrypted report: %s\n", encrypted)

    decrypted, err := decrypt(encrypted, passphrase)
    if err != nil {
        log.Fatalf("Failed to decrypt report: %v", err)
    }
    fmt.Printf("Decrypted report: %s\n", decrypted)
}
