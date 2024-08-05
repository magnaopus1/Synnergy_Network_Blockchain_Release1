package performance_metrics

import (
    "fmt"
    "sync"
    "time"
    "math"
    "context"
    "errors"
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "crypto/sha256"
    "golang.org/x/crypto/scrypt"
    "encoding/hex"
    "io"
    "log"

    "github.com/prometheus/client_golang/prometheus"
    "github.com/prometheus/client_golang/prometheus/promhttp"
    "net/http"
)

// Metric types
type MetricType string

const (
    MetricTypeGauge   MetricType = "gauge"
    MetricTypeCounter MetricType = "counter"
)

// PerformanceMetric represents a single performance metric
type PerformanceMetric struct {
    Name   string
    Help   string
    Type   MetricType
    Labels []string
    Gauge  prometheus.Gauge
    Counter prometheus.Counter
}

// PerformanceMetricsManager manages the performance metrics
type PerformanceMetricsManager struct {
    metrics map[string]PerformanceMetric
    mu      sync.Mutex
}

// NewPerformanceMetricsManager creates a new performance metrics manager
func NewPerformanceMetricsManager() *PerformanceMetricsManager {
    return &PerformanceMetricsManager{
        metrics: make(map[string]PerformanceMetric),
    }
}

// RegisterMetric registers a new performance metric
func (pm *PerformanceMetricsManager) RegisterMetric(name, help string, metricType MetricType, labels []string) error {
    pm.mu.Lock()
    defer pm.mu.Unlock()

    if _, exists := pm.metrics[name]; exists {
        return fmt.Errorf("metric %s already registered", name)
    }

    var metric PerformanceMetric
    switch metricType {
    case MetricTypeGauge:
        metric = PerformanceMetric{
            Name:  name,
            Help:  help,
            Type:  MetricTypeGauge,
            Labels: labels,
            Gauge: prometheus.NewGauge(prometheus.GaugeOpts{
                Name: name,
                Help: help,
            }),
        }
        prometheus.MustRegister(metric.Gauge)
    case MetricTypeCounter:
        metric = PerformanceMetric{
            Name:  name,
            Help:  help,
            Type:  MetricTypeCounter,
            Labels: labels,
            Counter: prometheus.NewCounter(prometheus.CounterOpts{
                Name: name,
                Help: help,
            }),
        }
        prometheus.MustRegister(metric.Counter)
    default:
        return fmt.Errorf("unsupported metric type: %s", metricType)
    }

    pm.metrics[name] = metric
    return nil
}

// UpdateGauge updates the value of a gauge metric
func (pm *PerformanceMetricsManager) UpdateGauge(name string, value float64) error {
    pm.mu.Lock()
    defer pm.mu.Unlock()

    metric, exists := pm.metrics[name]
    if !exists {
        return fmt.Errorf("metric %s not found", name)
    }

    if metric.Type != MetricTypeGauge {
        return fmt.Errorf("metric %s is not a gauge", name)
    }

    metric.Gauge.Set(value)
    return nil
}

// IncrementCounter increments the value of a counter metric
func (pm *PerformanceMetricsManager) IncrementCounter(name string) error {
    pm.mu.Lock()
    defer pm.mu.Unlock()

    metric, exists := pm.metrics[name]
    if !exists {
        return fmt.Errorf("metric %s not found", name)
    }

    if metric.Type != MetricTypeCounter {
        return fmt.Errorf("metric %s is not a counter", name)
    }

    metric.Counter.Inc()
    return nil
}

// Encrypt encrypts plain text using AES
func Encrypt(key, text string) (string, error) {
    block, err := aes.NewCipher([]byte(key))
    if err != nil {
        return "", err
    }

    plaintext := []byte(text)
    aesGCM, err := cipher.NewGCM(block)
    if err != nil {
        return "", err
    }

    nonce := make([]byte, aesGCM.NonceSize())
    if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
        return "", err
    }

    ciphertext := aesGCM.Seal(nonce, nonce, plaintext, nil)
    return hex.EncodeToString(ciphertext), nil
}

// Decrypt decrypts AES encrypted text
func Decrypt(key, cryptoText string) (string, error) {
    block, err := aes.NewCipher([]byte(key))
    if err != nil {
        return "", err
    }

    ciphertext, err := hex.DecodeString(cryptoText)
    if err != nil {
        return "", err
    }

    aesGCM, err := cipher.NewGCM(block)
    if err != nil {
        return "", err
    }

    nonceSize := aesGCM.NonceSize()
    if len(ciphertext) < nonceSize {
        return "", errors.New("ciphertext too short")
    }

    nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
    plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
    if err != nil {
        return "", err
    }

    return string(plaintext), nil
}

// GenerateKey generates a key from a passphrase using scrypt
func GenerateKey(passphrase, salt string) (string, error) {
    dk, err := scrypt.Key([]byte(passphrase), []byte(salt), 16384, 8, 1, 32)
    if err != nil {
        return "", err
    }
    return hex.EncodeToString(dk), nil
}

// MonitorPerformance starts the HTTP server for exposing metrics
func MonitorPerformance(address string) {
    http.Handle("/metrics", promhttp.Handler())
    log.Fatal(http.ListenAndServe(address, nil))
}

func main() {
    key, err := GenerateKey("your passphrase", "your salt")
    if err != nil {
        log.Fatal(err)
    }

    fmt.Println("Generated Key:", key)

    encryptedText, err := Encrypt(key, "your text to encrypt")
    if err != nil {
        log.Fatal(err)
    }

    fmt.Println("Encrypted Text:", encryptedText)

    decryptedText, err := Decrypt(key, encryptedText)
    if err != nil {
        log.Fatal(err)
    }

    fmt.Println("Decrypted Text:", decryptedText)

    pmManager := NewPerformanceMetricsManager()
    err = pmManager.RegisterMetric("example_gauge", "An example gauge metric", MetricTypeGauge, nil)
    if err != nil {
        log.Fatal(err)
    }

    err = pmManager.RegisterMetric("example_counter", "An example counter metric", MetricTypeCounter, nil)
    if err != nil {
        log.Fatal(err)
    }

    err = pmManager.UpdateGauge("example_gauge", 42)
    if err != nil {
        log.Fatal(err)
    }

    err = pmManager.IncrementCounter("example_counter")
    if err != nil {
        log.Fatal(err)
    }

    // Start monitoring HTTP server
    go MonitorPerformance(":2112")

    // Simulate a long-running process
    select {}
}
