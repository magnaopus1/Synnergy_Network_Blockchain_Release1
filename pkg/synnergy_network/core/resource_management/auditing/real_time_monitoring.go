package auditing

import (
    "fmt"
    "log"
    "os"
    "time"
    "sync"
    "io/ioutil"
    "path/filepath"
    "encoding/json"
    "sync/atomic"
    "errors"
    
    "github.com/synnergy_network/core/utils"
    "github.com/synnergy_network/core/resource_management/encryption"
    "github.com/synnergy_network/core/resource_management/security"
    "github.com/synnergy_network/core/resource_management/optimization"
)

// Metric defines the structure for resource metrics
type Metric struct {
    Timestamp      time.Time `json:"timestamp"`
    CPUUsage       float64   `json:"cpu_usage"`
    MemoryUsage    float64   `json:"memory_usage"`
    NetworkIn      float64   `json:"network_in"`
    NetworkOut     float64   `json:"network_out"`
    DiskUsage      float64   `json:"disk_usage"`
    Transactions   int       `json:"transactions"`
}

// Monitor is responsible for collecting and storing metrics
type Monitor struct {
    metrics       []Metric
    mutex         sync.Mutex
    threshold     Thresholds
    alertHandlers []AlertHandler
}

// Thresholds defines thresholds for resource usage to trigger alerts
type Thresholds struct {
    CPUUsage       float64
    MemoryUsage    float64
    NetworkIn      float64
    NetworkOut     float64
    DiskUsage      float64
}

// AlertHandler defines a structure for handling alerts
type AlertHandler struct {
    Name    string
    Handler func(Metric) error
}

// NewMonitor initializes a new Monitor instance
func NewMonitor(thresholds Thresholds, alertHandlers []AlertHandler) *Monitor {
    return &Monitor{
        metrics:       make([]Metric, 0),
        threshold:     thresholds,
        alertHandlers: alertHandlers,
    }
}

// CollectMetrics collects metrics from various system resources
func (m *Monitor) CollectMetrics() {
    for {
        metric := Metric{
            Timestamp:   time.Now(),
            CPUUsage:    utils.GetCPUUsage(),
            MemoryUsage: utils.GetMemoryUsage(),
            NetworkIn:   utils.GetNetworkIn(),
            NetworkOut:  utils.GetNetworkOut(),
            DiskUsage:   utils.GetDiskUsage(),
            Transactions: utils.GetTransactionCount(),
        }

        m.mutex.Lock()
        m.metrics = append(m.metrics, metric)
        m.mutex.Unlock()

        m.checkThresholds(metric)
        
        time.Sleep(time.Minute) // Collect metrics every minute
    }
}

// checkThresholds checks if any metric exceeds the defined thresholds
func (m *Monitor) checkThresholds(metric Metric) {
    if metric.CPUUsage > m.threshold.CPUUsage || 
       metric.MemoryUsage > m.threshold.MemoryUsage ||
       metric.NetworkIn > m.threshold.NetworkIn || 
       metric.NetworkOut > m.threshold.NetworkOut ||
       metric.DiskUsage > m.threshold.DiskUsage {
        m.triggerAlert(metric)
    }
}

// triggerAlert triggers alert handlers if a threshold is exceeded
func (m *Monitor) triggerAlert(metric Metric) {
    for _, handler := range m.alertHandlers {
        if err := handler.Handler(metric); err != nil {
            log.Printf("Error handling alert for %s: %v", handler.Name, err)
        }
    }
}

// StoreMetrics securely stores collected metrics
func (m *Monitor) StoreMetrics() error {
    m.mutex.Lock()
    defer m.mutex.Unlock()

    data, err := json.Marshal(m.metrics)
    if err != nil {
        return fmt.Errorf("failed to marshal metrics: %v", err)
    }

    encryptedData, err := encryption.Encrypt(data, encryption.DefaultKey())
    if err != nil {
        return fmt.Errorf("failed to encrypt metrics: %v", err)
    }

    fileName := fmt.Sprintf("metrics_%d.json.enc", time.Now().Unix())
    err = ioutil.WriteFile(filepath.Join("path_to_secure_storage", fileName), encryptedData, 0644)
    if err != nil {
        return fmt.Errorf("failed to write encrypted metrics to file: %v", err)
    }

    return nil
}

// LoadMetrics securely loads metrics from storage
func (m *Monitor) LoadMetrics(fileName string) ([]Metric, error) {
    encryptedData, err := ioutil.ReadFile(filepath.Join("path_to_secure_storage", fileName))
    if err != nil {
        return nil, fmt.Errorf("failed to read metrics file: %v", err)
    }

    data, err := encryption.Decrypt(encryptedData, encryption.DefaultKey())
    if err != nil {
        return nil, fmt.Errorf("failed to decrypt metrics: %v", err)
    }

    var metrics []Metric
    err = json.Unmarshal(data, &metrics)
    if err != nil {
        return nil, fmt.Errorf("failed to unmarshal metrics: %v", err)
    }

    return metrics, nil
}

// ExportMetricsToBlockchain exports metrics to the blockchain for transparency
func (m *Monitor) ExportMetricsToBlockchain(metrics []Metric) error {
    for _, metric := range metrics {
        // Blockchain export logic (pseudo-code)
        // err := blockchainClient.Publish("metrics", metric)
        // if err != nil {
        //     return fmt.Errorf("failed to export metric to blockchain: %v", err)
        // }
    }
    return nil
}

// DefaultAlertHandler is a default implementation of an alert handler
func DefaultAlertHandler(metric Metric) error {
    // Default alert handling logic (e.g., logging, sending notifications)
    log.Printf("Alert: metric exceeded threshold: %+v", metric)
    return nil
}

