package analytics

import (
    "log"
    "time"
    "sync"
    "math/rand"

    "golang.org/x/crypto/scrypt"
)

// NetworkMetrics holds data about network performance
type NetworkMetrics struct {
    Latency       float64 // in milliseconds
    Throughput    float64 // transactions per second
    ErrorRate     float64 // percentage of failed transactions
    LastUpdatedAt time.Time
}

// NetworkPerformanceMonitor is responsible for collecting and analyzing network performance data
type NetworkPerformanceMonitor struct {
    metrics      NetworkMetrics
    updateLock   sync.Mutex
}

// NewNetworkPerformanceMonitor creates a new instance of network performance monitor
func NewNetworkPerformanceMonitor() *NetworkPerformanceMonitor {
    return &NetworkPerformanceMonitor{
        metrics: NetworkMetrics{
            LastUpdatedAt: time.Now(),
        },
    }
}

// simulateDataGeneration simulates network data for testing purposes
func (npm *NetworkPerformanceMonitor) simulateDataGeneration() {
    // Simulate random performance metrics
    npm.updateLock.Lock()
    defer npm.updateLock.Unlock()

    npm.metrics.Latency = rand.Float64() * 100
    npm.metrics.Throughput = rand.Float64() * 1000
    npm.metrics.ErrorRate = rand.Float64() * 10
    npm.metrics.LastUpdatedAt = time.Now()
}

// EncryptMetrics uses Scrypt to encrypt network metrics data
func (npm *NetworkPerformanceMonitor) EncryptMetrics() ([]byte, error) {
    data := []byte(npm.metrics.String())
    salt := []byte("your-random-salt-here") // Ideally, this should be stored securely and should be unique for each encryption
    encryptedData, err := scrypt.Key(data, salt, 16384, 8, 1, 32)
    if err != nil {
        log.Printf("Failed to encrypt metrics: %v", err)
        return nil, err
    }
    return encryptedData, nil
}

// UpdateMetrics updates network performance metrics
func (npm *NetworkPerformanceMonitor) UpdateMetrics() {
    npm.simulateDataGeneration()
    log.Printf("Metrics updated at %v", npm.metrics.LastUpdatedAt)
}

// ReportMetrics logs the current state of network performance metrics
func (npm *NetworkPerformanceMonitor) ReportMetrics() {
    npm.updateLock.Lock()
    defer npm.updateLock.Unlock()

    log.Printf("Reporting Metrics - Latency: %.2f ms, Throughput: %.2f tps, Error Rate: %.2f%%, Updated At: %v", 
        npm.metrics.Latency, npm.metrics.Throughput, npm.metrics.ErrorRate, npm.metrics.LastUpdatedAt)
}

// main function to demonstrate functionality
func main() {
    monitor := NewNetworkPerformanceMonitor()
    monitor.UpdateMetrics()
    monitor.ReportMetrics()

    if encryptedMetrics, err := monitor.EncryptMetrics(); err == nil {
        log.Printf("Encrypted Metrics: %x", encryptedMetrics)
    }
}

// Helper method to convert metrics to a string
func (m *NetworkMetrics) String() string {
    return fmt.Sprintf("Latency: %.2f ms, Throughput: %.2f tps, Error Rate: %.2f%%, Updated At: %v", 
        m.Latency, m.Throughput, m.ErrorRate, m.LastUpdatedAt)
}
