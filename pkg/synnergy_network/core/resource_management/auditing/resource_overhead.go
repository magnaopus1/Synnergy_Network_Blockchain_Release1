package auditing

import (
    "fmt"
    "sync"
    "time"
)

// ResourceOverheadAuditor is responsible for monitoring and auditing the resource overhead in the network
type ResourceOverheadAuditor struct {
    resourceMetrics map[string]ResourceMetric
    mu              sync.Mutex
    alertThreshold  float64
}

// ResourceMetric holds data about resource usage metrics
type ResourceMetric struct {
    CPUUsage       float64
    MemoryUsage    float64
    NetworkUsage   float64
    DiskUsage      float64
    LastUpdated    time.Time
}

// NewResourceOverheadAuditor initializes a new ResourceOverheadAuditor
func NewResourceOverheadAuditor(threshold float64) *ResourceOverheadAuditor {
    return &ResourceOverheadAuditor{
        resourceMetrics: make(map[string]ResourceMetric),
        alertThreshold:  threshold,
    }
}

// UpdateMetrics updates the resource metrics for a given node
func (roa *ResourceOverheadAuditor) UpdateMetrics(nodeID string, cpuUsage, memoryUsage, networkUsage, diskUsage float64) {
    roa.mu.Lock()
    defer roa.mu.Unlock()

    roa.resourceMetrics[nodeID] = ResourceMetric{
        CPUUsage:    cpuUsage,
        MemoryUsage: memoryUsage,
        NetworkUsage: networkUsage,
        DiskUsage:   diskUsage,
        LastUpdated: time.Now(),
    }

    roa.checkAlert(nodeID)
}

// checkAlert checks if the resource usage exceeds the threshold and triggers an alert if necessary
func (roa *ResourceOverheadAuditor) checkAlert(nodeID string) {
    metric := roa.resourceMetrics[nodeID]
    if metric.CPUUsage > roa.alertThreshold || metric.MemoryUsage > roa.alertThreshold || metric.NetworkUsage > roa.alertThreshold || metric.DiskUsage > roa.alertThreshold {
        fmt.Printf("ALERT: Node %s exceeds resource usage threshold at %v\n", nodeID, time.Now())
        // Trigger alert actions such as notifying administrators or adjusting resource allocation
    }
}

// GenerateReport generates a comprehensive report of the resource usage across the network
func (roa *ResourceOverheadAuditor) GenerateReport() {
    roa.mu.Lock()
    defer roa.mu.Unlock()

    fmt.Println("Resource Usage Report")
    fmt.Println("=====================")
    for nodeID, metric := range roa.resourceMetrics {
        fmt.Printf("Node ID: %s\n", nodeID)
        fmt.Printf("CPU Usage: %.2f%%\n", metric.CPUUsage)
        fmt.Printf("Memory Usage: %.2f%%\n", metric.MemoryUsage)
        fmt.Printf("Network Usage: %.2f%%\n", metric.NetworkUsage)
        fmt.Printf("Disk Usage: %.2f%%\n", metric.DiskUsage)
        fmt.Printf("Last Updated: %v\n\n", metric.LastUpdated)
    }
}

// EncryptMetrics encrypts the resource metrics for secure transmission
func (roa *ResourceOverheadAuditor) EncryptMetrics(key []byte) ([]byte, error) {
    roa.mu.Lock()
    defer roa.mu.Unlock()

    data, err := json.Marshal(roa.resourceMetrics)
    if err != nil {
        return nil, err
    }

    encryptedData, err := encrypt(data, key)
    if err != nil {
        return nil, err
    }

    return encryptedData, nil
}

// DecryptMetrics decrypts the received resource metrics
func (roa *ResourceOverheadAuditor) DecryptMetrics(encryptedData, key []byte) error {
    decryptedData, err := decrypt(encryptedData, key)
    if err != nil {
        return err
    }

    roa.mu.Lock()
    defer roa.mu.Unlock()

    err = json.Unmarshal(decryptedData, &roa.resourceMetrics)
    if err != nil {
        return err
    }

    return nil
}

// encrypt encrypts the data using AES-GCM
func encrypt(data, key []byte) ([]byte, error) {
    block, err := aes.NewCipher(key)
    if err != nil {
        return nil, err
    }

    aesGCM, err := cipher.NewGCM(block)
    if err != nil {
        return nil, err
    }

    nonce := make([]byte, aesGCM.NonceSize())
    if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
        return nil, err
    }

    ciphertext := aesGCM.Seal(nonce, nonce, data, nil)
    return ciphertext, nil
}

// decrypt decrypts the data using AES-GCM
func decrypt(data, key []byte) ([]byte, error) {
    block, err := aes.NewCipher(key)
    if err != nil {
        return nil, err
    }

    aesGCM, err := cipher.NewGCM(block)
    if err != nil {
        return nil, err
    }

    nonceSize := aesGCM.NonceSize()
    if len(data) < nonceSize {
        return nil, fmt.Errorf("ciphertext too short")
    }

    nonce, ciphertext := data[:nonceSize], data[nonceSize:]
    plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
    if err != nil {
        return nil, err
    }

    return plaintext, nil
}

// MonitorResourceUsage continuously monitors resource usage and updates metrics
func (roa *ResourceOverheadAuditor) MonitorResourceUsage(nodeID string, getMetricsFunc func() (float64, float64, float64, float64)) {
    ticker := time.NewTicker(time.Minute)
    defer ticker.Stop()

    for {
        select {
        case <-ticker.C:
            cpuUsage, memoryUsage, networkUsage, diskUsage := getMetricsFunc()
            roa.UpdateMetrics(nodeID, cpuUsage, memoryUsage, networkUsage, diskUsage)
        }
    }
}
