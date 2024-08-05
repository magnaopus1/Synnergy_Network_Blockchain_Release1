package auditing

import (
    "fmt"
    "log"
    "os"
    "sync"
    "time"
    "encoding/json"
)

// TransparencyReport struct for storing detailed auditing data
type TransparencyReport struct {
    Timestamp         time.Time `json:"timestamp"`
    NodeID            string    `json:"node_id"`
    ResourceUsage     ResourceUsageData `json:"resource_usage"`
    Transactions      []TransactionData `json:"transactions"`
    IssuesDetected    []string  `json:"issues_detected"`
    AuditLog          []string  `json:"audit_log"`
    Recommendations   []string  `json:"recommendations"`
}

// ResourceUsageData struct to capture resource usage metrics
type ResourceUsageData struct {
    CPUUsage          float64 `json:"cpu_usage"`
    MemoryUsage       float64 `json:"memory_usage"`
    NetworkBandwidth  float64 `json:"network_bandwidth"`
    StorageUsage      float64 `json:"storage_usage"`
}

// TransactionData struct to store transaction details
type TransactionData struct {
    TransactionID     string    `json:"transaction_id"`
    Type              string    `json:"type"`
    Value             float64   `json:"value"`
    Status            string    `json:"status"`
    Timestamp         time.Time `json:"timestamp"`
}

// InitTransparencyReport initializes a new transparency report
func InitTransparencyReport(nodeID string) *TransparencyReport {
    return &TransparencyReport{
        Timestamp:         time.Now(),
        NodeID:            nodeID,
        ResourceUsage:     ResourceUsageData{},
        Transactions:      []TransactionData{},
        IssuesDetected:    []string{},
        AuditLog:          []string{},
        Recommendations:   []string{},
    }
}

// LogResourceUsage logs the resource usage data
func (tr *TransparencyReport) LogResourceUsage(cpu, memory, bandwidth, storage float64) {
    tr.ResourceUsage = ResourceUsageData{
        CPUUsage:         cpu,
        MemoryUsage:      memory,
        NetworkBandwidth: bandwidth,
        StorageUsage:     storage,
    }
    tr.AuditLog = append(tr.AuditLog, fmt.Sprintf("Logged resource usage: CPU %.2f, Memory %.2f, Bandwidth %.2f, Storage %.2f", cpu, memory, bandwidth, storage))
}

// LogTransaction logs a transaction detail
func (tr *TransparencyReport) LogTransaction(id, ttype string, value float64, status string) {
    transaction := TransactionData{
        TransactionID: id,
        Type:          ttype,
        Value:         value,
        Status:        status,
        Timestamp:     time.Now(),
    }
    tr.Transactions = append(tr.Transactions, transaction)
    tr.AuditLog = append(tr.AuditLog, fmt.Sprintf("Logged transaction ID: %s, Type: %s, Value: %.2f, Status: %s", id, ttype, value, status))
}

// DetectIssues analyzes data and detects issues
func (tr *TransparencyReport) DetectIssues() {
    // Example issue detection
    if tr.ResourceUsage.CPUUsage > 80 {
        tr.IssuesDetected = append(tr.IssuesDetected, "High CPU usage detected.")
    }
    tr.AuditLog = append(tr.AuditLog, "Issues detection complete.")
}

// RecommendActions suggests actions based on detected issues
func (tr *TransparencyReport) RecommendActions() {
    if len(tr.IssuesDetected) > 0 {
        tr.Recommendations = append(tr.Recommendations, "Review and optimize high CPU-consuming processes.")
    }
    tr.AuditLog = append(tr.AuditLog, "Recommendations generated.")
}

// GenerateJSONReport exports the report as a JSON file
func (tr *TransparencyReport) GenerateJSONReport(filePath string) error {
    file, err := os.Create(filePath)
    if err != nil {
        log.Fatalf("Failed to create report file: %s", err)
        return err
    }
    defer file.Close()

    encoder := json.NewEncoder(file)
    encoder.SetIndent("", "  ")
    if err := encoder.Encode(tr); err != nil {
        log.Fatalf("Failed to encode report to JSON: %s", err)
        return err
    }

    tr.AuditLog = append(tr.AuditLog, fmt.Sprintf("Generated JSON report at %s", filePath))
    return nil
}

// Example: Adding concurrency with a mutex for thread-safe operations
var mu sync.Mutex

// ThreadSafeLogTransaction adds a transaction in a thread-safe manner
func (tr *TransparencyReport) ThreadSafeLogTransaction(id, ttype string, value float64, status string) {
    mu.Lock()
    defer mu.Unlock()
    tr.LogTransaction(id, ttype, value, status)
}
