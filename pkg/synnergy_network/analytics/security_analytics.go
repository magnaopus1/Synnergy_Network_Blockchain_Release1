package analytics

import (
    "encoding/json"
    "log"
    "time"

    "golang.org/x/crypto/argon2"
    "golang.org/x/crypto/scrypt"
)

// SecurityEvent represents a security-related event in the blockchain
type SecurityEvent struct {
    Timestamp    time.Time
    EventType    string
    Description  string
    Severity     string
    AffectedNode string
}

// SecurityMetrics aggregates security-related statistics
type SecurityMetrics struct {
    TotalEvents  int
    Critical     int
    High         int
    Medium       int
    Low          int
}

// SecurityAnalytics manages the logging and analysis of security events
type SecurityAnalytics struct {
    events   []SecurityEvent
    metrics  SecurityMetrics
}

// Constants for encryption settings
const (
    Salt       = "high-entropy-salt" // This should be securely generated and stored
    KeyLength  = 32
    ArgonTime  = 1
    ArgonMemory = 64 * 1024
    ArgonThreads = 4
    ScryptN    = 16384
    ScryptR    = 8
    ScryptP    = 1
)

// NewSecurityAnalytics creates a new SecurityAnalytics instance
func NewSecurityAnalytics() *SecurityAnalytics {
    return &SecurityAnalytics{}
}

// AddEvent logs a new security event into the system
func (sa *SecurityAnalytics) AddEvent(eventType, description, severity, affectedNode string) {
    event := SecurityEvent{
        Timestamp:    time.Now(),
        EventType:    eventType,
        Description:  description,
        Severity:     severity,
        AffectedNode: affectedNode,
    }
    sa.events = append(sa.events, event)
    sa.updateMetrics(severity)
    log.Printf("Security event added: %v", event)
}

// updateMetrics updates the metrics based on the severity of an event
func (sa *SecurityAnalytics) updateMetrics(severity string) {
    sa.metrics.TotalEvents++
    switch severity {
    case "Critical":
        sa.metrics.Critical++
    case "High":
        sa.metrics.High++
    case "Medium":
        sa.metrics.Medium++
    case "Low":
        sa.metrics.Low++
    }
}

// EncryptMetrics encrypts the metrics for secure storage
func (sa *SecurityAnalytics) EncryptMetrics(useArgon bool) ([]byte, error) {
    metricsJSON, err := json.Marshal(sa.metrics)
    if err != nil {
        log.Printf("Error marshaling metrics: %v", err)
        return nil, err
    }

    var encryptedData []byte
    if useArgon {
        encryptedData = argon2.IDKey(metricsJSON, []byte(Salt), ArgonTime, ArgonMemory, ArgonThreads, KeyLength)
    } else {
        encryptedData, err = scrypt.Key(metricsJSON, []byte(Salt), ScryptN, ScryptR, ScryptP, KeyLength)
        if err != nil {
            log.Printf("Error encrypting metrics: %v", err)
            return nil, err
        }
    }

    return encryptedData, nil
}

// main function to demonstrate usage
func main() {
    sa := NewSecurityAnalytics()
    sa.AddEvent("UnauthorizedAccess", "Attempted access by unauthorized user", "Critical", "NodeA")
    sa.AddEvent("DataLeak", "Sensitive data exposure detected", "High", "NodeB")

    encryptedMetrics, err := sa.EncryptMetrics(true)
    if err != nil {
        log.Fatalf("Failed to encrypt security metrics: %v", err)
    }

    log.Printf("Encrypted Security Metrics: %x", encryptedMetrics)
}
