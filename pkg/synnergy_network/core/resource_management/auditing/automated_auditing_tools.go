package auditing

import (
	"encoding/json"
	"errors"
	"log"
	"time"
	"sync"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"net/http"
	"os"
	"path/filepath"
)

// AuditLog represents a single audit entry in the system
type AuditLog struct {
	Timestamp       time.Time
	NodeID          string
	Action          string
	ResourceType    string
	AmountAllocated float64
	Success         bool
	Details         string
}

// Auditor handles automated auditing processes within the Synnergy Network
type Auditor struct {
	AuditLogs   []AuditLog
	Thresholds  map[string]float64
	Alerts      []string
	AlertChan   chan string
	DataStore   DataStore
	mu          sync.Mutex
}

// DataStore is an interface for storing and retrieving audit logs
type DataStore interface {
	StoreLog(log AuditLog) error
	FetchLogs() ([]AuditLog, error)
}

// NewAuditor initializes a new Auditor with given thresholds
func NewAuditor(dataStore DataStore, thresholds map[string]float64) *Auditor {
	return &Auditor{
		Thresholds: thresholds,
		AlertChan:  make(chan string),
		DataStore:  dataStore,
	}
}

// LogAction logs a resource allocation action for auditing
func (a *Auditor) LogAction(nodeID, action, resourceType string, amountAllocated float64, success bool, details string) {
	auditLog := AuditLog{
		Timestamp:       time.Now(),
		NodeID:          nodeID,
		Action:          action,
		ResourceType:    resourceType,
		AmountAllocated: amountAllocated,
		Success:         success,
		Details:         details,
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	a.AuditLogs = append(a.AuditLogs, auditLog)
	a.DataStore.StoreLog(auditLog)
	a.checkThresholds(auditLog)
}

// checkThresholds checks if any audit entry exceeds the defined thresholds and triggers an alert
func (a *Auditor) checkThresholds(log AuditLog) {
	if threshold, ok := a.Thresholds[log.ResourceType]; ok {
		if log.AmountAllocated > threshold {
			alert := "Threshold exceeded for " + log.ResourceType + " by Node " + log.NodeID
			a.AlertChan <- alert
			a.Alerts = append(a.Alerts, alert)
			log.Printf("ALERT: %s", alert)
		}
	}
}

// ExportLogs exports the audit logs to a JSON file
func (a *Auditor) ExportLogs() ([]byte, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	logs, err := a.DataStore.FetchLogs()
	if err != nil {
		return nil, err
	}
	return json.Marshal(logs)
}

// ImportLogs imports audit logs from a JSON file
func (a *Auditor) ImportLogs(data []byte) error {
	var logs []AuditLog
	if err := json.Unmarshal(data, &logs); err != nil {
		return err
	}
	for _, log := range logs {
		a.DataStore.StoreLog(log)
		a.mu.Lock()
		a.AuditLogs = append(a.AuditLogs, log)
		a.mu.Unlock()
	}
	return nil
}

// AutomatedAudit initiates automated auditing processes
func (a *Auditor) AutomatedAudit() {
	go func() {
		for alert := range a.AlertChan {
			log.Printf("Processing alert: %s", alert)
			// Handle alert (e.g., send notification, log for review, etc.)
		}
	}()
}

// MonitoringServer starts a Prometheus metrics server for real-time monitoring
func (a *Auditor) MonitoringServer() {
	http.Handle("/metrics", promhttp.Handler())
	log.Fatal(http.ListenAndServe(":2112", nil))
}

// RegisterMetrics registers Prometheus metrics for auditing
func (a *Auditor) RegisterMetrics() {
	resourceAllocations := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "resource_allocations",
			Help: "Count of resource allocations",
		},
		[]string{"resource_type"},
	)
	prometheus.MustRegister(resourceAllocations)

	go func() {
		for {
			select {
			case alert := <-a.AlertChan:
				resourceAllocations.With(prometheus.Labels{"resource_type": alert}).Inc()
			}
		}
	}()
}

// StoreLogToFile stores audit logs to a file for backup and compliance
func (a *Auditor) StoreLogToFile(filename string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	data, err := a.ExportLogs()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(filename), 0755); err != nil {
		return err
	}
	return os.WriteFile(filename, data, 0644)
}

// LoadLogFromFile loads audit logs from a file
func (a *Auditor) LoadLogFromFile(filename string) error {
	data, err := os.ReadFile(filename)
	if err != nil {
		return err
	}
	return a.ImportLogs(data)
}
