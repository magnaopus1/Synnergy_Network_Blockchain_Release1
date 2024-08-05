package fault_detection

import (
	"log"
	"time"
	"math/rand"
	"sync"
	"github.com/synnergy_network/pkg/synnergy_network/utils"
)

// HealthCheck defines the structure of a health check
type HealthCheck struct {
	ID          string
	Description string
	Timestamp   time.Time
	Status      string
	Details     string
}

// HealthCheckResult defines the result structure for health checks
type HealthCheckResult struct {
	ID        string
	NodeID    string
	CheckID   string
	Timestamp time.Time
	Status    string
	Details   string
}

// HealthCheckManager handles the execution and management of health checks
type HealthCheckManager struct {
	healthChecks []HealthCheck
	results      []HealthCheckResult
	mu           sync.Mutex
}

// NewHealthCheckManager creates a new instance of HealthCheckManager
func NewHealthCheckManager() *HealthCheckManager {
	return &HealthCheckManager{
		healthChecks: []HealthCheck{},
		results:      []HealthCheckResult{},
	}
}

// AddHealthCheck adds a new health check to the manager
func (hcm *HealthCheckManager) AddHealthCheck(description string) string {
	hcm.mu.Lock()
	defer hcm.mu.Unlock()

	id := utils.GenerateID()
	healthCheck := HealthCheck{
		ID:          id,
		Description: description,
		Timestamp:   time.Now(),
		Status:      "Pending",
		Details:     "",
	}
	hcm.healthChecks = append(hcm.healthChecks, healthCheck)
	return id
}

// RunHealthChecks executes all health checks and updates their results
func (hcm *HealthCheckManager) RunHealthChecks(nodeID string) {
	hcm.mu.Lock()
	defer hcm.mu.Unlock()

	for _, hc := range hcm.healthChecks {
		status, details := executeHealthCheck(hc)
		result := HealthCheckResult{
			ID:        utils.GenerateID(),
			NodeID:    nodeID,
			CheckID:   hc.ID,
			Timestamp: time.Now(),
			Status:    status,
			Details:   details,
		}
		hcm.results = append(hcm.results, result)
		hc.Status = status
		hc.Details = details
	}
}

// executeHealthCheck simulates the execution of a health check
func executeHealthCheck(hc HealthCheck) (string, string) {
	// Simulate random health check results
	statuses := []string{"Healthy", "Warning", "Critical"}
	status := statuses[rand.Intn(len(statuses))]
	details := "Health check executed successfully"
	if status == "Critical" {
		details = "Critical issue detected"
	} else if status == "Warning" {
		details = "Potential issue detected"
	}
	return status, details
}

// GetResults returns all health check results
func (hcm *HealthCheckManager) GetResults() []HealthCheckResult {
	hcm.mu.Lock()
	defer hcm.mu.Unlock()

	return hcm.results
}

// HealthCheckScheduler periodically runs health checks
type HealthCheckScheduler struct {
	manager   *HealthCheckManager
	interval  time.Duration
	stopChan  chan bool
	nodeID    string
}

// NewHealthCheckScheduler creates a new health check scheduler
func NewHealthCheckScheduler(manager *HealthCheckManager, interval time.Duration, nodeID string) *HealthCheckScheduler {
	return &HealthCheckScheduler{
		manager:  manager,
		interval: interval,
		stopChan: make(chan bool),
		nodeID:   nodeID,
	}
}

// Start begins the periodic execution of health checks
func (hcs *HealthCheckScheduler) Start() {
	go func() {
		ticker := time.NewTicker(hcs.interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				hcs.manager.RunHealthChecks(hcs.nodeID)
			case <-hcs.stopChan:
				return
			}
		}
	}()
}

// Stop halts the periodic execution of health checks
func (hcs *HealthCheckScheduler) Stop() {
	hcs.stopChan <- true
}

