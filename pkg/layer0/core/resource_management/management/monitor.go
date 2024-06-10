package management

import (
	"log"
	"sync"
	"time"

	"github.com/synthron_blockchain/pkg/layer0/core/resource_management/utils"
)

// Monitor controls the monitoring of resource utilization within the blockchain system.
type Monitor struct {
	mutex                sync.Mutex
	resourceMetrics      ResourceMetrics
	monitoringInterval   time.Duration
	warningThresholds    ResourceThresholds
	criticalThresholds   ResourceThresholds
	lastMonitoringTime   time.Time
	resourceCheckHandler func(ResourceMetrics) ResourceStatus
}

// ResourceMetrics stores the current resource usage levels.
type ResourceMetrics struct {
	CPUUsage    float64 // in percentage
	MemoryUsage float64 // in MB
	NetworkIO   float64 // in Mbps
}

// ResourceThresholds defines the critical and warning thresholds for resource usage.
type ResourceThresholds struct {
	CPUThreshold    float64 // in percentage
	MemoryThreshold float64 // in MB
	NetworkThreshold float64 // in Mbps
}

// ResourceStatus represents the current status of resources, determined by thresholds.
type ResourceStatus struct {
	CPUStatus    string
	MemoryStatus string
	NetworkStatus string
}

// NewMonitor creates a new resource monitoring system with specified configurations.
func NewMonitor(interval time.Duration, warnThresholds, critThresholds ResourceThresholds, checkFunc func(ResourceMetrics) ResourceStatus) *Monitor {
	return &Monitor{
		monitoringInterval:   interval,
		warningThresholds:    warnThresholds,
		criticalThresholds:   critThresholds,
		resourceCheckHandler: checkFunc,
		lastMonitoringTime:   time.Now(),
	}
}

// Start begins the monitoring process in a separate goroutine to continuously check resource status.
func (m *Monitor) Start() {
	go m.monitorLoop()
}

// monitorLoop executes the resource check at specified intervals and logs status.
func (m *Monitor) monitorLoop() {
	ticker := time.NewTicker(m.monitoringInterval)
	defer ticker.Stop()

	for range ticker.C {
		metrics := m.fetchResourceMetrics()
		status := m.resourceCheckHandler(metrics)
		m.logResourceStatus(status)
	}
}

// fetchResourceMetrics simulates the collection of system metrics.
func (m *Monitor) fetchResourceMetrics() ResourceMetrics {
	// Simulated data fetching. Replace with real metrics collection logic.
	return ResourceMetrics{
		CPUUsage:    utils.RandomFloat(0, 100),
		MemoryUsage: utils.RandomFloat(0, 16000),
		NetworkIO:   utils.RandomFloat(0, 1000),
	}
}

// logResourceStatus logs the results from the monitoring checks.
func (m *Monitor) logResourceStatus(status ResourceStatus) {
	log.Printf("Resource Status - CPU: %s, Memory: %s, Network: %s", status.CPUStatus, status.MemoryStatus, status.NetworkStatus)
}

// EvaluateResourceMetrics evaluates resource metrics against predefined thresholds.
func EvaluateResourceMetrics(metrics ResourceMetrics, warnThresholds, critThresholds ResourceThresholds) ResourceStatus {
	status := ResourceStatus{}

	// Check CPU usage against thresholds.
	if metrics.CPUUsage > critThresholds.CPUThreshold {
		status.CPUStatus = "Critical"
	} else if metrics.CPUUsage > warnThresholds.CPUThreshold {
		status.CPUStatus = "Warning"
	} else {
		status.CPUStatus = "Normal"
	}

	// Check memory usage against thresholds.
	if metrics.MemoryUsage > critThresholds.MemoryThreshold {
		status.MemoryStatus = "Critical"
	} else if metrics.MemoryUsage > warnThresholds.MemoryThreshold {
		status.MemoryStatus = "Warning"
	} else {
		status.MemoryStatus = "Normal"
	}

	// Check network I/O against thresholds.
	if metrics.NetworkIO > critThresholds.NetworkThreshold {
		status.NetworkStatus = "Critical"
	} else if metrics.NetworkIO > warnThresholds.NetworkThreshold {
		status.NetworkStatus = "Warning"
	} else {
		status.NetworkStatus = "Normal"
	}

	return status
}

