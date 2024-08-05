package allocation

import (
	"log"
	"sync"
	"time"
)

// Metrics stores real-time resource usage data.
type Metrics struct {
	CPUUsage         float64
	MemoryUsage      float64
	NetworkBandwidth float64
	TransactionRate  float64
}

// ResourceMonitor continuously monitors and reports the state of network resources.
type ResourceMonitor struct {
	metrics      Metrics
	alertThresholds Metrics
	alerts       chan string
	mu           sync.Mutex
	stopChan     chan struct{}
}

// NewResourceMonitor initializes a new ResourceMonitor with default settings.
func NewResourceMonitor() *ResourceMonitor {
	return &ResourceMonitor{
		metrics: Metrics{},
		alertThresholds: Metrics{
			CPUUsage:         80.0,
			MemoryUsage:      80.0,
			NetworkBandwidth: 1000.0, // Example in Mbps
			TransactionRate:  1000.0, // Example transactions per second
		},
		alerts:   make(chan string),
		stopChan: make(chan struct{}),
	}
}

// Start begins the monitoring process.
func (rm *ResourceMonitor) Start() {
	go rm.monitor()
	go rm.alertHandler()
}

// monitor gathers metrics periodically and checks against alert thresholds.
func (rm *ResourceMonitor) monitor() {
	ticker := time.NewTicker(10 * time.Second) // Adjust the frequency as needed
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			rm.collectMetrics()
			rm.checkAlerts()
		case <-rm.stopChan:
			return
		}
	}
}

// collectMetrics collects current metrics data. This function should interface with actual system monitoring tools.
func (rm *ResourceMonitor) collectMetrics() {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	// Mock data collection; replace with real data collection logic
	rm.metrics = Metrics{
		CPUUsage:         75.0,  // Example value, fetch real data
		MemoryUsage:      70.0,  // Example value, fetch real data
		NetworkBandwidth: 900.0, // Example value, fetch real data
		TransactionRate:  950.0, // Example value, fetch real data
	}
	log.Printf("Collected metrics: %+v\n", rm.metrics)
}

// checkAlerts checks if current metrics exceed the thresholds and sends alerts.
func (rm *ResourceMonitor) checkAlerts() {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	if rm.metrics.CPUUsage > rm.alertThresholds.CPUUsage {
		rm.alerts <- "High CPU usage"
	}
	if rm.metrics.MemoryUsage > rm.alertThresholds.MemoryUsage {
		rm.alerts <- "High Memory usage"
	}
	if rm.metrics.NetworkBandwidth > rm.alertThresholds.NetworkBandwidth {
		rm.alerts <- "High Network bandwidth usage"
	}
	if rm.metrics.TransactionRate > rm.alertThresholds.TransactionRate {
		rm.alerts <- "High Transaction rate"
	}
}

// alertHandler processes alerts and takes action.
func (rm *ResourceMonitor) alertHandler() {
	for alert := range rm.alerts {
		// Implement alert handling logic here: logging, notification, etc.
		log.Printf("ALERT: %s", alert)
		// Example: send email, adjust resource allocation, etc.
	}
}

// Stop halts the monitoring process.
func (rm *ResourceMonitor) Stop() {
	close(rm.stopChan)
	close(rm.alerts)
}
