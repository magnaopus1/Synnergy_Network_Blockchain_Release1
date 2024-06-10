package resource_utilization

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"runtime"
	"sync"
	"time"

	"github.com/shirou/gopsutil/cpu"
	"github.com/shirou/gopsutil/disk"
	"github.com/shirou/gopsutil/mem"
	"github.com/synthron_blockchain_final/pkg/layer0/monitoring/performance_metrics"
	"github.com/synthron_blockchain_final/pkg/security"
)

type ResourceMonitor struct {
	metricsManager     *performance_metrics.PerformanceMetricsManager
	alertSubscribers   map[string][]chan string
	mutex              sync.RWMutex
	secureCommunicator *security.SecureCommunicator
}

// NewResourceMonitor creates a new instance of ResourceMonitor.
func NewResourceMonitor() *ResourceMonitor {
	secureComm, err := security.NewSecureCommunicator("securepassphrase")
	if err != nil {
		log.Fatalf("Failed to initialize secure communicator: %v\n", err)
	}

	return &ResourceMonitor{
		metricsManager:   performance_metrics.NewPerformanceMetricsManager(),
		alertSubscribers: make(map[string][]chan string),
		secureCommunicator: secureComm,
	}
}

// GetCPUUtilization returns the current CPU usage as a percentage.
func (rm *ResourceMonitor) GetCPUUtilization() (float64, error) {
	percentages, err := cpu.Percent(0, false)
	if err != nil {
		return 0, fmt.Errorf("error getting CPU utilization: %w", err)
	}
	if len(percentages) > 0 {
		return percentages[0], nil
	}
	return 0, fmt.Errorf("no CPU utilization data available")
}

// GetMemoryUtilization returns the current memory usage.
func (rm *ResourceMonitor) GetMemoryUtilization() (float64, error) {
	vmStat, err := mem.VirtualMemory()
	if err != nil {
		return 0, fmt.Errorf("error getting memory utilization: %w", err)
	}
	return vmStat.UsedPercent, nil
}

// GetDiskUtilization returns the current disk usage.
func (rm *ResourceMonitor) GetDiskUtilization() (float64, error) {
	diskStat, err := disk.Usage("/")
	if err != nil {
		return 0, fmt.Errorf("error getting disk utilization: %w", err)
	}
	return diskStat.UsedPercent, nil
}

// MonitorResources continuously monitors system resources and triggers alerts if thresholds are exceeded.
func (rm *ResourceMonitor) MonitorResources(cpuThreshold, memThreshold, diskThreshold float64) {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		rm.checkResourceUsage(cpuThreshold, memThreshold, diskThreshold)
	}
}

func (rm *ResourceMonitor) checkResourceUsage(cpuThreshold, memThreshold, diskThreshold float64) {
	cpuUtil, err := rm.GetCPUUtilization()
	if err != nil {
		log.Printf("Error getting CPU utilization: %v\n", err)
	} else if cpuUtil > cpuThreshold {
		rm.triggerAlert("CPU", cpuUtil)
	}

	memUtil, err := rm.GetMemoryUtilization()
	if err != nil {
		log.Printf("Error getting memory utilization: %v\n", err)
	} else if memUtil > memThreshold {
		rm.triggerAlert("Memory", memUtil)
	}

	diskUtil, err := rm.GetDiskUtilization()
	if err != nil {
		log.Printf("Error getting disk utilization: %v\n", err)
	} else if diskUtil > diskThreshold {
		rm.triggerAlert("Disk", diskUtil)
	}
}

func (rm *ResourceMonitor) triggerAlert(resource string, usage float64) {
	rm.mutex.Lock()
	defer rm.mutex.Unlock()

	alertMessage := fmt.Sprintf("Alert! %s utilization exceeded threshold with usage: %f%%", resource, usage)
	log.Println(alertMessage)

	for _, subscriber := range rm.alertSubscribers[resource] {
		subscriber <- alertMessage
	}

	// Securely log the alert
	encryptedMessage, err := rm.secureCommunicator.Encrypt([]byte(alertMessage))
	if err != nil {
		log.Printf("Failed to encrypt alert message: %v\n", err)
		return
	}
	log.Printf("Encrypted alert message: %s\n", encryptedMessage)
}

// SubscribeToResourceAlerts allows a subscriber to receive alerts for a specific resource.
func (rm *ResourceMonitor) SubscribeToResourceAlerts(resource string, subscriber chan string) {
	rm.mutex.Lock()
	defer rm.mutex.Unlock()
	rm.alertSubscribers[resource] = append(rm.alertSubscribers[resource], subscriber)
}

// ServeHTTP serves the resource monitoring data via HTTP.
func (rm *ResourceMonitor) ServeHTTP(port string) {
	http.HandleFunc("/subscribe_to_resource_alert", rm.handleSubscribeToResourceAlertRequest)
	http.HandleFunc("/current_resource_utilization", rm.handleCurrentResourceUtilizationRequest)
	log.Printf("Serving resource monitoring system on port %s\n", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}

func (rm *ResourceMonitor) handleSubscribeToResourceAlertRequest(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Resource   string `json:"resource"`
		Subscriber string `json:"subscriber"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	subscriberChan := make(chan string)
	rm.SubscribeToResourceAlerts(req.Resource, subscriberChan)

	go func() {
		for alert := range subscriberChan {
			// Handle alert notifications to subscriber (e.g., send via WebSocket, email, etc.)
			log.Printf("Sending alert to subscriber %s: %s\n", req.Subscriber, alert)
		}
	}()

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Subscribed to resource alert"))
}

func (rm *ResourceMonitor) handleCurrentResourceUtilizationRequest(w http.ResponseWriter, r *http.Request) {
	cpuUtil, err := rm.GetCPUUtilization()
	if err != nil {
		http.Error(w, "Failed to get CPU utilization", http.StatusInternalServerError)
		return
	}

	memUtil, err := rm.GetMemoryUtilization()
	if err != nil {
		http.Error(w, "Failed to get memory utilization", http.StatusInternalServerError)
		return
	}

	diskUtil, err := rm.GetDiskUtilization()
	if err != nil {
		http.Error(w, "Failed to get disk utilization", http.StatusInternalServerError)
		return
	}

	resourceUtilization := map[string]float64{
		"CPU":    cpuUtil,
		"Memory": memUtil,
		"Disk":   diskUtil,
	}

	data, err := json.Marshal(resourceUtilization)
	if err != nil {
		http.Error(w, "Failed to marshal resource utilization", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(data)
}

// main function to start the resource monitoring server
func main() {
	resourceMonitor := NewResourceMonitor()
	go resourceMonitor.MonitorResources(80.0, 80.0, 90.0) // Set thresholds for CPU, Memory, and Disk utilization
	resourceMonitor.ServeHTTP("8083")
}
