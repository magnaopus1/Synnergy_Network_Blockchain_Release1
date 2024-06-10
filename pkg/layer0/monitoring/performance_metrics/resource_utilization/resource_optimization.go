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

type ResourceOptimization struct {
	metricsManager     *performance_metrics.PerformanceMetricsManager
	alertSubscribers   map[string][]chan string
	mutex              sync.RWMutex
	secureCommunicator *security.SecureCommunicator
}

// NewResourceOptimization creates a new instance of ResourceOptimization.
func NewResourceOptimization() *ResourceOptimization {
	secureComm, err := security.NewSecureCommunicator("securepassphrase")
	if err != nil {
		log.Fatalf("Failed to initialize secure communicator: %v\n", err)
	}

	return &ResourceOptimization{
		metricsManager:   performance_metrics.NewPerformanceMetricsManager(),
		alertSubscribers: make(map[string][]chan string),
		secureCommunicator: secureComm,
	}
}

// GetCPUUtilization returns the current CPU usage as a percentage.
func (ro *ResourceOptimization) GetCPUUtilization() (float64, error) {
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
func (ro *ResourceOptimization) GetMemoryUtilization() (float64, error) {
	vmStat, err := mem.VirtualMemory()
	if err != nil {
		return 0, fmt.Errorf("error getting memory utilization: %w", err)
	}
	return vmStat.UsedPercent, nil
}

// GetDiskUtilization returns the current disk usage.
func (ro *ResourceOptimization) GetDiskUtilization() (float64, error) {
	diskStat, err := disk.Usage("/")
	if err != nil {
		return 0, fmt.Errorf("error getting disk utilization: %w", err)
	}
	return diskStat.UsedPercent, nil
}

// OptimizeResources continuously monitors and optimizes system resources.
func (ro *ResourceOptimization) OptimizeResources(cpuThreshold, memThreshold, diskThreshold float64) {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		ro.optimizeResourceUsage(cpuThreshold, memThreshold, diskThreshold)
	}
}

func (ro *ResourceOptimization) optimizeResourceUsage(cpuThreshold, memThreshold, diskThreshold float64) {
	cpuUtil, err := ro.GetCPUUtilization()
	if err != nil {
		log.Printf("Error getting CPU utilization: %v\n", err)
	} else if cpuUtil > cpuThreshold {
		ro.triggerAlert("CPU", cpuUtil)
		ro.adjustResourceAllocation("CPU", cpuUtil)
	}

	memUtil, err := ro.GetMemoryUtilization()
	if err != nil {
		log.Printf("Error getting memory utilization: %v\n", err)
	} else if memUtil > memThreshold {
		ro.triggerAlert("Memory", memUtil)
		ro.adjustResourceAllocation("Memory", memUtil)
	}

	diskUtil, err := ro.GetDiskUtilization()
	if err != nil {
		log.Printf("Error getting disk utilization: %v\n", err)
	} else if diskUtil > diskThreshold {
		ro.triggerAlert("Disk", diskUtil)
		ro.adjustResourceAllocation("Disk", diskUtil)
	}
}

func (ro *ResourceOptimization) triggerAlert(resource string, usage float64) {
	ro.mutex.Lock()
	defer ro.mutex.Unlock()

	alertMessage := fmt.Sprintf("Alert! %s utilization exceeded threshold with usage: %f%%", resource, usage)
	log.Println(alertMessage)

	for _, subscriber := range ro.alertSubscribers[resource] {
		subscriber <- alertMessage
	}

	// Securely log the alert
	encryptedMessage, err := ro.secureCommunicator.Encrypt([]byte(alertMessage))
	if err != nil {
		log.Printf("Failed to encrypt alert message: %v\n", err)
		return
	}
	log.Printf("Encrypted alert message: %s\n", encryptedMessage)
}

func (ro *ResourceOptimization) adjustResourceAllocation(resource string, usage float64) {
	switch resource {
	case "CPU":
		// Example: Reduce CPU-intensive operations or prioritize critical tasks
		log.Printf("Optimizing CPU usage. Current usage: %f%%\n", usage)
	case "Memory":
		// Example: Clear cache or optimize memory usage
		log.Printf("Optimizing Memory usage. Current usage: %f%%\n", usage)
	case "Disk":
		// Example: Clean up disk space or move data to other storage
		log.Printf("Optimizing Disk usage. Current usage: %f%%\n", usage)
	default:
		log.Printf("Unknown resource type: %s\n", resource)
	}
}

// SubscribeToResourceAlerts allows a subscriber to receive alerts for a specific resource.
func (ro *ResourceOptimization) SubscribeToResourceAlerts(resource string, subscriber chan string) {
	ro.mutex.Lock()
	defer ro.mutex.Unlock()
	ro.alertSubscribers[resource] = append(ro.alertSubscribers[resource], subscriber)
}

// ServeHTTP serves the resource monitoring data via HTTP.
func (ro *ResourceOptimization) ServeHTTP(port string) {
	http.HandleFunc("/subscribe_to_resource_alert", ro.handleSubscribeToResourceAlertRequest)
	http.HandleFunc("/current_resource_utilization", ro.handleCurrentResourceUtilizationRequest)
	log.Printf("Serving resource optimization system on port %s\n", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}

func (ro *ResourceOptimization) handleSubscribeToResourceAlertRequest(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Resource   string `json:"resource"`
		Subscriber string `json:"subscriber"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	subscriberChan := make(chan string)
	ro.SubscribeToResourceAlerts(req.Resource, subscriberChan)

	go func() {
		for alert := range subscriberChan {
			// Handle alert notifications to subscriber (e.g., send via WebSocket, email, etc.)
			log.Printf("Sending alert to subscriber %s: %s\n", req.Subscriber, alert)
		}
	}()

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Subscribed to resource alert"))
}

func (ro *ResourceOptimization) handleCurrentResourceUtilizationRequest(w http.ResponseWriter, r *http.Request) {
	cpuUtil, err := ro.GetCPUUtilization()
	if err != nil {
		http.Error(w, "Failed to get CPU utilization", http.StatusInternalServerError)
		return
	}

	memUtil, err := ro.GetMemoryUtilization()
	if err != nil {
		http.Error(w, "Failed to get memory utilization", http.StatusInternalServerError)
		return
	}

	diskUtil, err := ro.GetDiskUtilization()
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

// main function to start the resource optimization server
func main() {
	resourceOptimization := NewResourceOptimization()
	go resourceOptimization.OptimizeResources(80.0, 80.0, 90.0) // Set thresholds for CPU, Memory, and Disk utilization
	resourceOptimization.ServeHTTP("8083")
}
