package performance_monitoring

import (
	"encoding/json"
	"log"
	"math"
	"os/exec"
	"runtime"
	"sync"
	"time"
)

// ResourceMetrics holds metrics about CPU, Memory, and Bandwidth usage
type ResourceMetrics struct {
	CPUUsage      float64 `json:"cpu_usage"`
	MemoryUsage   float64 `json:"memory_usage"`
	NetworkIn     float64 `json:"network_in"`
	NetworkOut    float64 `json:"network_out"`
	DiskUsage     float64 `json:"disk_usage"`
	Timestamp     int64   `json:"timestamp"`
}

// ResourceMonitor is responsible for collecting and reporting resource metrics
type ResourceMonitor struct {
	metrics     []ResourceMetrics
	mu          sync.Mutex
	reportFile  string
	collectFreq time.Duration
}

// NewResourceMonitor creates a new ResourceMonitor
func NewResourceMonitor(reportFile string, collectFreq time.Duration) *ResourceMonitor {
	return &ResourceMonitor{
		reportFile:  reportFile,
		collectFreq: collectFreq,
	}
}

// Start begins the resource monitoring process
func (rm *ResourceMonitor) Start() {
	go func() {
		ticker := time.NewTicker(rm.collectFreq)
		defer ticker.Stop()
		for range ticker.C {
			rm.collectMetrics()
		}
	}()
}

// collectMetrics gathers current resource metrics
func (rm *ResourceMonitor) collectMetrics() {
	metrics := ResourceMetrics{
		CPUUsage:    rm.getCPUUsage(),
		MemoryUsage: rm.getMemoryUsage(),
		NetworkIn:   rm.getNetworkUsage("in"),
		NetworkOut:  rm.getNetworkUsage("out"),
		DiskUsage:   rm.getDiskUsage(),
		Timestamp:   time.Now().Unix(),
	}

	rm.mu.Lock()
	rm.metrics = append(rm.metrics, metrics)
	rm.mu.Unlock()

	rm.writeReport()
}

// getCPUUsage returns the current CPU usage as a percentage
func (rm *ResourceMonitor) getCPUUsage() float64 {
	// Implementation for CPU usage monitoring
	cmd := exec.Command("sh", "-c", "top -bn2 | grep 'Cpu(s)' | tail -n 1 | awk '{print $2 + $4}'")
	out, err := cmd.Output()
	if err != nil {
		log.Printf("Error fetching CPU usage: %v", err)
		return 0
	}
	var cpuUsage float64
	fmt.Sscanf(string(out), "%f", &cpuUsage)
	return cpuUsage
}

// getMemoryUsage returns the current memory usage as a percentage
func (rm *ResourceMonitor) getMemoryUsage() float64 {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return float64(m.Alloc) / float64(m.Sys) * 100
}

// getNetworkUsage returns the current network usage (in or out) in bytes
func (rm *ResourceMonitor) getNetworkUsage(direction string) float64 {
	// Implementation for Network usage monitoring (direction: "in" or "out")
	return 0 // Placeholder
}

// getDiskUsage returns the current disk usage as a percentage
func (rm *ResourceMonitor) getDiskUsage() float64 {
	// Implementation for Disk usage monitoring
	return 0 // Placeholder
}

// writeReport writes the collected metrics to the report file
func (rm *ResourceMonitor) writeReport() {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	data, err := json.MarshalIndent(rm.metrics, "", "  ")
	if err != nil {
		log.Printf("Error marshalling metrics: %v", err)
		return
	}

	err = os.WriteFile(rm.reportFile, data, 0644)
	if err != nil {
		log.Printf("Error writing report file: %v", err)
	}
}

// GetMetrics returns the collected resource metrics
func (rm *ResourceMonitor) GetMetrics() []ResourceMetrics {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	return rm.metrics
}

// main is omitted based on the request
