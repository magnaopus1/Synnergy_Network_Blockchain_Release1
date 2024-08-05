package performance_tests

import (
	"log"
	"os"
	"os/exec"
	"runtime"
	"sync"
	"time"
	"io/ioutil"
	"net/http"
)

// ResourceUsage holds the resource utilization metrics
type ResourceUsage struct {
	CPUUsage     float64
	MemoryUsage  float64
	BandwidthUsage float64
}

// MonitorResourceUsage monitors CPU, memory, and bandwidth usage
func MonitorResourceUsage(interval time.Duration) {
	var wg sync.WaitGroup
	wg.Add(3)

	usage := &ResourceUsage{}

	go monitorCPUUsage(interval, usage, &wg)
	go monitorMemoryUsage(interval, usage, &wg)
	go monitorBandwidthUsage(interval, usage, &wg)

	wg.Wait()

	logResourceUsage(usage)
}

// monitorCPUUsage monitors the CPU usage
func monitorCPUUsage(interval time.Duration, usage *ResourceUsage, wg *sync.WaitGroup) {
	defer wg.Done()

	for {
		cpuUsage, err := getCPUUsage()
		if err != nil {
			log.Printf("Error getting CPU usage: %v", err)
			return
		}
		usage.CPUUsage = cpuUsage
		time.Sleep(interval)
	}
}

// getCPUUsage retrieves the current CPU usage
func getCPUUsage() (float64, error) {
	// Platform-specific implementation for CPU usage
	switch runtime.GOOS {
	case "linux":
		return getCPUUsageLinux()
	case "darwin":
		return getCPUUsageMac()
	case "windows":
		return getCPUUsageWindows()
	default:
		return 0, nil
	}
}

// getCPUUsageLinux retrieves CPU usage on Linux
func getCPUUsageLinux() (float64, error) {
	out, err := exec.Command("sh", "-c", "top -bn1 | grep 'Cpu(s)' | awk '{print $2 + $4}'").Output()
	if err != nil {
		return 0, err
	}
	var cpuUsage float64
	fmt.Sscanf(string(out), "%f", &cpuUsage)
	return cpuUsage, nil
}

// getCPUUsageMac retrieves CPU usage on MacOS
func getCPUUsageMac() (float64, error) {
	out, err := exec.Command("sh", "-c", "ps -A -o %cpu | awk '{s+=$1} END {print s}'").Output()
	if err != nil {
		return 0, err
	}
	var cpuUsage float64
	fmt.Sscanf(string(out), "%f", &cpuUsage)
	return cpuUsage, nil
}

// getCPUUsageWindows retrieves CPU usage on Windows
func getCPUUsageWindows() (float64, error) {
	out, err := exec.Command("cmd", "/C", "wmic cpu get loadpercentage").Output()
	if err != nil {
		return 0, err
	}
	var cpuUsage float64
	fmt.Sscanf(string(out), "%f", &cpuUsage)
	return cpuUsage, nil
}

// monitorMemoryUsage monitors the memory usage
func monitorMemoryUsage(interval time.Duration, usage *ResourceUsage, wg *sync.WaitGroup) {
	defer wg.Done()

	for {
		memoryUsage, err := getMemoryUsage()
		if err != nil {
			log.Printf("Error getting memory usage: %v", err)
			return
		}
		usage.MemoryUsage = memoryUsage
		time.Sleep(interval)
	}
}

// getMemoryUsage retrieves the current memory usage
func getMemoryUsage() (float64, error) {
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)
	return float64(mem.Alloc) / 1024 / 1024, nil // Convert bytes to MB
}

// monitorBandwidthUsage monitors the bandwidth usage
func monitorBandwidthUsage(interval time.Duration, usage *ResourceUsage, wg *sync.WaitGroup) {
	defer wg.Done()

	for {
		bandwidthUsage, err := getBandwidthUsage()
		if err != nil {
			log.Printf("Error getting bandwidth usage: %v", err)
			return
		}
		usage.BandwidthUsage = bandwidthUsage
		time.Sleep(interval)
	}
}

// getBandwidthUsage retrieves the current bandwidth usage
func getBandwidthUsage() (float64, error) {
	// This is a simple placeholder implementation, real-world implementation would need actual network monitoring
	resp, err := http.Get("http://example.com")
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return 0, err
	}
	return float64(len(body)) / 1024, nil // Convert bytes to KB
}

// logResourceUsage logs the resource utilization
func logResourceUsage(usage *ResourceUsage) {
	log.Printf("CPU Usage: %.2f%%", usage.CPUUsage)
	log.Printf("Memory Usage: %.2f MB", usage.MemoryUsage)
	log.Printf("Bandwidth Usage: %.2f KB/s", usage.BandwidthUsage)
}

func main() {
	interval := 10 * time.Second
	MonitorResourceUsage(interval)
}
