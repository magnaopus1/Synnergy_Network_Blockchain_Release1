package auditing

import (
	"fmt"
	"time"
	"sync"
	"log"
)

// MetricsData struct holds metrics for resource usage
type MetricsData struct {
	CPUUsage       float64
	MemoryUsage    float64
	NetworkUsage   float64
	TransactionVolume int64
	Timestamp      time.Time
}

// ScalabilityAuditor is responsible for auditing and ensuring network scalability
type ScalabilityAuditor struct {
	metrics []MetricsData
	mutex   sync.Mutex
}

// NewScalabilityAuditor initializes a new instance of ScalabilityAuditor
func NewScalabilityAuditor() *ScalabilityAuditor {
	return &ScalabilityAuditor{
		metrics: make([]MetricsData, 0),
	}
}

// CollectMetrics collects and stores metrics data
func (sa *ScalabilityAuditor) CollectMetrics(cpu, memory, network float64, transactions int64) {
	sa.mutex.Lock()
	defer sa.mutex.Unlock()
	data := MetricsData{
		CPUUsage:        cpu,
		MemoryUsage:     memory,
		NetworkUsage:    network,
		TransactionVolume: transactions,
		Timestamp:       time.Now(),
	}
	sa.metrics = append(sa.metrics, data)
	log.Printf("Collected metrics: %+v\n", data)
}

// EvaluateScalability assesses the scalability of the network based on collected metrics
func (sa *ScalabilityAuditor) EvaluateScalability() (bool, error) {
	sa.mutex.Lock()
	defer sa.mutex.Unlock()
	// Example threshold values for scalability
	const cpuThreshold = 85.0
	const memoryThreshold = 80.0
	const networkThreshold = 90.0
	const transactionGrowthThreshold = 1.5 // 150% increase

	if len(sa.metrics) == 0 {
		return false, fmt.Errorf("no metrics available to evaluate")
	}

	latestMetrics := sa.metrics[len(sa.metrics)-1]
	isScalable := latestMetrics.CPUUsage < cpuThreshold &&
		latestMetrics.MemoryUsage < memoryThreshold &&
		latestMetrics.NetworkUsage < networkThreshold &&
		latestMetrics.TransactionVolume <= int64(float64(sa.metrics[0].TransactionVolume)*transactionGrowthThreshold)

	if !isScalable {
		log.Println("Scalability issues detected")
	} else {
		log.Println("Network is scalable")
	}

	return isScalable, nil
}

// OptimizeScalability suggests optimizations based on the evaluation of scalability
func (sa *ScalabilityAuditor) OptimizeScalability() {
	isScalable, err := sa.EvaluateScalability()
	if err != nil {
		log.Printf("Error evaluating scalability: %v\n", err)
		return
	}

	if !isScalable {
		// Example optimization actions
		log.Println("Suggesting optimizations:")
		log.Println("1. Increase computational resources.")
		log.Println("2. Optimize memory usage and reduce overhead.")
		log.Println("3. Enhance network bandwidth.")
		log.Println("4. Consider load balancing and scaling strategies.")
	} else {
		log.Println("No optimizations needed at this time.")
	}
}

// Report generates a report of the scalability audit
func (sa *ScalabilityAuditor) Report() {
	sa.mutex.Lock()
	defer sa.mutex.Unlock()
	log.Println("Generating scalability audit report...")
	for _, metric := range sa.metrics {
		log.Printf("Metrics at %s: CPU Usage: %.2f%%, Memory Usage: %.2f%%, Network Usage: %.2f%%, Transactions: %d\n",
			metric.Timestamp.Format(time.RFC3339), metric.CPUUsage, metric.MemoryUsage, metric.NetworkUsage, metric.TransactionVolume)
	}
	log.Println("Scalability audit report generated.")
}
