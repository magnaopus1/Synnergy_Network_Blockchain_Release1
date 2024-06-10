package performance_metrics

import (
	"log"
	"sync"
	"time"

	"github.com/synthron_blockchain_final/pkg/layer0/monitoring/performance_metrics/resource_utilization"
	"github.com/synthron_blockchain_final/pkg/layer0/monitoring/performance_metrics/transaction_throughput"
	"github.com/synthron_blockchain_final/pkg/security"
)

// PerformanceMetricsManager manages all performance metrics related to the blockchain.
type PerformanceMetricsManager struct {
	nodeConnectivity       map[string]bool
	consensusAlgorithmData map[string]float64
	dataPropagationTimes   map[string]float64
	transactionThroughput  *transaction_throughput.ThroughputVisualizer
	resourceUtilization    *resource_utilization.ResourceMonitor
	mutex                  sync.Mutex
	secureCommunicator     *security.SecureCommunicator
	alertSubscribers       map[string][]chan string
}

// NewPerformanceMetricsManager creates a new instance of PerformanceMetricsManager.
func NewPerformanceMetricsManager() *PerformanceMetricsManager {
	secureComm, err := security.NewSecureCommunicator("securepassphrase")
	if err != nil {
		log.Fatalf("Failed to initialize secure communicator: %v\n", err)
	}

	return &PerformanceMetricsManager{
		nodeConnectivity:       make(map[string]bool),
		consensusAlgorithmData: make(map[string]float64),
		dataPropagationTimes:   make(map[string]float64),
		transactionThroughput:  transaction_throughput.NewThroughputVisualizer(),
		resourceUtilization:    resource_utilization.NewResourceMonitor(),
		secureCommunicator:     secureComm,
		alertSubscribers:       make(map[string][]chan string),
	}
}

// MonitorNodeConnectivity continuously monitors node connectivity.
func (pmm *PerformanceMetricsManager) MonitorNodeConnectivity() {
	for {
		pmm.checkNodeConnectivity()
		time.Sleep(1 * time.Minute)
	}
}

func (pmm *PerformanceMetricsManager) checkNodeConnectivity() {
	// Implementation to check node connectivity
	// This is a placeholder. Actual implementation will depend on the specific blockchain network.
	for node, connected := range pmm.nodeConnectivity {
		if !connected {
			pmm.triggerAlert("Node Connectivity", node)
		}
	}
}

// MonitorConsensusAlgorithm continuously monitors the performance of the consensus algorithm.
func (pmm *PerformanceMetricsManager) MonitorConsensusAlgorithm() {
	for {
		pmm.checkConsensusAlgorithm()
		time.Sleep(1 * time.Minute)
	}
}

func (pmm *PerformanceMetricsManager) checkConsensusAlgorithm() {
	// Placeholder for actual implementation
	for metric, value := range pmm.consensusAlgorithmData {
		if value > 100 { // Example threshold
			pmm.triggerAlert("Consensus Algorithm", metric)
		}
	}
}

// MonitorDataPropagation continuously monitors data propagation times.
func (pmm *PerformanceMetricsManager) MonitorDataPropagation() {
	for {
		pmm.checkDataPropagation()
		time.Sleep(1 * time.Minute)
	}
}

func (pmm *PerformanceMetricsManager) checkDataPropagation() {
	// Placeholder for actual implementation
	for metric, value := range pmm.dataPropagationTimes {
		if value > 10 { // Example threshold
			pmm.triggerAlert("Data Propagation", metric)
		}
	}
}

// SubscribeToAlerts allows a subscriber to receive alerts for a specific metric.
func (pmm *PerformanceMetricsManager) SubscribeToAlerts(metric string, subscriber chan string) {
	pmm.mutex.Lock()
	defer pmm.mutex.Unlock()
	pmm.alertSubscribers[metric] = append(pmm.alertSubscribers[metric], subscriber)
}

// triggerAlert triggers an alert for a specific metric.
func (pmm *PerformanceMetricsManager) triggerAlert(metric, value string) {
	pmm.mutex.Lock()
	defer pmm.mutex.Unlock()

	alertMessage := "Alert! " + metric + " exceeded threshold with value: " + value
	log.Println(alertMessage)

	for _, subscriber := range pmm.alertSubscribers[metric] {
		subscriber <- alertMessage
	}

	// Securely log the alert
	encryptedMessage, err := pmm.secureCommunicator.Encrypt([]byte(alertMessage))
	if err != nil {
		log.Printf("Failed to encrypt alert message: %v\n", err)
		return
	}
	log.Printf("Encrypted alert message: %s\n", encryptedMessage)
}

// StartMonitoring starts all monitoring processes.
func (pmm *PerformanceMetricsManager) StartMonitoring() {
	go pmm.MonitorNodeConnectivity()
	go pmm.MonitorConsensusAlgorithm()
	go pmm.MonitorDataPropagation()
	go pmm.transactionThroughput.MonitorThroughput(100.0) // Set threshold for throughput
	go pmm.resourceUtilization.MonitorResourceUtilization(80.0, 80.0, 80.0) // Set thresholds for CPU, Memory, and Disk
}

// main function to start the performance metrics manager
func main() {
	metricsManager := NewPerformanceMetricsManager()
	metricsManager.StartMonitoring()

	// Serve the transaction throughput visualization
	go metricsManager.transactionThroughput.ServeHTTP("8084")

	// Serve the resource utilization visualization
	go metricsManager.resourceUtilization.ServeHTTP("8085")

	select {}
}
