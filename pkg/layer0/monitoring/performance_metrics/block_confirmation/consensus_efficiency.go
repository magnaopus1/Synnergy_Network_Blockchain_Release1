package block_confirmation

import (
	"encoding/json"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/synthron_blockchain_final/pkg/layer0/monitoring/performance_metrics"
	"github.com/synthron_blockchain_final/pkg/layer0/monitoring/network_monitoring/data_propagation"
	"github.com/synthron_blockchain_final/pkg/layer0/monitoring/network_monitoring/geographical_visualization"
	"github.com/synthron_blockchain_final/pkg/layer0/monitoring/network_monitoring/node_connectivity"
	"github.com/synthron_blockchain_final/pkg/layer0/monitoring/network_monitoring/peer_communications"
	"github.com/synthron_blockchain_final/pkg/security"
)

// ConsensusEfficiencyManager monitors and analyzes the efficiency of the consensus algorithm
type ConsensusEfficiencyManager struct {
	validationTimes    map[string]time.Duration
	mutex              sync.RWMutex
	alertManager       *AlertManager
	peerCommunicator   *peer_communications.PeerCommunicator
	secureCommunicator *security.SecureCommunicator
}

func NewConsensusEfficiencyManager() *ConsensusEfficiencyManager {
	secureComm, err := security.NewSecureCommunicator("securepassphrase")
	if err != nil {
		log.Fatalf("Failed to initialize secure communicator: %v\n", err)
	}

	return &ConsensusEfficiencyManager{
		validationTimes:    make(map[string]time.Duration),
		alertManager:       NewAlertManager(5),
		secureCommunicator: secureComm,
	}
}

// LogValidationTime logs the time taken to validate a block
func (cem *ConsensusEfficiencyManager) LogValidationTime(blockID string, startTime, endTime time.Time) {
	duration := endTime.Sub(startTime)
	cem.mutex.Lock()
	defer cem.mutex.Unlock()
	cem.validationTimes[blockID] = duration
	cem.alertManager.CheckForAlerts(cem.validationTimes)
}

// GetValidationTimes returns the block validation times
func (cem *ConsensusEfficiencyManager) GetValidationTimes() map[string]time.Duration {
	cem.mutex.RLock()
	defer cem.mutex.RUnlock()
	return cem.validationTimes
}

// StartMonitoring initializes monitoring routines
func (cem *ConsensusEfficiencyManager) StartMonitoring() {
	go func() {
		for {
			time.Sleep(1 * time.Minute)
			cem.alertManager.CheckForAlerts(cem.validationTimes)
		}
	}()
}

// AlertManager handles alerts for validation times
type AlertManager struct {
	alertThreshold int
	alertChan      chan string
}

func NewAlertManager(threshold int) *AlertManager {
	return &AlertManager{
		alertThreshold: threshold,
		alertChan:      make(chan string),
	}
}

// CheckForAlerts checks for alerts based on validation times
func (am *AlertManager) CheckForAlerts(validationTimes map[string]time.Duration) {
	var slowBlocks []string
	for blockID, duration := range validationTimes {
		if duration > 2*time.Minute { // Example threshold
			slowBlocks = append(slowBlocks, blockID)
		}
	}
	if len(slowBlocks) >= am.alertThreshold {
		alert := am.createAlert(slowBlocks)
		log.Println(alert)
		am.alertChan <- alert
	}
}

func (am *AlertManager) createAlert(slowBlocks []string) string {
	return log.Sprintf("Alert: %d blocks took too long to validate: %v", len(slowBlocks), slowBlocks)
}

// GetAlertChannel returns the alert channel
func (am *AlertManager) GetAlertChannel() <-chan string {
	return am.alertChan
}

// NetworkMonitor integrates all monitoring components
type NetworkMonitor struct {
	nodeManager          *node_connectivity.NodeConnectivityManager
	metricsManager       *performance_metrics.PerformanceMetricsManager
	dataPropagation      *data_propagation.DataPropagationAnalyzer
	geoVisualization     *geographical_visualization.GeoVisualization
	consensusEfficiency  *ConsensusEfficiencyManager
	alertManager         *AlertManager
	peerCommunicator     *peer_communications.PeerCommunicator
	secureCommunicator   *security.SecureCommunicator
}

func NewNetworkMonitor() *NetworkMonitor {
	ncm := node_connectivity.NewNodeConnectivityManager()
	metricsManager := performance_metrics.NewPerformanceMetricsManager()
	dataPropagation := data_propagation.NewDataPropagationAnalyzer()
	geoVisualization := geographical_visualization.NewGeoVisualization()
	consensusEfficiency := NewConsensusEfficiencyManager()
	alertManager := NewAlertManager(5)
	secureComm, err := security.NewSecureCommunicator("securepassphrase")
	if err != nil {
		log.Fatalf("Failed to initialize secure communicator: %v\n", err)
	}
	peerCommunicator := peer_communications.NewPeerCommunicator(ncm, secureComm)

	return &NetworkMonitor{
		nodeManager:         ncm,
		metricsManager:      metricsManager,
		dataPropagation:     dataPropagation,
		geoVisualization:    geoVisualization,
		consensusEfficiency: consensusEfficiency,
		alertManager:        alertManager,
		peerCommunicator:    peerCommunicator,
	}
}

func (nm *NetworkMonitor) StartMonitoring() {
	go nm.nodeManager.CheckAllNodesConnectivity()
	go nm.metricsManager.StartCollectingMetrics()
	go nm.dataPropagation.AnalyzeDataPropagation()
	go nm.geoVisualization.VisualizeGeographicalData()
	nm.consensusEfficiency.StartMonitoring()
	nm.alertManager.StartMonitoring(nm.consensusEfficiency)
	nm.peerCommunicator.HandlePeerCommunication()
}

func (nm *NetworkMonitor) ServeHTTP(port string) {
	http.HandleFunc("/nodes", nm.handleNodesRequest)
	http.HandleFunc("/metrics", nm.handleMetricsRequest)
	http.HandleFunc("/alerts", nm.handleAlertsRequest)
	http.HandleFunc("/validation_times", nm.handleValidationTimesRequest)
	log.Printf("Serving network monitoring status on port %s\n", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}

func (nm *NetworkMonitor) handleNodesRequest(w http.ResponseWriter, r *http.Request) {
	nodes := nm.nodeManager.GetAllNodesStatus()
	data, err := json.Marshal(nodes)
	if err != nil {
		http.Error(w, "Failed to marshal nodes status", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(data)
}

func (nm *NetworkMonitor) handleMetricsRequest(w http.ResponseWriter, r *http.Request) {
	metrics := nm.metricsManager.GetMetrics()
	data, err := json.Marshal(metrics)
	if err != nil {
		http.Error(w, "Failed to marshal metrics", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(data)
}

func (nm *NetworkMonitor) handleAlertsRequest(w http.ResponseWriter, r *http.Request) {
	alerts := make([]string, 0)
	alertChan := nm.alertManager.GetAlertChannel()
	for {
		select {
		case alert := <-alertChan:
			alerts = append(alerts, alert)
		default:
			data, err := json.Marshal(alerts)
			if err != nil {
				http.Error(w, "Failed to marshal alerts", http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.Write(data)
			return
		}
	}
}

func (nm *NetworkMonitor) handleValidationTimesRequest(w http.ResponseWriter, r *http.Request) {
	validationTimes := nm.consensusEfficiency.GetValidationTimes()
	data, err := json.Marshal(validationTimes)
	if err != nil {
		http.Error(w, "Failed to marshal validation times", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(data)
}

func main() {
	nm := NewNetworkMonitor()
	nm.StartMonitoring()
	nm.ServeHTTP("8080")
}
