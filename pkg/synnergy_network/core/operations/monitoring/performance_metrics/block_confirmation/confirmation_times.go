package block_confirmation

import (
	"encoding/json"
	"log"
	"sync"
	"time"

	"github.com/synthron_blockchain_final/pkg/layer0/monitoring/performance_metrics"
	"github.com/synthron_blockchain_final/pkg/layer0/monitoring/network_monitoring/data_propagation"
	"github.com/synthron_blockchain_final/pkg/layer0/monitoring/network_monitoring/geographical_visualization"
	"github.com/synthron_blockchain_final/pkg/layer0/monitoring/network_monitoring/node_connectivity"
)

// ConfirmationTimesManager is responsible for monitoring and analyzing block confirmation times
type ConfirmationTimesManager struct {
	confirmationTimes map[string]time.Duration
	mutex             sync.RWMutex
	alertManager      *AlertManager
}

func NewConfirmationTimesManager() *ConfirmationTimesManager {
	return &ConfirmationTimesManager{
		confirmationTimes: make(map[string]time.Duration),
		alertManager:      NewAlertManager(5),
	}
}

// LogBlockConfirmation logs the time taken to confirm a block
func (ctm *ConfirmationTimesManager) LogBlockConfirmation(blockID string, startTime, endTime time.Time) {
	duration := endTime.Sub(startTime)
	ctm.mutex.Lock()
	defer ctm.mutex.Unlock()
	ctm.confirmationTimes[blockID] = duration
	ctm.alertManager.CheckForAlerts(ctm.confirmationTimes)
}

// GetConfirmationTimes returns the block confirmation times
func (ctm *ConfirmationTimesManager) GetConfirmationTimes() map[string]time.Duration {
	ctm.mutex.RLock()
	defer ctm.mutex.RUnlock()
	return ctm.confirmationTimes
}

// StartMonitoring initializes monitoring routines
func (ctm *ConfirmationTimesManager) StartMonitoring() {
	go func() {
		for {
			time.Sleep(1 * time.Minute)
			ctm.alertManager.CheckForAlerts(ctm.confirmationTimes)
		}
	}()
}

// AlertManager handles alerts for confirmation times
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

// CheckForAlerts checks for alerts based on confirmation times
func (am *AlertManager) CheckForAlerts(confirmationTimes map[string]time.Duration) {
	var slowBlocks []string
	for blockID, duration := range confirmationTimes {
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
	return log.Sprintf("Alert: %d blocks took too long to confirm: %v", len(slowBlocks), slowBlocks)
}

// GetAlertChannel returns the alert channel
func (am *AlertManager) GetAlertChannel() <-chan string {
	return am.alertChan
}

// NetworkMonitor integrates all monitoring components
type NetworkMonitor struct {
	nodeManager           *node_connectivity.NodeConnectivityManager
	metricsManager        *performance_metrics.PerformanceMetricsManager
	dataPropagation       *data_propagation.DataPropagationAnalyzer
	geoVisualization      *geographical_visualization.GeoVisualization
	confirmationTimesMgr  *ConfirmationTimesManager
	alertManager          *AlertManager
	peerCommunicator      *PeerCommunicator
}

func NewNetworkMonitor() *NetworkMonitor {
	ncm := node_connectivity.NewNodeConnectivityManager()
	metricsManager := performance_metrics.NewPerformanceMetricsManager()
	dataPropagation := data_propagation.NewDataPropagationAnalyzer()
	geoVisualization := geographical_visualization.NewGeoVisualization()
	confirmationTimesMgr := NewConfirmationTimesManager()
	alertManager := NewAlertManager(5)
	secureComm, err := NewSecureCommunicator("securepassphrase")
	if err != nil {
		log.Fatalf("Failed to initialize secure communicator: %v\n", err)
	}
	peerCommunicator := NewPeerCommunicator(ncm, secureComm)

	return &NetworkMonitor{
		nodeManager:           ncm,
		metricsManager:        metricsManager,
		dataPropagation:       dataPropagation,
		geoVisualization:      geoVisualization,
		confirmationTimesMgr:  confirmationTimesMgr,
		alertManager:          alertManager,
		peerCommunicator:      peerCommunicator,
	}
}

func (nm *NetworkMonitor) StartMonitoring() {
	go nm.nodeManager.CheckAllNodesConnectivity()
	go nm.metricsManager.StartCollectingMetrics()
	go nm.dataPropagation.AnalyzeDataPropagation()
	go nm.geoVisualization.VisualizeGeographicalData()
	nm.confirmationTimesMgr.StartMonitoring()
	nm.alertManager.StartMonitoring(nm.confirmationTimesMgr)
	nm.peerCommunicator.HandlePeerCommunication()
}

func (nm *NetworkMonitor) ServeHTTP(port string) {
	http.HandleFunc("/nodes", nm.handleNodesRequest)
	http.HandleFunc("/metrics", nm.handleMetricsRequest)
	http.HandleFunc("/alerts", nm.handleAlertsRequest)
	http.HandleFunc("/confirmation_times", nm.handleConfirmationTimesRequest)
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

func (nm *NetworkMonitor) handleConfirmationTimesRequest(w http.ResponseWriter, r *http.Request) {
	confirmationTimes := nm.confirmationTimesMgr.GetConfirmationTimes()
	data, err := json.Marshal(confirmationTimes)
	if err != nil {
		http.Error(w, "Failed to marshal confirmation times", http.StatusInternalServerError)
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
