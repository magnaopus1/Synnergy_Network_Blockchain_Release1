package real_time_alerts

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/synthron_blockchain_final/pkg/layer0/monitoring/performance_metrics"
	"github.com/synthron_blockchain_final/pkg/layer0/monitoring/predictive_maintenance"
	"github.com/synthron_blockchain_final/pkg/layer0/monitoring/network_monitoring/data_propagation"
	"github.com/synthron_blockchain_final/pkg/layer0/monitoring/network_monitoring/geographical_visualization"
	"github.com/synthron_blockchain_final/pkg/layer0/monitoring/network_monitoring/node_connectivity"
	"github.com/synthron_blockchain_final/pkg/layer0/monitoring/network_monitoring/peer_communications"
	"github.com/synthron_blockchain_final/pkg/security"
	"github.com/synthron_blockchain_final/pkg/layer0/monitoring/network_monitoring/anomaly_detection"
)

// AlertSystem manages real-time alerts based on performance metrics.
type AlertSystem struct {
	metricsManager       *performance_metrics.PerformanceMetricsManager
	predictiveManager    *predictive_maintenance.PredictiveMaintenanceManager
	dataPropagation      *data_propagation.DataPropagationAnalyzer
	geoVisualization     *geographical_visualization.GeoVisualization
	anomalyDetection     *anomaly_detection.AnomalyDetection
	alerts               map[string]bool
	alertThresholds      map[string]float64
	alertSubscribers     map[string][]chan string
	mutex                sync.RWMutex
	secureCommunicator   *security.SecureCommunicator
}

// NewAlertSystem creates a new instance of AlertSystem.
func NewAlertSystem() *AlertSystem {
	secureComm, err := security.NewSecureCommunicator("securepassphrase")
	if err != nil {
		log.Fatalf("Failed to initialize secure communicator: %v\n", err)
	}

	return &AlertSystem{
		metricsManager:    performance_metrics.NewPerformanceMetricsManager(),
		predictiveManager: predictive_maintenance.NewPredictiveMaintenanceManager(),
		dataPropagation:   data_propagation.NewDataPropagationAnalyzer(),
		geoVisualization:  geographical_visualization.NewGeoVisualization(),
		anomalyDetection:  anomaly_detection.NewAnomalyDetection(),
		alerts:            make(map[string]bool),
		alertThresholds:   make(map[string]float64),
		alertSubscribers:  make(map[string][]chan string),
		secureCommunicator: secureComm,
	}
}

// SetAlertThreshold sets the threshold for a specific metric.
func (as *AlertSystem) SetAlertThreshold(metric string, threshold float64) {
	as.mutex.Lock()
	defer as.mutex.Unlock()
	as.alertThresholds[metric] = threshold
}

// SubscribeToAlert allows a subscriber to receive alerts for a specific metric.
func (as *AlertSystem) SubscribeToAlert(metric string, subscriber chan string) {
	as.mutex.Lock()
	defer as.mutex.Unlock()
	as.alertSubscribers[metric] = append(as.alertSubscribers[metric], subscriber)
}

// MonitorMetrics monitors performance metrics and triggers alerts if thresholds are exceeded.
func (as *AlertSystem) MonitorMetrics() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		as.mutex.RLock()
		for metric, threshold := range as.alertThresholds {
			value, err := as.metricsManager.GetMetricValue(metric)
			if err != nil {
				log.Printf("Error getting metric value for %s: %v\n", metric, err)
				continue
			}

			if value > threshold {
				as.triggerAlert(metric, value)
			}
		}
		as.mutex.RUnlock()
	}
}

func (as *AlertSystem) triggerAlert(metric string, value float64) {
	as.mutex.Lock()
	defer as.mutex.Unlock()

	alertMessage := fmt.Sprintf("Alert! %s exceeded threshold with value %f", metric, value)
	log.Println(alertMessage)

	if as.alerts[metric] {
		return // Alert already triggered
	}

	as.alerts[metric] = true
	for _, subscriber := range as.alertSubscribers[metric] {
		subscriber <- alertMessage
	}

	// Securely log the alert
	encryptedMessage, err := as.secureCommunicator.Encrypt([]byte(alertMessage))
	if err != nil {
		log.Printf("Failed to encrypt alert message: %v\n", err)
		return
	}
	log.Printf("Encrypted alert message: %s\n", encryptedMessage)
}

// ServeHTTP serves the real-time alert data via HTTP.
func (as *AlertSystem) ServeHTTP(port string) {
	http.HandleFunc("/set_alert_threshold", as.handleSetAlertThresholdRequest)
	http.HandleFunc("/subscribe_to_alert", as.handleSubscribeToAlertRequest)
	http.HandleFunc("/current_alerts", as.handleCurrentAlertsRequest)
	log.Printf("Serving real-time alert system on port %s\n", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}

func (as *AlertSystem) handleSetAlertThresholdRequest(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Metric    string  `json:"metric"`
		Threshold float64 `json:"threshold"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	as.SetAlertThreshold(req.Metric, req.Threshold)
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Alert threshold set"))
}

func (as *AlertSystem) handleSubscribeToAlertRequest(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Metric     string `json:"metric"`
		Subscriber string `json:"subscriber"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	subscriberChan := make(chan string)
	as.SubscribeToAlert(req.Metric, subscriberChan)

	go func() {
		for alert := range subscriberChan {
			// Handle alert notifications to subscriber (e.g., send via WebSocket, email, etc.)
			log.Printf("Sending alert to subscriber %s: %s\n", req.Subscriber, alert)
		}
	}()

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Subscribed to alert"))
}

func (as *AlertSystem) handleCurrentAlertsRequest(w http.ResponseWriter, r *http.Request) {
	as.mutex.RLock()
	defer as.mutex.RUnlock()
	data, err := json.Marshal(as.alerts)
	if err != nil {
		http.Error(w, "Failed to marshal current alerts", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(data)
}

// main function to start the real-time alert system server
func main() {
	alertSystem := NewAlertSystem()
	go alertSystem.MonitorMetrics()
	alertSystem.ServeHTTP("8082")
}
