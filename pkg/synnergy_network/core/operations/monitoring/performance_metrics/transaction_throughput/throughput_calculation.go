package transaction_throughput

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/synthron_blockchain_final/pkg/layer0/monitoring/performance_metrics"
	"github.com/synthron_blockchain_final/pkg/security"
)

type ThroughputCalculator struct {
	transactionCount   int
	mutex              sync.Mutex
	metricsManager     *performance_metrics.PerformanceMetricsManager
	alertSubscribers   map[string][]chan string
	secureCommunicator *security.SecureCommunicator
}

// NewThroughputCalculator creates a new instance of ThroughputCalculator.
func NewThroughputCalculator() *ThroughputCalculator {
	secureComm, err := security.NewSecureCommunicator("securepassphrase")
	if err != nil {
		log.Fatalf("Failed to initialize secure communicator: %v\n", err)
	}

	return &ThroughputCalculator{
		metricsManager:     performance_metrics.NewPerformanceMetricsManager(),
		alertSubscribers:   make(map[string][]chan string),
		secureCommunicator: secureComm,
	}
}

// RecordTransaction increments the transaction count.
func (tc *ThroughputCalculator) RecordTransaction() {
	tc.mutex.Lock()
	defer tc.mutex.Unlock()
	tc.transactionCount++
}

// CalculateThroughput calculates the transactions per second.
func (tc *ThroughputCalculator) CalculateThroughput() float64 {
	tc.mutex.Lock()
	defer tc.mutex.Unlock()

	throughput := float64(tc.transactionCount) / 60.0 // Transactions per minute
	tc.transactionCount = 0                            // Reset the counter after calculation
	return throughput
}

// MonitorThroughput continuously monitors transaction throughput.
func (tc *ThroughputCalculator) MonitorThroughput(threshold float64) {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		tc.checkThroughput(threshold)
	}
}

func (tc *ThroughputCalculator) checkThroughput(threshold float64) {
	throughput := tc.CalculateThroughput()

	if throughput > threshold {
		tc.triggerAlert("Transaction Throughput", throughput)
	}
}

func (tc *ThroughputCalculator) triggerAlert(metric string, value float64) {
	tc.mutex.Lock()
	defer tc.mutex.Unlock()

	alertMessage := fmt.Sprintf("Alert! %s exceeded threshold with value: %f", metric, value)
	log.Println(alertMessage)

	for _, subscriber := range tc.alertSubscribers[metric] {
		subscriber <- alertMessage
	}

	// Securely log the alert
	encryptedMessage, err := tc.secureCommunicator.Encrypt([]byte(alertMessage))
	if err != nil {
		log.Printf("Failed to encrypt alert message: %v\n", err)
		return
	}
	log.Printf("Encrypted alert message: %s\n", encryptedMessage)
}

// SubscribeToAlerts allows a subscriber to receive alerts for a specific metric.
func (tc *ThroughputCalculator) SubscribeToAlerts(metric string, subscriber chan string) {
	tc.mutex.Lock()
	defer tc.mutex.Unlock()
	tc.alertSubscribers[metric] = append(tc.alertSubscribers[metric], subscriber)
}

// ServeHTTP serves the transaction throughput monitoring data via HTTP.
func (tc *ThroughputCalculator) ServeHTTP(port string) {
	http.HandleFunc("/subscribe_to_throughput_alert", tc.handleSubscribeToAlertRequest)
	http.HandleFunc("/current_throughput", tc.handleCurrentThroughputRequest)
	log.Printf("Serving throughput monitoring system on port %s\n", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}

func (tc *ThroughputCalculator) handleSubscribeToAlertRequest(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Metric     string `json:"metric"`
		Subscriber string `json:"subscriber"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	subscriberChan := make(chan string)
	tc.SubscribeToAlerts(req.Metric, subscriberChan)

	go func() {
		for alert := range subscriberChan {
			// Handle alert notifications to subscriber (e.g., send via WebSocket, email, etc.)
			log.Printf("Sending alert to subscriber %s: %s\n", req.Subscriber, alert)
		}
	}()

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Subscribed to throughput alert"))
}

func (tc *ThroughputCalculator) handleCurrentThroughputRequest(w http.ResponseWriter, r *http.Request) {
	throughput := tc.CalculateThroughput()

	data, err := json.Marshal(map[string]float64{"Throughput": throughput})
	if err != nil {
		http.Error(w, "Failed to marshal throughput data", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(data)
}

// main function to start the throughput monitoring server
func main() {
	throughputCalculator := NewThroughputCalculator()
	go throughputCalculator.MonitorThroughput(100.0) // Set threshold for throughput
	throughputCalculator.ServeHTTP("8084")
}
