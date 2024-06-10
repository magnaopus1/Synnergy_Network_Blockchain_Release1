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
	"github.com/gorilla/websocket"
	"github.com/wcharczuk/go-chart"
)

// ThroughputVisualizer handles the visualization of transaction throughput.
type ThroughputVisualizer struct {
	transactionCount   int
	mutex              sync.Mutex
	metricsManager     *performance_metrics.PerformanceMetricsManager
	alertSubscribers   map[string][]chan string
	secureCommunicator *security.SecureCommunicator
	upgrader           websocket.Upgrader
	throughputHistory  []float64
	historyLimit       int
}

// NewThroughputVisualizer creates a new instance of ThroughputVisualizer.
func NewThroughputVisualizer() *ThroughputVisualizer {
	secureComm, err := security.NewSecureCommunicator("securepassphrase")
	if err != nil {
		log.Fatalf("Failed to initialize secure communicator: %v\n", err)
	}

	return &ThroughputVisualizer{
		metricsManager:     performance_metrics.NewPerformanceMetricsManager(),
		alertSubscribers:   make(map[string][]chan string),
		secureCommunicator: secureComm,
		upgrader:           websocket.Upgrader{},
		throughputHistory:  make([]float64, 0),
		historyLimit:       60, // Keep 60 data points for 1 hour history with 1 data point per minute
	}
}

// RecordTransaction increments the transaction count.
func (tv *ThroughputVisualizer) RecordTransaction() {
	tv.mutex.Lock()
	defer tv.mutex.Unlock()
	tv.transactionCount++
}

// CalculateThroughput calculates the transactions per second.
func (tv *ThroughputVisualizer) CalculateThroughput() float64 {
	tv.mutex.Lock()
	defer tv.mutex.Unlock()

	throughput := float64(tv.transactionCount) / 60.0 // Transactions per minute
	tv.transactionCount = 0                            // Reset the counter after calculation
	tv.throughputHistory = append(tv.throughputHistory, throughput)
	if len(tv.throughputHistory) > tv.historyLimit {
		tv.throughputHistory = tv.throughputHistory[1:] // Maintain the history limit
	}
	return throughput
}

// MonitorThroughput continuously monitors transaction throughput.
func (tv *ThroughputVisualizer) MonitorThroughput(threshold float64) {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		tv.checkThroughput(threshold)
	}
}

func (tv *ThroughputVisualizer) checkThroughput(threshold float64) {
	throughput := tv.CalculateThroughput()

	if throughput > threshold {
		tv.triggerAlert("Transaction Throughput", throughput)
	}
}

func (tv *ThroughputVisualizer) triggerAlert(metric string, value float64) {
	tv.mutex.Lock()
	defer tv.mutex.Unlock()

	alertMessage := fmt.Sprintf("Alert! %s exceeded threshold with value: %f", metric, value)
	log.Println(alertMessage)

	for _, subscriber := range tv.alertSubscribers[metric] {
		subscriber <- alertMessage
	}

	// Securely log the alert
	encryptedMessage, err := tv.secureCommunicator.Encrypt([]byte(alertMessage))
	if err != nil {
		log.Printf("Failed to encrypt alert message: %v\n", err)
		return
	}
	log.Printf("Encrypted alert message: %s\n", encryptedMessage)
}

// SubscribeToAlerts allows a subscriber to receive alerts for a specific metric.
func (tv *ThroughputVisualizer) SubscribeToAlerts(metric string, subscriber chan string) {
	tv.mutex.Lock()
	defer tv.mutex.Unlock()
	tv.alertSubscribers[metric] = append(tv.alertSubscribers[metric], subscriber)
}

// ServeHTTP serves the transaction throughput monitoring data via HTTP.
func (tv *ThroughputVisualizer) ServeHTTP(port string) {
	http.HandleFunc("/subscribe_to_throughput_alert", tv.handleSubscribeToAlertRequest)
	http.HandleFunc("/current_throughput", tv.handleCurrentThroughputRequest)
	http.HandleFunc("/throughput_chart", tv.handleThroughputChartRequest)
	http.HandleFunc("/ws", tv.handleWebSocket)
	log.Printf("Serving throughput monitoring system on port %s\n", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}

func (tv *ThroughputVisualizer) handleSubscribeToAlertRequest(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Metric     string `json:"metric"`
		Subscriber string `json:"subscriber"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	subscriberChan := make(chan string)
	tv.SubscribeToAlerts(req.Metric, subscriberChan)

	go func() {
		for alert := range subscriberChan {
			// Handle alert notifications to subscriber (e.g., send via WebSocket, email, etc.)
			log.Printf("Sending alert to subscriber %s: %s\n", req.Subscriber, alert)
		}
	}()

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Subscribed to throughput alert"))
}

func (tv *ThroughputVisualizer) handleCurrentThroughputRequest(w http.ResponseWriter, r *http.Request) {
	throughput := tv.CalculateThroughput()

	data, err := json.Marshal(map[string]float64{"Throughput": throughput})
	if err != nil {
		http.Error(w, "Failed to marshal throughput data", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(data)
}

func (tv *ThroughputVisualizer) handleThroughputChartRequest(w http.ResponseWriter, r *http.Request) {
	tv.mutex.Lock()
	defer tv.mutex.Unlock()

	xValues := make([]float64, len(tv.throughputHistory))
	yValues := make([]float64, len(tv.throughputHistory))

	for i := 0; i < len(tv.throughputHistory); i++ {
		xValues[i] = float64(i)
		yValues[i] = tv.throughputHistory[i]
	}

	graph := chart.Chart{
		Series: []chart.Series{
			chart.ContinuousSeries{
				XValues: xValues,
				YValues: yValues,
			},
		},
	}

	w.Header().Set("Content-Type", "image/png")
	err := graph.Render(chart.PNG, w)
	if err != nil {
		http.Error(w, "Failed to render chart", http.StatusInternalServerError)
		return
	}
}

func (tv *ThroughputVisualizer) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := tv.upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("Failed to upgrade to WebSocket: %v\n", err)
		http.Error(w, "Failed to upgrade to WebSocket", http.StatusInternalServerError)
		return
	}
	defer conn.Close()

	subscriberChan := make(chan string)
	tv.SubscribeToAlerts("Transaction Throughput", subscriberChan)

	for {
		select {
		case alert := <-subscriberChan:
			err = conn.WriteMessage(websocket.TextMessage, []byte(alert))
			if err != nil {
				log.Printf("Failed to send message via WebSocket: %v\n", err)
				return
			}
		}
	}
}

// main function to start the throughput visualization server
func main() {
	throughputVisualizer := NewThroughputVisualizer()
	go throughputVisualizer.MonitorThroughput(100.0) // Set threshold for throughput
	throughputVisualizer.ServeHTTP("8084")
}
