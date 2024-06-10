package monitoring

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"sync"
	"time"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"io"

	"github.com/gorilla/mux"
)

// NodeMetric represents performance metrics of a node
type NodeMetric struct {
	NodeID         string    `json:"node_id"`
	CPUUsage       float64   `json:"cpu_usage"`
	MemoryUsage    float64   `json:"memory_usage"`
	DiskUsage      float64   `json:"disk_usage"`
	NetworkTraffic float64   `json:"network_traffic"`
	Timestamp      time.Time `json:"timestamp"`
}

// Alert represents an alert triggered by the monitoring system
type Alert struct {
	AlertID    string    `json:"alert_id"`
	NodeID     string    `json:"node_id"`
	Metric     string    `json:"metric"`
	Threshold  float64   `json:"threshold"`
	Value      float64   `json:"value"`
	Timestamp  time.Time `json:"timestamp"`
	Resolved   bool      `json:"resolved"`
}

// Dashboard represents the monitoring dashboard for the blockchain network
type Dashboard struct {
	NodeMetrics map[string][]NodeMetric
	Alerts      map[string][]Alert
	mutex       sync.Mutex
	encryptionKey []byte
}

// NewDashboard initializes a new Dashboard instance
func NewDashboard(encryptionKey []byte) *Dashboard {
	return &Dashboard{
		NodeMetrics: make(map[string][]NodeMetric),
		Alerts:      make(map[string][]Alert),
		encryptionKey: encryptionKey,
	}
}

// AddNodeMetric adds a new node metric to the dashboard
func (d *Dashboard) AddNodeMetric(metric NodeMetric) {
	d.mutex.Lock()
	defer d.mutex.Unlock()
	d.NodeMetrics[metric.NodeID] = append(d.NodeMetrics[metric.NodeID], metric)
	d.checkAlerts(metric)
}

// GetNodeMetrics returns the metrics for a specific node
func (d *Dashboard) GetNodeMetrics(nodeID string) ([]NodeMetric, error) {
	d.mutex.Lock()
	defer d.mutex.Unlock()
	metrics, exists := d.NodeMetrics[nodeID]
	if !exists {
		return nil, fmt.Errorf("node with ID %s not found", nodeID)
	}
	return metrics, nil
}

// AddAlert adds a new alert to the dashboard
func (d *Dashboard) AddAlert(alert Alert) {
	d.mutex.Lock()
	defer d.mutex.Unlock()
	d.Alerts[alert.NodeID] = append(d.Alerts[alert.NodeID], alert)
}

// GetAlerts returns the alerts for a specific node
func (d *Dashboard) GetAlerts(nodeID string) ([]Alert, error) {
	d.mutex.Lock()
	defer d.mutex.Unlock()
	alerts, exists := d.Alerts[nodeID]
	if !exists {
		return nil, fmt.Errorf("no alerts found for node with ID %s", nodeID)
	}
	return alerts, nil
}

// checkAlerts checks for threshold breaches and triggers alerts if necessary
func (d *Dashboard) checkAlerts(metric NodeMetric) {
	thresholds := map[string]float64{
		"cpu": 85.0,
		"memory": 75.0,
		"disk": 90.0,
		"network": 70.0,
	}

	checkAndAddAlert := func(metricName string, value float64, threshold float64) {
		if value > threshold {
			alert := Alert{
				AlertID:    fmt.Sprintf("%s-%s-%d", metric.NodeID, metricName, time.Now().UnixNano()),
				NodeID:     metric.NodeID,
				Metric:     metricName,
				Threshold:  threshold,
				Value:      value,
				Timestamp:  time.Now(),
				Resolved:   false,
			}
			d.AddAlert(alert)
		}
	}

	checkAndAddAlert("cpu", metric.CPUUsage, thresholds["cpu"])
	checkAndAddAlert("memory", metric.MemoryUsage, thresholds["memory"])
	checkAndAddAlert("disk", metric.DiskUsage, thresholds["disk"])
	checkAndAddAlert("network", metric.NetworkTraffic, thresholds["network"])
}

// Encrypt encrypts plaintext using AES encryption
func (d *Dashboard) Encrypt(plaintext []byte) (string, error) {
	block, err := aes.NewCipher(d.encryptionKey)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// Decrypt decrypts ciphertext using AES encryption
func (d *Dashboard) Decrypt(ciphertext string) ([]byte, error) {
	data, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(d.encryptionKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// ServeHTTP serves the monitoring dashboard over HTTP
func (d *Dashboard) ServeHTTP() {
	r := mux.NewRouter()
	r.HandleFunc("/metrics/{nodeID}", d.handleGetNodeMetrics).Methods("GET")
	r.HandleFunc("/metrics", d.handleAddNodeMetric).Methods("POST")
	r.HandleFunc("/alerts/{nodeID}", d.handleGetAlerts).Methods("GET")

	http.Handle("/", r)
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func (d *Dashboard) handleGetNodeMetrics(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	nodeID := vars["nodeID"]

	metrics, err := d.GetNodeMetrics(nodeID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	response, err := json.Marshal(metrics)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	encryptedResponse, err := d.Encrypt(response)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(encryptedResponse))
}

func (d *Dashboard) handleAddNodeMetric(w http.ResponseWriter, r *http.Request) {
	var metric NodeMetric
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&metric); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	d.AddNodeMetric(metric)
	w.WriteHeader(http.StatusCreated)
}

func (d *Dashboard) handleGetAlerts(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	nodeID := vars["nodeID"]

	alerts, err := d.GetAlerts(nodeID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	response, err := json.Marshal(alerts)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	encryptedResponse, err := d.Encrypt(response)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(encryptedResponse))
}

func main() {
	encryptionKey := []byte(os.Getenv("ENCRYPTION_KEY"))
	if len(encryptionKey) != 32 {
		log.Fatal("Encryption key must be 32 bytes")
	}

	dashboard := NewDashboard(encryptionKey)

	// Example: Add some dummy metrics
	go func() {
		for {
			dashboard.AddNodeMetric(NodeMetric{
				NodeID:         "node1",
				CPUUsage:       75.0,
				MemoryUsage:    60.0,
				DiskUsage:      55.0,
				NetworkTraffic: 45.0,
				Timestamp:      time.Now(),
			})
			time.Sleep(10 * time.Second)
		}
	}()

	// Start the HTTP server
	dashboard.ServeHTTP()
}
