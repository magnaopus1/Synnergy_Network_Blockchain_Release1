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
	NodeID      string    `json:"node_id"`
	CPUUsage    float64   `json:"cpu_usage"`
	MemoryUsage float64   `json:"memory_usage"`
	DiskUsage   float64   `json:"disk_usage"`
	Timestamp   time.Time `json:"timestamp"`
}

// Dashboard represents the monitoring dashboard for the blockchain network
type Dashboard struct {
	NodeMetrics map[string][]NodeMetric
	mutex       sync.Mutex
	encryptionKey []byte
}

// NewDashboard initializes a new Dashboard instance
func NewDashboard(encryptionKey []byte) *Dashboard {
	return &Dashboard{
		NodeMetrics: make(map[string][]NodeMetric),
		encryptionKey: encryptionKey,
	}
}

// AddNodeMetric adds a new node metric to the dashboard
func (d *Dashboard) AddNodeMetric(metric NodeMetric) {
	d.mutex.Lock()
	defer d.mutex.Unlock()
	d.NodeMetrics[metric.NodeID] = append(d.NodeMetrics[metric.NodeID], metric)
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
				NodeID:      "node1",
				CPUUsage:    75.0,
				MemoryUsage: 60.0,
				DiskUsage:   55.0,
				Timestamp:   time.Now(),
			})
			time.Sleep(10 * time.Second)
		}
	}()

	// Start the HTTP server
	dashboard.ServeHTTP()
}
