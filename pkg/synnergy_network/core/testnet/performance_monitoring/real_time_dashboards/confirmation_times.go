// Package real_time_dashboards provides tools for real-time monitoring of network performance.
package real_time_dashboards

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/mux"
)

// ConfirmationTimeRecord represents a record of transaction confirmation time.
type ConfirmationTimeRecord struct {
	TransactionID string    `json:"transaction_id"`
	NodeID        string    `json:"node_id"`
	Timestamp     time.Time `json:"timestamp"`
	ConfirmationTime int64  `json:"confirmation_time"` // in milliseconds
}

// ConfirmationTimeStore manages the storage and retrieval of confirmation time records.
type ConfirmationTimeStore struct {
	records []ConfirmationTimeRecord
	mu      sync.RWMutex
}

// NewConfirmationTimeStore creates a new ConfirmationTimeStore.
func NewConfirmationTimeStore() *ConfirmationTimeStore {
	return &ConfirmationTimeStore{
		records: []ConfirmationTimeRecord{},
	}
}

// AddRecord adds a new confirmation time record to the store.
func (cts *ConfirmationTimeStore) AddRecord(record ConfirmationTimeRecord) {
	cts.mu.Lock()
	defer cts.mu.Unlock()
	cts.records = append(cts.records, record)
}

// GetRecords returns all confirmation time records.
func (cts *ConfirmationTimeStore) GetRecords() []ConfirmationTimeRecord {
	cts.mu.RLock()
	defer cts.mu.RUnlock()
	return cts.records
}

// GetAverageConfirmationTime calculates the average confirmation time.
func (cts *ConfirmationTimeStore) GetAverageConfirmationTime() int64 {
	cts.mu.RLock()
	defer cts.mu.RUnlock()

	if len(cts.records) == 0 {
		return 0
	}

	var total int64
	for _, record := range cts.records {
		total += record.ConfirmationTime
	}
	return total / int64(len(cts.records))
}

// MonitorConfirmationTimes continuously monitors and records transaction confirmation times.
func (cts *ConfirmationTimeStore) MonitorConfirmationTimes() {
	for {
		// Simulate monitoring and recording confirmation times.
		record := ConfirmationTimeRecord{
			TransactionID: generateTransactionID(),
			NodeID:        generateNodeID(),
			Timestamp:     time.Now(),
			ConfirmationTime: int64(time.Duration(rand.Intn(1000)) * time.Millisecond),
		}
		cts.AddRecord(record)
		time.Sleep(10 * time.Second) // Simulate interval
	}
}

// generateTransactionID generates a unique transaction ID.
func generateTransactionID() string {
	return fmt.Sprintf("tx_%d", time.Now().UnixNano())
}

// generateNodeID generates a unique node ID.
func generateNodeID() string {
	return fmt.Sprintf("node_%d", time.Now().UnixNano())
}

// API handler functions

// handleGetRecords handles GET requests to retrieve confirmation time records.
func handleGetRecords(w http.ResponseWriter, r *http.Request, store *ConfirmationTimeStore) {
	records := store.GetRecords()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(records); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// handleGetAverageConfirmationTime handles GET requests to retrieve the average confirmation time.
func handleGetAverageConfirmationTime(w http.ResponseWriter, r *http.Request, store *ConfirmationTimeStore) {
	avgTime := store.GetAverageConfirmationTime()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]int64{"average_confirmation_time": avgTime}); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// StartServer starts the HTTP server for the confirmation time dashboard.
func StartServer(store *ConfirmationTimeStore) {
	router := mux.NewRouter()
	router.HandleFunc("/confirmation_times", func(w http.ResponseWriter, r *http.Request) {
		handleGetRecords(w, r, store)
	}).Methods("GET")

	router.HandleFunc("/average_confirmation_time", func(w http.ResponseWriter, r *http.Request) {
		handleGetAverageConfirmationTime(w, r, store)
	}).Methods("GET")

	srv := &http.Server{
		Handler:      router,
		Addr:         "0.0.0.0:8080",
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
	}

	log.Println("Starting server on :8080")
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}

// Encrypt data using AES.
func Encrypt(key, text string) (string, error) {
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return "", err
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, aesGCM.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ciphertext := aesGCM.Seal(nonce, nonce, []byte(text), nil)
	return hex.EncodeToString(ciphertext), nil
}

// Decrypt data using AES.
func Decrypt(key, cryptoText string) (string, error) {
	data, err := hex.DecodeString(cryptoText)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return "", err
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonceSize := aesGCM.NonceSize()
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

// Example usage of the confirmation time monitoring system.
func main() {
	encryptionKey := "a very very very very secret key" // Replace with a secure key
	store := NewConfirmationTimeStore()

	// Start monitoring confirmation times in a separate goroutine
	go store.MonitorConfirmationTimes()

	// Start the HTTP server
	StartServer(store)
}
