package liquidity

import (
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"
)

// LiquidityRecord represents a single liquidity event or transaction
type LiquidityRecord struct {
	ID          string    `json:"id"`
	Timestamp   time.Time `json:"timestamp"`
	FromAsset   string    `json:"from_asset"`
	ToAsset     string    `json:"to_asset"`
	Amount      float64   `json:"amount"`
	Fee         float64   `json:"fee"`
	Transaction string    `json:"transaction"`
}

// LiquidityRecordsManager manages all liquidity records
type LiquidityRecordsManager struct {
	mu      sync.RWMutex
	records map[string]*LiquidityRecord
}

// NewLiquidityRecordsManager creates a new LiquidityRecordsManager
func NewLiquidityRecordsManager() *LiquidityRecordsManager {
	return &LiquidityRecordsManager{
		records: make(map[string]*LiquidityRecord),
	}
}

// AddRecord adds a new liquidity record
func (lrm *LiquidityRecordsManager) AddRecord(record *LiquidityRecord) error {
	lrm.mu.Lock()
	defer lrm.mu.Unlock()

	if _, exists := lrm.records[record.ID]; exists {
		return errors.New("record already exists")
	}

	lrm.records[record.ID] = record
	return nil
}

// GetRecord retrieves a liquidity record by ID
func (lrm *LiquidityRecordsManager) GetRecord(id string) (*LiquidityRecord, error) {
	lrm.mu.RLock()
	defer lrm.mu.RUnlock()

	record, exists := lrm.records[id]
	if !exists {
		return nil, errors.New("record not found")
	}

	return record, nil
}

// ListRecords lists all liquidity records
func (lrm *LiquidityRecordsManager) ListRecords() map[string]*LiquidityRecord {
	lrm.mu.RLock()
	defer lrm.mu.RUnlock()

	records := make(map[string]*LiquidityRecord)
	for id, record := range lrm.records {
		records[id] = record
	}

	return records
}

// RemoveRecord removes a liquidity record by ID
func (lrm *LiquidityRecordsManager) RemoveRecord(id string) error {
	lrm.mu.Lock()
	defer lrm.mu.Unlock()

	if _, exists := lrm.records[id]; !exists {
		return errors.New("record not found")
	}

	delete(lrm.records, id)
	return nil
}

// UpdateRecord updates an existing liquidity record
func (lrm *LiquidityRecordsManager) UpdateRecord(record *LiquidityRecord) error {
	lrm.mu.Lock()
	defer lrm.mu.Unlock()

	if _, exists := lrm.records[record.ID]; !exists {
		return errors.New("record not found")
	}

	lrm.records[record.ID] = record
	return nil
}

// ServeHTTP implements the http.Handler interface for the LiquidityRecordsManager
func (lrm *LiquidityRecordsManager) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		lrm.handleGetRecords(w, r)
	case http.MethodPost:
		lrm.handleAddRecord(w, r)
	case http.MethodDelete:
		lrm.handleRemoveRecord(w, r)
	case http.MethodPut:
		lrm.handleUpdateRecord(w, r)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (lrm *LiquidityRecordsManager) handleGetRecords(w http.ResponseWriter, r *http.Request) {
	records := lrm.ListRecords()
	response, _ := json.Marshal(records)
	w.Header().Set("Content-Type", "application/json")
	w.Write(response)
}

func (lrm *LiquidityRecordsManager) handleAddRecord(w http.ResponseWriter, r *http.Request) {
	var record LiquidityRecord
	if err := json.NewDecoder(r.Body).Decode(&record); err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	if err := lrm.AddRecord(&record); err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}

	w.WriteHeader(http.StatusCreated)
}

func (lrm *LiquidityRecordsManager) handleRemoveRecord(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" {
		http.Error(w, "Missing record ID", http.StatusBadRequest)
		return
	}

	if err := lrm.RemoveRecord(id); err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func (lrm *LiquidityRecordsManager) handleUpdateRecord(w http.ResponseWriter, r *http.Request) {
	var record LiquidityRecord
	if err := json.NewDecoder(r.Body).Decode(&record); err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	if err := lrm.UpdateRecord(&record); err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	w.WriteHeader(http.StatusOK)
}

// StartServer starts the HTTP server for the LiquidityRecordsManager
func (lrm *LiquidityRecordsManager) StartServer(port int) {
	http.Handle("/records", lrm)
	address := fmt.Sprintf(":%d", port)
	fmt.Printf("Starting server at %s\n", address)
	http.ListenAndServe(address, nil)
}
