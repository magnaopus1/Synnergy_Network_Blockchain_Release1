package visualizationcomponents

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// TransactionFlow represents a single transaction flow within the blockchain network
type TransactionFlow struct {
	TransactionID string    `json:"transaction_id"`
	From          string    `json:"from"`
	To            string    `json:"to"`
	Amount        float64   `json:"amount"`
	Timestamp     time.Time `json:"timestamp"`
	Status        string    `json:"status"` // e.g., pending, confirmed, failed
}

// TransactionFlowsManager manages the transaction flows within the blockchain network
type TransactionFlowsManager struct {
	Flows map[string]TransactionFlow
	Mutex sync.RWMutex
}

// InitializeManager initializes a new TransactionFlowsManager
func (tfm *TransactionFlowsManager) InitializeManager() {
	tfm.Flows = make(map[string]TransactionFlow)
}

// AddFlow adds a new transaction flow to the manager
func (tfm *TransactionFlowsManager) AddFlow(flow TransactionFlow) {
	tfm.Mutex.Lock()
	defer tfm.Mutex.Unlock()
	tfm.Flows[flow.TransactionID] = flow
}

// UpdateFlow updates an existing transaction flow in the manager
func (tfm *TransactionFlowsManager) UpdateFlow(flow TransactionFlow) error {
	tfm.Mutex.Lock()
	defer tfm.Mutex.Unlock()
	if _, exists := tfm.Flows[flow.TransactionID]; exists {
		tfm.Flows[flow.TransactionID] = flow
		return nil
	}
	return fmt.Errorf("transaction flow with ID %s not found", flow.TransactionID)
}

// RemoveFlow removes a transaction flow from the manager
func (tfm *TransactionFlowsManager) RemoveFlow(transactionID string) error {
	tfm.Mutex.Lock()
	defer tfm.Mutex.Unlock()
	if _, exists := tfm.Flows[transactionID]; exists {
		delete(tfm.Flows, transactionID)
		return nil
	}
	return fmt.Errorf("transaction flow with ID %s not found", transactionID)
}

// GetFlow retrieves a specific transaction flow by its ID
func (tfm *TransactionFlowsManager) GetFlow(transactionID string) (TransactionFlow, error) {
	tfm.Mutex.RLock()
	defer tfm.Mutex.RUnlock()
	if flow, exists := tfm.Flows[transactionID]; exists {
		return flow, nil
	}
	return TransactionFlow{}, fmt.Errorf("transaction flow with ID %s not found", transactionID)
}

// GetAllFlows retrieves all transaction flows
func (tfm *TransactionFlowsManager) GetAllFlows() []TransactionFlow {
	tfm.Mutex.RLock()
	defer tfm.Mutex.RUnlock()
	flows := []TransactionFlow{}
	for _, flow := range tfm.Flows {
		flows = append(flows, flow)
	}
	return flows
}

// ServeHTTP serves the transaction flows over HTTP
func (tfm *TransactionFlowsManager) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	switch r.Method {
	case http.MethodGet:
		tfm.Mutex.RLock()
		defer tfm.Mutex.RUnlock()
		json.NewEncoder(w).Encode(tfm.GetAllFlows())
	case http.MethodPost:
		var flow TransactionFlow
		if err := json.NewDecoder(r.Body).Decode(&flow); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		tfm.AddFlow(flow)
		w.WriteHeader(http.StatusCreated)
	case http.MethodPut:
		var flow TransactionFlow
		if err := json.NewDecoder(r.Body).Decode(&flow); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := tfm.UpdateFlow(flow); err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	case http.MethodDelete:
		var req struct {
			TransactionID string `json:"transaction_id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := tfm.RemoveFlow(req.TransactionID); err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// Secure serves the transaction flows over HTTPS
func (tfm *TransactionFlowsManager) Secure(certFile, keyFile string) error {
	srv := &http.Server{
		Addr:         ":443",
		Handler:      tfm,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}
	return srv.ListenAndServeTLS(certFile, keyFile)
}

// Example integration function for TransactionFlowsManager
func integrateTransactionFlowsManager() {
	manager := &TransactionFlowsManager{}
	manager.InitializeManager()

	http.Handle("/transaction_flows", manager)
	go func() {
		fmt.Println("Serving transaction flows on http://localhost:8080")
		if err := http.ListenAndServe(":8080", nil); err != nil {
			fmt.Println("Failed to start HTTP server:", err)
		}
	}()

	fmt.Println("Serving secure transaction flows on https://localhost")
	if err := manager.Secure("server.crt", "server.key"); err != nil {
		fmt.Println("Failed to start HTTPS server:", err)
	}
}
