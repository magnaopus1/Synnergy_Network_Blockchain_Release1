package walletSDK

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/gorilla/mux"
	"github.com/synnergy_network/core/wallet/storage"
	"github.com/synnergy_network/logger"
	"github.com/synnergy_network/utils"
)

// Initialize services
var (
	blockchainService           = storage.NewBlockchainService()
	balanceService              = storage.NewBalanceService(blockchainService)
	secureStorageService        = storage.NewSecureStorageService()
	transactionStorageService   = storage.NewTransactionStorage("transactions.json")
	cleanupService              = storage.NewWalletStorageCleanupService(blockchainService, walletService, decentralizedStorage, encryptionService, auditService, dataProtectionService, 24*time.Hour)
	addressAliasService         = storage.NewAddressAliasService()
	dynamicFeeAdjustmentService = storage.NewDynamicFeeAdjustmentService(blockchainService, 0.001, 0.01)
	logger                      = logger.NewLogger()
)

// BalanceHandler handles balance-related requests
func BalanceHandler(w http.ResponseWriter, r *http.Request) {
	walletAddress := r.URL.Query().Get("wallet_address")
	if walletAddress == "" {
		http.Error(w, "Wallet address is required", http.StatusBadRequest)
		return
	}

	balance, err := balanceService.GetBalance(walletAddress)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]float64{"balance": balance})
}

// UpdateBalanceHandler handles balance update requests
func UpdateBalanceHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		WalletAddress string  `json:"wallet_address"`
		Amount        float64 `json:"amount"`
		Add           bool    `json:"add"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	err := balanceService.UpdateBalance(req.WalletAddress, req.Amount, req.Add)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "Balance updated"})
}

// SecureStoreHandler handles secure storage requests
func SecureStoreHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Key       string `json:"key"`
		Data      string `json:"data"`
		Passphrase string `json:"passphrase"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	err := secureStorageService.Store(req.Key, req.Data, req.Passphrase)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "Data stored securely"})
}

// SecureRetrieveHandler handles secure retrieval requests
func SecureRetrieveHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Key       string `json:"key"`
		Passphrase string `json:"passphrase"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	data, err := secureStorageService.Retrieve(req.Key, req.Passphrase)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]string{"data": data})
}

// TransactionHandler handles transaction storage requests
func TransactionHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		From          string  `json:"from"`
		To            string  `json:"to"`
		Amount        float64 `json:"amount"`
		TransactionFee float64 `json:"transaction_fee"`
		Timestamp     int64   `json:"timestamp"`
		Signature     string  `json:"signature"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	id, err := transactionStorageService.AddTransaction(req.From, req.To, req.Amount, req.TransactionFee, req.Timestamp, req.Signature)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]string{"transaction_id": id})
}

// GetTransactionHandler handles retrieval of a transaction by ID
func GetTransactionHandler(w http.ResponseWriter, r *http.Request) {
	transactionID := mux.Vars(r)["id"]
	transaction, err := transactionStorageService.GetTransaction(transactionID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(transaction)
}

// GetTransactionsByAddressHandler handles retrieval of transactions by address
func GetTransactionsByAddressHandler(w http.ResponseWriter, r *http.Request) {
	address := r.URL.Query().Get("address")
	if address == "" {
		http.Error(w, "Address is required", http.StatusBadRequest)
		return
	}

	transactions, err := transactionStorageService.GetTransactionsByAddress(address)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(transactions)
}

// CleanupHandler handles storage cleanup requests
func CleanupHandler(w http.ResponseWriter, r *http.Request) {
	cleanupService.CleanupStorage()
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "Storage cleanup initiated"})
}

// SetupStorageRoutes sets up the routes for the wallet storage API
func SetupStorageRoutes() *mux.Router {
	r := mux.NewRouter()

	r.HandleFunc("/storage/balance", BalanceHandler).Methods("GET")
	r.HandleFunc("/storage/balance/update", UpdateBalanceHandler).Methods("POST")
	r.HandleFunc("/storage/secure/store", SecureStoreHandler).Methods("POST")
	r.HandleFunc("/storage/secure/retrieve", SecureRetrieveHandler).Methods("POST")
	r.HandleFunc("/storage/transaction", TransactionHandler).Methods("POST")
	r.HandleFunc("/storage/transaction/{id}", GetTransactionHandler).Methods("GET")
	r.HandleFunc("/storage/transactions/address", GetTransactionsByAddressHandler).Methods("GET")
	r.HandleFunc("/storage/cleanup", CleanupHandler).Methods("POST")

	return r
}

// StartStorageAPIServer starts the API server for wallet storage
func StartStorageAPIServer() {
	router := SetupStorageRoutes()
	http.ListenAndServe(":8084", router)
}
