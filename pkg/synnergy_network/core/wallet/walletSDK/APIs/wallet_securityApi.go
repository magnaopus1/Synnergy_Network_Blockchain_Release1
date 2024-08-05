package walletSDK

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/synnergy_network/core/wallet/security"
	"github.com/synnergy_network/logger"
	"github.com/synnergy_network/storage"
	"github.com/synnergy_network/cryptography/encryption"
	"github.com/synnergy_network/utils"
	"golang.org/x/crypto/argon2"
)

// Initialize services
var (
	storageService           = storage.NewStorageService()
	encryptionService        = encryption.NewEncryptionService()
	addressAliasService      = security.NewRecoveryService(storageService)
	anomalyDetectionService  = security.NewZeroKnowledgeProofRecovery()
	biometricSecurityService = security.NewBiometricSecurityManager(encryptionService)
	coldWalletService        = security.NewColdWalletService()
	complianceService        = security.NewComplianceService()
	secureKeyStorageService  = security.NewSecureKeyStorageService(storageService)
	walletFreezingService    = security.NewWalletFreezingService(blockchainService, walletService)
	walletSecurityService    = security.NewWalletSecurityService(blockchainService, walletService)
	logger                   = logger.NewLogger()
)

// AddressAliasHandler handles address alias functionality
func AddressAliasHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Alias    string `json:"alias"`
		Address  string `json:"address"`
		Passphrase string `json:"passphrase"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	encryptedData, err := addressAliasService.EncryptWalletData([]byte(req.Address), req.Passphrase)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"encrypted_address": encryptedData})
}

// AnomalyDetectionHandler handles anomaly detection functionality
func AnomalyDetectionHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		UserID    string `json:"user_id"`
		PublicKey string `json:"public_key"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	sessionID, err := anomalyDetectionService.InitiateRecovery(req.UserID, req.PublicKey)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"session_id": sessionID})
}

// BiometricSecurityHandler handles biometric security functionality
func BiometricSecurityHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		UserID        string `json:"user_id"`
		BiometricData []byte `json:"biometric_data"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	err := biometricSecurityService.RegisterBiometricData(req.UserID, req.BiometricData)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "Biometric data registered"})
}

// ColdWalletHandler handles cold wallet functionality
func ColdWalletHandler(w http.ResponseWriter, r *http.Request) {
	coldWallet, err := coldWalletService.NewColdWallet()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(coldWallet)
}

// ComplianceRulesHandler handles compliance rules functionality
func ComplianceRulesHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Description string `json:"description"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	rule, err := complianceService.AddRule(req.Description)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(rule)
}

// SecureKeyStorageHandler handles secure key storage functionality
func SecureKeyStorageHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Alias   string `json:"alias"`
		Key     string `json:"key"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	err := secureKeyStorageService.StoreKey(req.Alias, []byte(req.Key))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "Key stored"})
}

// WalletFreezingHandler handles wallet freezing functionality
func WalletFreezingHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		WalletAddress string `json:"wallet_address"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	err := walletFreezingService.FreezeWallet(req.WalletAddress)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "Wallet frozen"})
}

// WalletSecurityHandler handles wallet security functionality
func WalletSecurityHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		WalletAddress string `json:"wallet_address"`
		UserID        string `json:"user_id"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	err := walletSecurityService.FreezeWalletWithMFA(req.WalletAddress, req.UserID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "Wallet frozen with MFA"})
}

// SetupSecurityRoutes sets up the routes for the wallet security API
func SetupSecurityRoutes() *mux.Router {
	r := mux.NewRouter()

	r.HandleFunc("/security/address_alias", AddressAliasHandler).Methods("POST")
	r.HandleFunc("/security/anomaly_detection", AnomalyDetectionHandler).Methods("POST")
	r.HandleFunc("/security/biometric", BiometricSecurityHandler).Methods("POST")
	r.HandleFunc("/security/cold_wallet", ColdWalletHandler).Methods("POST")
	r.HandleFunc("/security/compliance_rules", ComplianceRulesHandler).Methods("POST")
	r.HandleFunc("/security/secure_key_storage", SecureKeyStorageHandler).Methods("POST")
	r.HandleFunc("/security/wallet_freezing", WalletFreezingHandler).Methods("POST")
	r.HandleFunc("/security/wallet_security", WalletSecurityHandler).Methods("POST")

	return r
}

// StartSecurityAPIServer starts the API server for wallet security
func StartSecurityAPIServer() {
	router := SetupSecurityRoutes()
	http.ListenAndServe(":8083", router)
}
