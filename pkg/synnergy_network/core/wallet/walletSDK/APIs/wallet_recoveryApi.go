package walletSDK

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/gorilla/mux"
	"github.com/synnergy_network/core/wallet/recovery"
	"github.com/synnergy_network/logger"
	"github.com/synnergy_network/storage"
	"github.com/synnergy_network/cryptography/encryption"
	"github.com/synnergy_network/identity_services"
	"github.com/synnergy_network/utils"
	"github.com/synnergy_network/tokens/token_standards/syn900"
	"github.com/synnergy_network/core/wallet/wallet_creation"
)

// Initialize the services
var (
	storageService           = storage.NewStorageService()
	cryptoService            = encryption.NewEncryptionService()
	idTokenVerifier          = recovery.NewIDTokenVerifier(syn900.NewValidator(), storageService)
	mnemonicRecoveryService  = recovery.NewMnemonicRecoveryService(wallet_creation.NewWalletCreator(), syn900.NewVerifier(), utils.NewEmailService(), utils.NewSMSProvider())
	biometricRecoveryService = recovery.NewBiometricRecoveryService(storageService)
	coldWalletRecoveryService = recovery.NewColdWalletRecoveryService(storageService)
	forgottenMnemonicRecoveryService = recovery.NewForgottenMnemonicRecoveryService(utils.NewEmailService(), utils.NewSMSProvider(), idTokenVerifier, wallet_creation.NewWalletConstructor())
	multiFactorRecoveryService = recovery.NewMultiFactorRecoveryService(syn900.NewTokenService(), idTokenVerifier, authentication.NewAuthManager(), recovery.NewRecoveryManager())
	zeroKnowledgeProofService = recovery.NewZeroKnowledgeProofService(storageService, cryptography.NewZKPCrypto())
	recoveryProtocolManager = recovery.NewRecoveryProtocolManager(mnemonicRecoveryService, biometricRecoveryService, multiFactorRecoveryService, zeroKnowledgeProofService)
	logger = logger.NewLogger()
)

// BiometricRecoveryHandler handles wallet recovery using biometric data
func BiometricRecoveryHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		UserID        string `json:"user_id"`
		BiometricData []byte `json:"biometric_data"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	wallet, err := biometricRecoveryService.RecoverWallet(req.UserID, req.BiometricData)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(wallet)
}

// ColdWalletRecoveryHandler handles wallet recovery for cold wallets
func ColdWalletRecoveryHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		UserID      string `json:"user_id"`
		RecoveryKey string `json:"recovery_key"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	wallet, err := coldWalletRecoveryService.RecoverWallet(req.UserID, req.RecoveryKey)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(wallet)
}

// ForgottenMnemonicRecoveryHandler handles wallet recovery when the mnemonic is forgotten
func ForgottenMnemonicRecoveryHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		UserID     string `json:"user_id"`
		Email      string `json:"email"`
		PhoneNumber string `json:"phone_number"`
		IDToken    string `json:"id_token"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	wallet, err := forgottenMnemonicRecoveryService.RecoverWallet(req.UserID, req.Email, req.PhoneNumber, req.IDToken)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(wallet)
}

// MultiFactorRecoveryHandler handles wallet recovery using multiple authentication factors
func MultiFactorRecoveryHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		UserID      string `json:"user_id"`
		Email       string `json:"email"`
		PhoneNumber string `json:"phone_number"`
		Mnemonic    string `json:"mnemonic"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	err := multiFactorRecoveryService.StartRecovery(req.UserID, req.Email, req.PhoneNumber, req.Mnemonic)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "Recovery process started"})
}

// ZeroKnowledgeProofRecoveryHandler handles wallet recovery using zero-knowledge proofs
func ZeroKnowledgeProofRecoveryHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		UserID     string            `json:"user_id"`
		ProofData  map[string]string `json:"proof_data"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	success, err := zeroKnowledgeProofService.InitiateRecovery(req.UserID, req.ProofData)
	if err != nil || !success {
		http.Error(w, "Zero-knowledge proof validation failed", http.StatusUnauthorized)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "Zero-knowledge proof verified"})
}

// IDTokenVerificationHandler handles ID token verification
func IDTokenVerificationHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		UserID string `json:"user_id"`
		Token  string `json:"token"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	valid, err := idTokenVerifier.VerifyIDToken(req.UserID, req.Token)
	if err != nil || !valid {
		http.Error(w, "ID token verification failed", http.StatusUnauthorized)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "ID token verified"})
}

// RecoveryProtocolsHandler returns details about available recovery protocols
func RecoveryProtocolsHandler(w http.ResponseWriter, r *http.Request) {
	protocols := recoveryProtocolManager.RecoveryProtocolDetails()
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(protocols)
}

// MnemonicRecoveryHandler handles wallet recovery using mnemonic phrases
func MnemonicRecoveryHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		UserID   string `json:"user_id"`
		Mnemonic string `json:"mnemonic"`
		Token    string `json:"token"`
		Email    string `json:"email"`
		Contact  string `json:"contact"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	wallet, err := mnemonicRecoveryService.RecoverWallet(req.Mnemonic, req.Token, req.Email, req.Contact)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(wallet)
}

// WalletRecoveryHandler handles the recovery of a user's wallet using multiple factors
func WalletRecoveryHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		UserID        string            `json:"user_id"`
		RecoveryType  string            `json:"recovery_type"`
		RecoveryData  map[string]string `json:"recovery_data"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	wallet, err := recoveryProtocolManager.ExecuteRecovery(req.RecoveryType, req.UserID, req.RecoveryData)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(wallet)
}

// SetupRecoveryRoutes sets up the routes for the wallet recovery API
func SetupRecoveryRoutes() *mux.Router {
	r := mux.NewRouter()

	r.HandleFunc("/recovery/biometric", BiometricRecoveryHandler).Methods("POST")
	r.HandleFunc("/recovery/cold_wallet", ColdWalletRecoveryHandler).Methods("POST")
	r.HandleFunc("/recovery/forgotten_mnemonic", ForgottenMnemonicRecoveryHandler).Methods("POST")
	r.HandleFunc("/recovery/multi_factor", MultiFactorRecoveryHandler).Methods("POST")
	r.HandleFunc("/recovery/zero_knowledge_proof", ZeroKnowledgeProofRecoveryHandler).Methods("POST")
	r.HandleFunc("/recovery/id_token", IDTokenVerificationHandler).Methods("POST")
	r.HandleFunc("/recovery/protocols", RecoveryProtocolsHandler).Methods("GET")
	r.HandleFunc("/recovery/mnemonic", MnemonicRecoveryHandler).Methods("POST")
	r.HandleFunc("/recovery/wallet", WalletRecoveryHandler).Methods("POST")

	return r
}

// StartRecoveryAPIServer starts the API server for wallet recovery
func StartRecoveryAPIServer() {
	router := SetupRecoveryRoutes()
	http.ListenAndServe(":8082", router)
}
