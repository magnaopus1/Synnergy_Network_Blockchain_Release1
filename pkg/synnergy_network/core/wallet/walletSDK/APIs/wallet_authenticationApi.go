package walletSDK

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/synnergy_network/core/wallet/authentication"
	"github.com/synnergy_network/logger"
	"github.com/synnergy_network/identity_services"
	"github.com/synnergy_network/cryptography/encryption"
	"github.com/synnergy_network/blockchain/storage"
	"github.com/synnergy_network/utils"
)

// Initialize the services and middleware
var (
	authLogger               = authentication.NewAuthLogger("auth_log.txt", true)
	accountManager           = authentication.NewAccountManager(storage.NewBlockchainStorage(), storage.NewCacheService())
	mfaAuthenticator         = authentication.NewMultiFactorAuthenticator(identity_services.NewMFAService())
	biometricAuthenticator   = authentication.NewBiometricAuthenticator(logger.NewLogger(), storage.NewFileStorageClient())
	sessionManager           = authentication.NewSessionManager(logger.NewLogger(), storage.NewStorage(), 30*time.Minute)
	authMiddleware           = authentication.NewAuthMiddleware(authentication.NewTokenService(), logger.NewLogger())
	walletManager            = authentication.NewWalletManager()
)

// RegisterHandler handles user registration
func RegisterHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Mnemonic string `json:"mnemonic"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	userAccount, err := accountManager.RegisterAccount(req.Username, req.Password, req.Mnemonic)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(userAccount)
}

// LoginHandler handles user login
func LoginHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username     string `json:"username"`
		Password     string `json:"password"`
		Key          string `json:"key"`
		UsePrivateKey bool  `json:"use_private_key"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	userAccount, err := accountManager.LoginAccount(req.Username, req.Password, req.UsePrivateKey, req.Key)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(userAccount)
}

// MFAHandler handles multi-factor authentication
func MFAHandler(w http.ResponseWriter, r *http.Request) {
	var req authentication.MFARequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	resp, err := mfaAuthenticator.AuthenticateMFA(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// BiometricRegisterHandler registers biometric data
func BiometricRegisterHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		UserID       string `json:"user_id"`
		BiometricData []byte `json:"biometric_data"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	err := biometricAuthenticator.RegisterBiometricData(req.UserID, req.BiometricData)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}

// BiometricAuthHandler handles biometric authentication
func BiometricAuthHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		UserID       string `json:"user_id"`
		BiometricData []byte `json:"biometric_data"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	success, err := biometricAuthenticator.AuthenticateUser(req.UserID, req.BiometricData)
	if err != nil || !success {
		http.Error(w, "Biometric authentication failed", http.StatusUnauthorized)
		return
	}

	w.WriteHeader(http.StatusOK)
}

// SessionCreateHandler creates a new session
func SessionCreateHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		UserID string `json:"user_id"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	session, err := sessionManager.CreateSession(req.UserID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(session)
}

// SessionRetrieveHandler retrieves an existing session
func SessionRetrieveHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		SessionID string `json:"session_id"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	session, err := sessionManager.RetrieveSession(req.SessionID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(session)
}

// SessionEndHandler ends an existing session
func SessionEndHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		SessionID string `json:"session_id"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	err := sessionManager.EndSession(req.SessionID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}

// SetupRoutes sets up the routes for the wallet authentication API
func SetupRoutes() *mux.Router {
	r := mux.NewRouter()

	r.HandleFunc("/register", RegisterHandler).Methods("POST")
	r.HandleFunc("/login", LoginHandler).Methods("POST")
	r.HandleFunc("/mfa", MFAHandler).Methods("POST")
	r.HandleFunc("/biometric/register", BiometricRegisterHandler).Methods("POST")
	r.HandleFunc("/biometric/authenticate", BiometricAuthHandler).Methods("POST")
	r.HandleFunc("/session/create", SessionCreateHandler).Methods("POST")
	r.HandleFunc("/session/retrieve", SessionRetrieveHandler).Methods("POST")
	r.HandleFunc("/session/end", SessionEndHandler).Methods("POST")

	return r
}

// StartAPIServer starts the API server for wallet authentication
func StartAPIServer() {
	router := SetupRoutes()
	http.ListenAndServe(":8081", router)
}
