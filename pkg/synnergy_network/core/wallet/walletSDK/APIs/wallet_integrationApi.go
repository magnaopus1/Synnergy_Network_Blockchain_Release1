package wallet_integrationApi

import (
	"encoding/json"
	"net/http"
	"synnergy_network/core/wallet/integration"
	"synnergy_network/utils/logger"

	"github.com/gorilla/mux"
)

var log *logger.Logger

func init() {
	var err error
	log, err = logger.NewLogger("wallet_integrationApi.log")
	if err != nil {
		panic("Failed to initialize logger: " + err.Error())
	}
}

// APIResponse is a standard response structure for the APIs
type APIResponse struct {
	Status  string      `json:"status"`
	Message string      `json:"message,omitempty"`
	Data    interface{} `json:"data,omitempty"`
}

// HandleCheckBalance handles balance check requests for wallets
func HandleCheckBalance(w http.ResponseWriter, r *http.Request) {
	walletAddress := r.URL.Query().Get("wallet_address")
	if walletAddress == "" {
		respondWithJSON(w, http.StatusBadRequest, APIResponse{Status: "error", Message: "Wallet address is required"})
		return
	}

	blockchainIntegration := integration.NewBlockchainIntegration(nil, nil) // Assuming dependencies are injected
	balance, err := blockchainIntegration.CheckBalance(walletAddress)
	if err != nil {
		log.Error("Failed to check balance: ", err)
		respondWithJSON(w, http.StatusInternalServerError, APIResponse{Status: "error", Message: "Failed to check balance"})
		return
	}

	respondWithJSON(w, http.StatusOK, APIResponse{Status: "success", Data: balance})
}

// HandleSendTransaction handles transaction requests
func HandleSendTransaction(w http.ResponseWriter, r *http.Request) {
	var requestData struct {
		From       string  `json:"from"`
		To         string  `json:"to"`
		Amount     float64 `json:"amount"`
		PrivateKey string  `json:"private_key"`
	}
	if err := json.NewDecoder(r.Body).Decode(&requestData); err != nil {
		log.Error("Invalid request data: ", err)
		respondWithJSON(w, http.StatusBadRequest, APIResponse{Status: "error", Message: "Invalid request data"})
		return
	}

	blockchainIntegration := integration.NewBlockchainIntegration(nil, nil) // Assuming dependencies are injected
	if err := blockchainIntegration.SendTransaction(requestData.From, requestData.To, requestData.Amount, requestData.PrivateKey); err != nil {
		log.Error("Failed to send transaction: ", err)
		respondWithJSON(w, http.StatusInternalServerError, APIResponse{Status: "error", Message: "Failed to send transaction"})
		return
	}

	respondWithJSON(w, http.StatusOK, APIResponse{Status: "success", Message: "Transaction sent successfully"})
}

// HandleSyncWithBlockchain handles requests to sync with the blockchain
func HandleSyncWithBlockchain(w http.ResponseWriter, r *http.Request) {
	blockchainIntegration := integration.NewBlockchainIntegration(nil, nil) // Assuming dependencies are injected
	if err := blockchainIntegration.SyncWithBlockchain(); err != nil {
		log.Error("Failed to sync with blockchain: ", err)
		respondWithJSON(w, http.StatusInternalServerError, APIResponse{Status: "error", Message: "Failed to sync with blockchain"})
		return
	}

	respondWithJSON(w, http.StatusOK, APIResponse{Status: "success", Message: "Synced with blockchain successfully"})
}

// HandleCrossChainTransfer handles cross-chain asset transfer requests
func HandleCrossChainTransfer(w http.ResponseWriter, r *http.Request) {
	var requestData struct {
		SourceChain string  `json:"source_chain"`
		TargetChain string  `json:"target_chain"`
		FromAddr    string  `json:"from_addr"`
		ToAddr      string  `json:"to_addr"`
		Amount      float64 `json:"amount"`
	}
	if err := json.NewDecoder(r.Body).Decode(&requestData); err != nil {
		log.Error("Invalid request data: ", err)
		respondWithJSON(w, http.StatusBadRequest, APIResponse{Status: "error", Message: "Invalid request data"})
		return
	}

	crossChainIntegration := integration.NewCrossChainIntegration()
	txID, err := crossChainIntegration.TransferAssets(requestData.SourceChain, requestData.TargetChain, requestData.FromAddr, requestData.ToAddr, requestData.Amount)
	if err != nil {
		log.Error("Failed to transfer assets: ", err)
		respondWithJSON(w, http.StatusInternalServerError, APIResponse{Status: "error", Message: "Failed to transfer assets"})
		return
	}

	respondWithJSON(w, http.StatusOK, APIResponse{Status: "success", Data: txID})
}

// HandleExternalAPISync handles requests to sync with an external API
func HandleExternalAPISync(w http.ResponseWriter, r *http.Request) {
	externalAPIHandler := integration.NewExternalAPIHandler("api-key", "https://external-api-url.com")
	if err := externalAPIHandler.SyncWithExternalAPI(); err != nil {
		log.Error("Failed to sync with external API: ", err)
		respondWithJSON(w, http.StatusInternalServerError, APIResponse{Status: "error", Message: "Failed to sync with external API"})
		return
	}

	respondWithJSON(w, http.StatusOK, APIResponse{Status: "success", Message: "Synced with external API successfully"})
}

// HandleHSMGenerateKeyPair handles requests to generate a key pair using an HSM
func HandleHSMGenerateKeyPair(w http.ResponseWriter, r *http.Request) {
	hsm, err := integration.NewHardwareSecurityModule("/path/to/pkcs11/module", "pin")
	if err != nil {
		log.Error("Failed to initialize HSM: ", err)
		respondWithJSON(w, http.StatusInternalServerError, APIResponse{Status: "error", Message: "Failed to initialize HSM"})
		return
	}
	defer hsm.Close()

	keyPair, err := hsm.GenerateKeyPair()
	if err != nil {
		log.Error("Failed to generate key pair: ", err)
		respondWithJSON(w, http.StatusInternalServerError, APIResponse{Status: "error", Message: "Failed to generate key pair"})
		return
	}

	respondWithJSON(w, http.StatusOK, APIResponse{Status: "success", Data: keyPair})
}

// HandleThirdPartyServiceIntegration handles third-party service integration requests
func HandleThirdPartyServiceIntegration(w http.ResponseWriter, r *http.Request) {
	var requestData struct {
		URL string `json:"url"`
	}
	if err := json.NewDecoder(r.Body).Decode(&requestData); err != nil {
		log.Error("Invalid request data: ", err)
		respondWithJSON(w, http.StatusBadRequest, APIResponse{Status: "error", Message: "Invalid request data"})
		return
	}

	secClient := security.NewClient("encryption-key")
	apiHandler := integration.NewExternalAPIHandler("api-key", secClient)
	data, err := apiHandler.QueryExternalService(requestData.URL)
	if err != nil {
		log.Error("Failed to query external service: ", err)
		respondWithJSON(w, http.StatusInternalServerError, APIResponse{Status: "error", Message: "Failed to query external service"})
		return
	}

	respondWithJSON(w, http.StatusOK, APIResponse{Status: "success", Data: data})
}

// Set up the API routes
func SetupRoutes(router *mux.Router) {
	router.HandleFunc("/api/check_balance", HandleCheckBalance).Methods("GET")
	router.HandleFunc("/api/send_transaction", HandleSendTransaction).Methods("POST")
	router.HandleFunc("/api/sync_blockchain", HandleSyncWithBlockchain).Methods("POST")
	router.HandleFunc("/api/cross_chain_transfer", HandleCrossChainTransfer).Methods("POST")
	router.HandleFunc("/api/external_api_sync", HandleExternalAPISync).Methods("POST")
	router.HandleFunc("/api/hsm_generate_keypair", HandleHSMGenerateKeyPair).Methods("POST")
	router.HandleFunc("/api/third_party_service", HandleThirdPartyServiceIntegration).Methods("POST")
}

// Helper function to respond with JSON
func respondWithJSON(w http.ResponseWriter, status int, payload APIResponse) {
	response, err := json.Marshal(payload)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("HTTP 500: Internal Server Error"))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	w.Write(response)
}
