package wallet_cryptoApi

import (
	"crypto/ecdsa"
	"encoding/json"
	"net/http"

	"github.com/gorilla/mux"
	"your_project_path/pkg/synnergy_network/core/wallet/crypto"
	"your_project_path/utils/logger"
)

var log *logger.Logger

func init() {
	var err error
	log, err = logger.NewLogger("wallet_cryptoApi.log")
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

// GenerateKeyPairHandler handles the generation of a new key pair
func GenerateKeyPairHandler(w http.ResponseWriter, r *http.Request) {
	privateKey, err := crypto.GenerateKeyPair()
	if err != nil {
		log.Error("Failed to generate key pair: ", err)
		respondWithJSON(w, http.StatusInternalServerError, APIResponse{Status: "error", Message: "Failed to generate key pair"})
		return
	}

	publicKey := &privateKey.PublicKey
	respondWithJSON(w, http.StatusOK, APIResponse{Status: "success", Data: map[string]interface{}{
		"private_key": privateKey,
		"public_key":  publicKey,
	}})
}

// EncryptDataHandler handles data encryption
func EncryptDataHandler(w http.ResponseWriter, r *http.Request) {
	var requestData struct {
		Data      string `json:"data"`
		Passphrase string `json:"passphrase"`
	}

	if err := json.NewDecoder(r.Body).Decode(&requestData); err != nil {
		log.Error("Invalid request data: ", err)
		respondWithJSON(w, http.StatusBadRequest, APIResponse{Status: "error", Message: "Invalid request data"})
		return
	}

	encryptedData, err := crypto.EncryptData([]byte(requestData.Data), requestData.Passphrase)
	if err != nil {
		log.Error("Failed to encrypt data: ", err)
		respondWithJSON(w, http.StatusInternalServerError, APIResponse{Status: "error", Message: "Failed to encrypt data"})
		return
	}

	respondWithJSON(w, http.StatusOK, APIResponse{Status: "success", Data: map[string]interface{}{
		"encrypted_data": encryptedData,
	}})
}

// DecryptDataHandler handles data decryption
func DecryptDataHandler(w http.ResponseWriter, r *http.Request) {
	var requestData struct {
		Data      string `json:"data"`
		Passphrase string `json:"passphrase"`
	}

	if err := json.NewDecoder(r.Body).Decode(&requestData); err != nil {
		log.Error("Invalid request data: ", err)
		respondWithJSON(w, http.StatusBadRequest, APIResponse{Status: "error", Message: "Invalid request data"})
		return
	}

	decryptedData, err := crypto.DecryptData([]byte(requestData.Data), requestData.Passphrase)
	if err != nil {
		log.Error("Failed to decrypt data: ", err)
		respondWithJSON(w, http.StatusInternalServerError, APIResponse{Status: "error", Message: "Failed to decrypt data"})
		return
	}

	respondWithJSON(w, http.StatusOK, APIResponse{Status: "success", Data: map[string]interface{}{
		"decrypted_data": decryptedData,
	}})
}

// SignDataHandler handles data signing
func SignDataHandler(w http.ResponseWriter, r *http.Request) {
	var requestData struct {
		Data       string `json:"data"`
		PrivateKey string `json:"private_key"`
	}

	if err := json.NewDecoder(r.Body).Decode(&requestData); err != nil {
		log.Error("Invalid request data: ", err)
		respondWithJSON(w, http.StatusBadRequest, APIResponse{Status: "error", Message: "Invalid request data"})
		return
	}

	privateKey, err := crypto.DecodePrivateKey(requestData.PrivateKey)
	if err != nil {
		log.Error("Invalid private key: ", err)
		respondWithJSON(w, http.StatusBadRequest, APIResponse{Status: "error", Message: "Invalid private key"})
		return
	}

	signature, err := crypto.SignData(privateKey, []byte(requestData.Data))
	if err != nil {
		log.Error("Failed to sign data: ", err)
		respondWithJSON(w, http.StatusInternalServerError, APIResponse{Status: "error", Message: "Failed to sign data"})
		return
	}

	respondWithJSON(w, http.StatusOK, APIResponse{Status: "success", Data: map[string]interface{}{
		"signature": signature,
	}})
}

// VerifySignatureHandler handles signature verification
func VerifySignatureHandler(w http.ResponseWriter, r *http.Request) {
	var requestData struct {
		Data      string `json:"data"`
		PublicKey string `json:"public_key"`
		Signature string `json:"signature"`
	}

	if err := json.NewDecoder(r.Body).Decode(&requestData); err != nil {
		log.Error("Invalid request data: ", err)
		respondWithJSON(w, http.StatusBadRequest, APIResponse{Status: "error", Message: "Invalid request data"})
		return
	}

	publicKey, err := crypto.DecodePublicKey(requestData.PublicKey)
	if err != nil {
		log.Error("Invalid public key: ", err)
		respondWithJSON(w, http.StatusBadRequest, APIResponse{Status: "error", Message: "Invalid public key"})
		return
	}

	isValid := crypto.VerifySignature(publicKey, []byte(requestData.Data), []byte(requestData.Signature))
	respondWithJSON(w, http.StatusOK, APIResponse{Status: "success", Data: map[string]interface{}{
		"is_valid": isValid,
	}})
}

// HashDataHandler handles data hashing
func HashDataHandler(w http.ResponseWriter, r *http.Request) {
	var requestData struct {
		Data string `json:"data"`
	}

	if err := json.NewDecoder(r.Body).Decode(&requestData); err != nil {
		log.Error("Invalid request data: ", err)
		respondWithJSON(w, http.StatusBadRequest, APIResponse{Status: "error", Message: "Invalid request data"})
		return
	}

	hash := crypto.HashData([]byte(requestData.Data))
	respondWithJSON(w, http.StatusOK, APIResponse{Status: "success", Data: map[string]interface{}{
		"hash": hash,
	}})
}

// Set up the API routes
func SetupRoutes(router *mux.Router) {
	router.HandleFunc("/api/generate_keypair", GenerateKeyPairHandler).Methods("POST")
	router.HandleFunc("/api/encrypt_data", EncryptDataHandler).Methods("POST")
	router.HandleFunc("/api/decrypt_data", DecryptDataHandler).Methods("POST")
	router.HandleFunc("/api/sign_data", SignDataHandler).Methods("POST")
	router.HandleFunc("/api/verify_signature", VerifySignatureHandler).Methods("POST")
	router.HandleFunc("/api/hash_data", HashDataHandler).Methods("POST")
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
