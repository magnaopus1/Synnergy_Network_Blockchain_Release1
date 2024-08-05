package apis

import (
	"encoding/json"
	"net/http"
	"sync"

	"github.com/gorilla/mux"
	"your_project_path/pkg/synnergy_network/core/wallet/core"
	"your_project_path/utils/logger"
)

var (
	hdWalletService          *core.HDWalletService
	keypairService           *core.KeypairService
	multiCurrencyWallet      *core.MultiCurrencyWallet
	notificationService      *core.NotificationService
	walletService            *core.WalletService
	walletMetadataService    *core.WalletMetadataService
	walletAPIMutex           sync.Mutex
)

func init() {
	log := logger.NewLogger("wallet_core_api.log")

	hdWalletService = core.NewHDWalletService(log)
	keypairService = core.NewKeypairService(log)
	multiCurrencyWallet = core.NewMultiCurrencyWallet()
	notificationService = core.NewNotificationService([]byte("your-encryption-key"))
	walletService = core.NewWalletService(log)
	walletMetadataService = core.NewWalletMetadataService(log)
}

// CreateHDWalletHandler handles requests to create a new HD wallet.
func CreateHDWalletHandler(w http.ResponseWriter, r *http.Request) {
	walletAPIMutex.Lock()
	defer walletAPIMutex.Unlock()

	var requestData struct {
		Seed []byte `json:"seed"`
	}

	if err := json.NewDecoder(r.Body).Decode(&requestData); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	wallet, err := hdWalletService.CreateHDWallet(requestData.Seed)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{"wallet": wallet}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(response)
}

// GenerateKeyPairHandler handles requests to generate a new key pair.
func GenerateKeyPairHandler(w http.ResponseWriter, r *http.Request) {
	walletAPIMutex.Lock()
	defer walletAPIMutex.Unlock()

	keypair, err := keypairService.GenerateKeypair()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{"keypair": keypair}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(response)
}

// AddCurrencyHandler handles requests to add a new currency to the wallet.
func AddCurrencyHandler(w http.ResponseWriter, r *http.Request) {
	walletAPIMutex.Lock()
	defer walletAPIMutex.Unlock()

	var requestData struct {
		Name       string `json:"name"`
		Blockchain string `json:"blockchain"`
		KeyPair    core.KeyPair `json:"keypair"`
	}

	if err := json.NewDecoder(r.Body).Decode(&requestData); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if err := multiCurrencyWallet.AddCurrency(requestData.Name, requestData.Blockchain, requestData.KeyPair); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// NotifyBalanceUpdateHandler handles requests to send balance update notifications.
func NotifyBalanceUpdateHandler(w http.ResponseWriter, r *http.Request) {
	walletAPIMutex.Lock()
	defer walletAPIMutex.Unlock()

	var requestData struct {
		Currency string  `json:"currency"`
		Amount   float64 `json:"amount"`
	}

	if err := json.NewDecoder(r.Body).Decode(&requestData); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	notificationService.NotifyBalanceUpdate(requestData.Currency, requestData.Amount)
	w.WriteHeader(http.StatusNoContent)
}

// FreezeWalletHandler handles requests to freeze a wallet.
func FreezeWalletHandler(w http.ResponseWriter, r *http.Request) {
	walletAPIMutex.Lock()
	defer walletAPIMutex.Unlock()

	var requestData struct {
		WalletID string `json:"wallet_id"`
	}

	if err := json.NewDecoder(r.Body).Decode(&requestData); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if err := walletService.FreezeWallet(requestData.WalletID); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// UnfreezeWalletHandler handles requests to unfreeze a wallet.
func UnfreezeWalletHandler(w http.ResponseWriter, r *http.Request) {
	walletAPIMutex.Lock()
	defer walletAPIMutex.Unlock()

	var requestData struct {
		WalletID string `json:"wallet_id"`
	}

	if err := json.NewDecoder(r.Body).Decode(&requestData); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if err := walletService.UnfreezeWallet(requestData.WalletID); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// SaveWalletMetadataHandler handles requests to save wallet metadata.
func SaveWalletMetadataHandler(w http.ResponseWriter, r *http.Request) {
	walletAPIMutex.Lock()
	defer walletAPIMutex.Unlock()

	var requestData struct {
		FilePath       string          `json:"file_path"`
		EncryptionKey  []byte          `json:"encryption_key"`
		WalletMetadata core.WalletMetadata `json:"wallet_metadata"`
	}

	if err := json.NewDecoder(r.Body).Decode(&requestData); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if err := walletMetadataService.SaveMetadata(requestData.FilePath, requestData.EncryptionKey, requestData.WalletMetadata); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// LoadWalletMetadataHandler handles requests to load wallet metadata.
func LoadWalletMetadataHandler(w http.ResponseWriter, r *http.Request) {
	walletAPIMutex.Lock()
	defer walletAPIMutex.Unlock()

	var requestData struct {
		FilePath      string `json:"file_path"`
		EncryptionKey []byte `json:"encryption_key"`
	}

	if err := json.NewDecoder(r.Body).Decode(&requestData); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	metadata, err := walletMetadataService.LoadMetadata(requestData.FilePath, requestData.EncryptionKey)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{"metadata": metadata}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// RegisterWalletCoreRoutes registers the API routes for the wallet core services.
func RegisterWalletCoreRoutes(router *mux.Router) {
	router.HandleFunc("/api/v1/wallet/hdwallet", CreateHDWalletHandler).Methods("POST")
	router.HandleFunc("/api/v1/wallet/keypair", GenerateKeyPairHandler).Methods("POST")
	router.HandleFunc("/api/v1/wallet/add_currency", AddCurrencyHandler).Methods("POST")
	router.HandleFunc("/api/v1/wallet/notify_balance", NotifyBalanceUpdateHandler).Methods("POST")
	router.HandleFunc("/api/v1/wallet/freeze", FreezeWalletHandler).Methods("POST")
	router.HandleFunc("/api/v1/wallet/unfreeze", UnfreezeWalletHandler).Methods("POST")
	router.HandleFunc("/api/v1/wallet/save_metadata", SaveWalletMetadataHandler).Methods("POST")
	router.HandleFunc("/api/v1/wallet/load_metadata", LoadWalletMetadataHandler).Methods("POST")
}
