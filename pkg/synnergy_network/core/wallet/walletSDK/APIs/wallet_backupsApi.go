package apis

import (
	"encoding/json"
	"net/http"
	"sync"

	"github.com/gorilla/mux"
	"synnergy_network_blockchain/pkg/synnergy_network/core/wallet/backups"
	"synnergy_network_blockchain/pkg/synnergy_network/utils/logger"
	"synnergy_network_blockchain/pkg/synnergy_network/core/storage/decentralized"
)

var (
	backupService *backups.BackupService
	apiMutex      sync.Mutex
)

func init() {
	// Initialize the backup service components
	log := logger.NewLogger("backup_api.log")
	localBackup := backups.NewLocalBackup("/path/to/local/backup", log)
	cloudBackup := backups.NewCloudBackup(decentralized.NewStorageProvider(), log)
	scheduler := backups.NewScheduler(localBackup, cloudBackup, time.Hour*24) // daily backups

	backupService = backups.NewBackupService(scheduler, localBackup, cloudBackup, decentralized.NewStorageProvider(), log)
}

// EncryptDataHandler handles the encryption of data.
func EncryptDataHandler(w http.ResponseWriter, r *http.Request) {
	apiMutex.Lock()
	defer apiMutex.Unlock()

	var requestData struct {
		Data       []byte `json:"data"`
		Passphrase string `json:"passphrase"`
	}

	if err := json.NewDecoder(r.Body).Decode(&requestData); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	encryptedData, err := backups.EncryptData(requestData.Data, requestData.Passphrase)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	response := map[string]string{"encrypted_data": encryptedData}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// DecryptDataHandler handles the decryption of data.
func DecryptDataHandler(w http.ResponseWriter, r *http.Request) {
	apiMutex.Lock()
	defer apiMutex.Unlock()

	var requestData struct {
		EncryptedData string `json:"encrypted_data"`
		Passphrase    string `json:"passphrase"`
	}

	if err := json.NewDecoder(r.Body).Decode(&requestData); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	decryptedData, err := backups.DecryptData(requestData.EncryptedData, requestData.Passphrase)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	response := map[string][]byte{"decrypted_data": decryptedData}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// BackupDataHandler handles the backup of wallet data.
func BackupDataHandler(w http.ResponseWriter, r *http.Request) {
	apiMutex.Lock()
	defer apiMutex.Unlock()

	var requestData struct {
		UserID     string `json:"user_id"`
		Data       []byte `json:"data"`
		Passphrase string `json:"passphrase"`
	}

	if err := json.NewDecoder(r.Body).Decode(&requestData); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	err := backupService.LocalBackup.Backup(requestData.Data, requestData.Passphrase)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	err = backupService.CloudBackup.Backup(requestData.UserID, requestData.Data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// RestoreDataHandler handles the restoration of wallet data.
func RestoreDataHandler(w http.ResponseWriter, r *http.Request) {
	apiMutex.Lock()
	defer apiMutex.Unlock()

	var requestData struct {
		UserID     string `json:"user_id"`
		Passphrase string `json:"passphrase"`
	}

	if err := json.NewDecoder(r.Body).Decode(&requestData); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Restore from local backup first
	data, err := backupService.LocalBackup.Restore(requestData.Passphrase)
	if err != nil {
		// If local restore fails, try cloud restore
		data, err = backupService.CloudBackup.Restore(requestData.UserID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}

	response := map[string][]byte{"data": data}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// ScheduleBackupHandler handles the scheduling of backups.
func ScheduleBackupHandler(w http.ResponseWriter, r *http.Request) {
	apiMutex.Lock()
	defer apiMutex.Unlock()

	var requestData struct {
		Interval int `json:"interval"` // in hours
	}

	if err := json.NewDecoder(r.Body).Decode(&requestData); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	err := backupService.ScheduleBackup(time.Duration(requestData.Interval) * time.Hour)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// GetBackupStatusHandler provides the current status of the backup processes.
func GetBackupStatusHandler(w http.ResponseWriter, r *http.Request) {
	apiMutex.Lock()
	defer apiMutex.Unlock()

	status := backupService.GetBackupStatus()
	response := map[string]string{"status": status}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// RegisterBackupRoutes registers the API routes for the backup services.
func RegisterBackupRoutes(router *mux.Router) {
	router.HandleFunc("/api/v1/backups/encrypt", EncryptDataHandler).Methods("POST")
	router.HandleFunc("/api/v1/backups/decrypt", DecryptDataHandler).Methods("POST")
	router.HandleFunc("/api/v1/backups/backup", BackupDataHandler).Methods("POST")
	router.HandleFunc("/api/v1/backups/restore", RestoreDataHandler).Methods("POST")
	router.HandleFunc("/api/v1/backups/schedule", ScheduleBackupHandler).Methods("POST")
	router.HandleFunc("/api/v1/backups/status", GetBackupStatusHandler).Methods("GET")
}
