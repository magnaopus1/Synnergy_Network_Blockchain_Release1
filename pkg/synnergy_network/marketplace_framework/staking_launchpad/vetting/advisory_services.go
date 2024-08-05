package vetting

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"golang.org/x/crypto/scrypt"
	"github.com/gorilla/mux"
)

// AdvisoryService represents an advisory service for projects in the staking launchpad.
type AdvisoryService struct {
	ID              string    `json:"id"`
	ProjectID       string    `json:"project_id"`
	ServiceName     string    `json:"service_name"`
	Description     string    `json:"description"`
	ProvidedBy      string    `json:"provided_by"`
	ProvidedAt      time.Time `json:"provided_at"`
}

// AdvisoryServicesManager manages the advisory services.
type AdvisoryServicesManager struct {
	services map[string]*AdvisoryService
	lock     sync.Mutex
}

// NewAdvisoryServicesManager creates a new instance of AdvisoryServicesManager.
func NewAdvisoryServicesManager() *AdvisoryServicesManager {
	return &AdvisoryServicesManager{
		services: make(map[string]*AdvisoryService),
	}
}

// AddService adds a new advisory service.
func (manager *AdvisoryServicesManager) AddService(projectID, serviceName, description, providedBy string) (*AdvisoryService, error) {
	manager.lock.Lock()
	defer manager.lock.Unlock()

	id, err := generateUniqueID(serviceName + projectID)
	if err != nil {
		return nil, err
	}

	service := &AdvisoryService{
		ID:              id,
		ProjectID:       projectID,
		ServiceName:     serviceName,
		Description:     description,
		ProvidedBy:      providedBy,
		ProvidedAt:      time.Now(),
	}

	manager.services[id] = service
	return service, nil
}

// GetService retrieves an advisory service by its ID.
func (manager *AdvisoryServicesManager) GetService(id string) (*AdvisoryService, error) {
	manager.lock.Lock()
	defer manager.lock.Unlock()

	service, exists := manager.services[id]
	if !exists {
		return nil, errors.New("service not found")
	}
	return service, nil
}

// ListServices lists all advisory services for a given project.
func (manager *AdvisoryServicesManager) ListServices(projectID string) ([]*AdvisoryService, error) {
	manager.lock.Lock()
	defer manager.lock.Unlock()

	var services []*AdvisoryService
	for _, service := range manager.services {
		if service.ProjectID == projectID {
			services = append(services, service)
		}
	}
	return services, nil
}

// generateUniqueID generates a unique ID using scrypt.
func generateUniqueID(input string) (string, error) {
	salt, err := generateSalt()
	if err != nil {
		return "", err
	}
	dk, err := scrypt.Key([]byte(input), salt, 32768, 8, 1, 32)
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256(dk)
	return hex.EncodeToString(hash[:]), nil
}

// generateSalt generates a salt for hashing.
func generateSalt() ([]byte, error) {
	salt := make([]byte, 16)
	_, err := rand.Read(salt)
	return salt, err
}

// APIHandler handles HTTP requests for the advisory services.
type APIHandler struct {
	manager *AdvisoryServicesManager
}

// NewAPIHandler creates a new APIHandler.
func NewAPIHandler(manager *AdvisoryServicesManager) *APIHandler {
	return &APIHandler{manager: manager}
}

// AddServiceHandler handles adding new advisory services.
func (handler *APIHandler) AddServiceHandler(w http.ResponseWriter, r *http.Request) {
	var request struct {
		ProjectID   string `json:"project_id"`
		ServiceName string `json:"service_name"`
		Description string `json:"description"`
		ProvidedBy  string `json:"provided_by"`
	}
	err := json.NewDecoder(r.Body).Decode(&request)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	newService, err := handler.manager.AddService(request.ProjectID, request.ServiceName, request.Description, request.ProvidedBy)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(newService)
}

// GetServiceHandler handles retrieving an advisory service.
func (handler *APIHandler) GetServiceHandler(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	service, err := handler.manager.GetService(id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(service)
}

// ListServicesHandler handles listing all advisory services for a project.
func (handler *APIHandler) ListServicesHandler(w http.ResponseWriter, r *http.Request) {
	projectID := mux.Vars(r)["project_id"]
	services, err := handler.manager.ListServices(projectID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(services)
}

// SetupRouter sets up the HTTP router.
func SetupRouter(handler *APIHandler) *mux.Router {
	r := mux.NewRouter()
	r.HandleFunc("/advisory_services", handler.AddServiceHandler).Methods("POST")
	r.HandleFunc("/advisory_services/{id}", handler.GetServiceHandler).Methods("GET")
	r.HandleFunc("/advisory_services/project/{project_id}", handler.ListServicesHandler).Methods("GET")
	return r
}

// Encryption and decryption utilities for additional security.
func encrypt(data []byte, passphrase string) ([]byte, error) {
	block, _ := aes.NewCipher([]byte(createHash(passphrase)))
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return ciphertext, nil
}

func decrypt(data []byte, passphrase string) ([]byte, error) {
	key := []byte(createHash(passphrase))
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

func createHash(key string) string {
	hash := sha256.New()
	hash.Write([]byte(key))
	return hex.EncodeToString(hash.Sum(nil))
}
