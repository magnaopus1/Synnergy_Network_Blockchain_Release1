package launchpad

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/mux"
	"golang.org/x/crypto/scrypt"
)

// LaunchService represents a comprehensive launch service
type LaunchService struct {
	ID             string    `json:"id"`
	Name           string    `json:"name"`
	Description    string    `json:"description"`
	Creator        string    `json:"creator"`
	CreatedAt      time.Time `json:"created_at"`
	SupportDetails string    `json:"support_details"`
}

// LaunchServiceRequest represents a request for creating a launch service
type LaunchServiceRequest struct {
	Name           string `json:"name"`
	Description    string `json:"description"`
	Creator        string `json:"creator"`
	SupportDetails string `json:"support_details"`
}

// LaunchServiceManager manages comprehensive launch services
type LaunchServiceManager struct {
	Services map[string]*LaunchService
	Lock     sync.Mutex
}

// NewLaunchServiceManager creates a new LaunchServiceManager instance
func NewLaunchServiceManager() *LaunchServiceManager {
	return &LaunchServiceManager{
		Services: make(map[string]*LaunchService),
	}
}

// CreateLaunchService creates a new launch service
func (manager *LaunchServiceManager) CreateLaunchService(request LaunchServiceRequest) (*LaunchService, error) {
	manager.Lock.Lock()
	defer manager.Lock.Unlock()

	id, err := generateUniqueID(request.Creator + time.Now().String())
	if err != nil {
		return nil, err
	}

	service := &LaunchService{
		ID:             id,
		Name:           request.Name,
		Description:    request.Description,
		Creator:        request.Creator,
		CreatedAt:      time.Now(),
		SupportDetails: request.SupportDetails,
	}

	manager.Services[id] = service
	return service, nil
}

// GetLaunchService retrieves a launch service by ID
func (manager *LaunchServiceManager) GetLaunchService(id string) (*LaunchService, error) {
	manager.Lock.Lock()
	defer manager.Lock.Unlock()

	service, exists := manager.Services[id]
	if !exists {
		return nil, errors.New("service not found")
	}
	return service, nil
}

// ListLaunchServices lists all launch services
func (manager *LaunchServiceManager) ListLaunchServices() []*LaunchService {
	manager.Lock.Lock()
	defer manager.Lock.Unlock()

	services := make([]*LaunchService, 0, len(manager.Services))
	for _, service := range manager.Services {
		services = append(services, service)
	}
	return services
}

// generateUniqueID generates a unique ID using scrypt
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

// generateSalt generates a salt for hashing
func generateSalt() ([]byte, error) {
	salt := make([]byte, 16)
	_, err := rand.Read(salt)
	return salt, err
}

// APIHandler handles HTTP requests for launch services
type APIHandler struct {
	manager *LaunchServiceManager
}

// NewAPIHandler creates a new APIHandler
func NewAPIHandler(manager *LaunchServiceManager) *APIHandler {
	return &APIHandler{manager: manager}
}

// CreateLaunchServiceHandler handles creating launch services
func (handler *APIHandler) CreateLaunchServiceHandler(w http.ResponseWriter, r *http.Request) {
	var request LaunchServiceRequest
	err := json.NewDecoder(r.Body).Decode(&request)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	newService, err := handler.manager.CreateLaunchService(request)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(newService)
}

// GetLaunchServiceHandler handles retrieving a launch service
func (handler *APIHandler) GetLaunchServiceHandler(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	service, err := handler.manager.GetLaunchService(id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(service)
}

// ListLaunchServicesHandler handles listing all launch services
func (handler *APIHandler) ListLaunchServicesHandler(w http.ResponseWriter, r *http.Request) {
	services := handler.manager.ListLaunchServices()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(services)
}

// SetupRouter sets up the HTTP router
func SetupRouter(handler *APIHandler) *mux.Router {
	r := mux.NewRouter()
	r.HandleFunc("/launch_service", handler.CreateLaunchServiceHandler).Methods("POST")
	r.HandleFunc("/launch_service/{id}", handler.GetLaunchServiceHandler).Methods("GET")
	r.HandleFunc("/launch_services", handler.ListLaunchServicesHandler).Methods("GET")
	return r
}

// main initializes and starts the server
func main() {
	manager := NewLaunchServiceManager()
	handler := NewAPIHandler(manager)
	router := SetupRouter(handler)

	http.ListenAndServe(":8080", router)
}
