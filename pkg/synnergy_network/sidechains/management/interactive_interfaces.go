package management

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"sync"
)

// InteractiveInterfacesManager handles the interactive interfaces for blockchain management
type InteractiveInterfacesManager struct {
	mutex       sync.Mutex
	interfaces  map[string]InterfaceConfig
	server      *http.Server
	port        string
	encryptionKey []byte
}

// InterfaceConfig holds the configuration for an interactive interface
type InterfaceConfig struct {
	Endpoint   string `json:"endpoint"`
	AuthToken  string `json:"auth_token"`
	Encryption string `json:"encryption"`
}

// NewInteractiveInterfacesManager creates a new InteractiveInterfacesManager
func NewInteractiveInterfacesManager(port string, encryptionKey string) *InteractiveInterfacesManager {
	return &InteractiveInterfacesManager{
		interfaces:  make(map[string]InterfaceConfig),
		port:        port,
		encryptionKey: []byte(encryptionKey),
	}
}

// RegisterInterface registers a new interactive interface with its configuration
func (iim *InteractiveInterfacesManager) RegisterInterface(name string, config InterfaceConfig) error {
	iim.mutex.Lock()
	defer iim.mutex.Unlock()

	if _, exists := iim.interfaces[name]; exists {
		return errors.New("interface already registered")
	}

	iim.interfaces[name] = config
	return nil
}

// UpdateInterfaceConfig updates the configuration of an existing interactive interface
func (iim *InteractiveInterfacesManager) UpdateInterfaceConfig(name string, config InterfaceConfig) error {
	iim.mutex.Lock()
	defer iim.mutex.Unlock()

	if _, exists := iim.interfaces[name]; !exists {
		return errors.New("interface not registered")
	}

	iim.interfaces[name] = config
	return nil
}

// GetInterfaceConfig retrieves the configuration of a specific interactive interface
func (iim *InteractiveInterfacesManager) GetInterfaceConfig(name string) (InterfaceConfig, error) {
	iim.mutex.Lock()
	defer iim.mutex.Unlock()

	config, exists := iim.interfaces[name]
	if !exists {
		return InterfaceConfig{}, errors.New("interface not registered")
	}
	return config, nil
}

// StartServer starts the HTTP server for interactive interfaces
func (iim *InteractiveInterfacesManager) StartServer() {
	iim.server = &http.Server{
		Addr:    ":" + iim.port,
		Handler: iim.setupRoutes(),
	}
	log.Printf("Starting server on port %s", iim.port)
	if err := iim.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("Could not start server: %s", err)
	}
}

// setupRoutes sets up the HTTP routes for interactive interfaces
func (iim *InteractiveInterfacesManager) setupRoutes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/register", iim.handleRegister)
	mux.HandleFunc("/update", iim.handleUpdate)
	mux.HandleFunc("/config", iim.handleGetConfig)
	return mux
}

// handleRegister handles the registration of a new interactive interface
func (iim *InteractiveInterfacesManager) handleRegister(w http.ResponseWriter, r *http.Request) {
	var config InterfaceConfig
	if err := json.NewDecoder(r.Body).Decode(&config); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	name := r.URL.Query().Get("name")
	if name == "" {
		http.Error(w, "missing interface name", http.StatusBadRequest)
		return
	}

	if err := iim.RegisterInterface(name, config); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	w.WriteHeader(http.StatusCreated)
}

// handleUpdate handles the update of an existing interactive interface configuration
func (iim *InteractiveInterfacesManager) handleUpdate(w http.ResponseWriter, r *http.Request) {
	var config InterfaceConfig
	if err := json.NewDecoder(r.Body).Decode(&config); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	name := r.URL.Query().Get("name")
	if name == "" {
		http.Error(w, "missing interface name", http.StatusBadRequest)
		return
	}

	if err := iim.UpdateInterfaceConfig(name, config); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	w.WriteHeader(http.StatusOK)
}

// handleGetConfig handles the retrieval of an interactive interface configuration
func (iim *InteractiveInterfacesManager) handleGetConfig(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	if name == "" {
		http.Error(w, "missing interface name", http.StatusBadRequest)
		return
	}

	config, err := iim.GetInterfaceConfig(name)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if err := json.NewEncoder(w).Encode(config); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// StopServer stops the HTTP server for interactive interfaces
func (iim *InteractiveInterfacesManager) StopServer() {
	if iim.server != nil {
		if err := iim.server.Close(); err != nil {
			log.Fatalf("Could not stop server: %s", err)
		}
	}
}

// LogEvent logs important events related to interactive interfaces
func (iim *InteractiveInterfacesManager) LogEvent(event string) {
	log.Println(event)
}
