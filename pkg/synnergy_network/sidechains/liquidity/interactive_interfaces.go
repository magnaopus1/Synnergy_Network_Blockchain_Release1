package liquidity

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"
)

// InterfaceManager manages interactive interfaces for the liquidity sidechain
type InterfaceManager struct {
	mu      sync.RWMutex
	clients map[string]*Client
}

// Client represents an interactive client
type Client struct {
	ID          string
	DisplayName string
	Role        string
	Permissions []string
}

// NewInterfaceManager creates a new InterfaceManager instance
func NewInterfaceManager() *InterfaceManager {
	return &InterfaceManager{
		clients: make(map[string]*Client),
	}
}

// AddClient adds a new client to the InterfaceManager
func (im *InterfaceManager) AddClient(id, displayName, role string, permissions []string) error {
	im.mu.Lock()
	defer im.mu.Unlock()

	if _, exists := im.clients[id]; exists {
		return errors.New("client already exists")
	}

	im.clients[id] = &Client{
		ID:          id,
		DisplayName: displayName,
		Role:        role,
		Permissions: permissions,
	}
	return nil
}

// RemoveClient removes a client from the InterfaceManager
func (im *InterfaceManager) RemoveClient(id string) error {
	im.mu.Lock()
	defer im.mu.Unlock()

	if _, exists := im.clients[id]; !exists {
		return errors.New("client not found")
	}

	delete(im.clients, id)
	return nil
}

// GetClient retrieves a client from the InterfaceManager
func (im *InterfaceManager) GetClient(id string) (*Client, error) {
	im.mu.RLock()
	defer im.mu.RUnlock()

	client, exists := im.clients[id]
	if !exists {
		return nil, errors.New("client not found")
	}

	return client, nil
}

// ListClients lists all clients in the InterfaceManager
func (im *InterfaceManager) ListClients() map[string]*Client {
	im.mu.RLock()
	defer im.mu.RUnlock()

	clients := make(map[string]*Client)
	for id, client := range im.clients {
		clients[id] = client
	}

	return clients
}

// UpdateClient updates the details of a client in the InterfaceManager
func (im *InterfaceManager) UpdateClient(id, displayName, role string, permissions []string) error {
	im.mu.Lock()
	defer im.mu.Unlock()

	client, exists := im.clients[id]
	if !exists {
		return errors.New("client not found")
	}

	client.DisplayName = displayName
	client.Role = role
	client.Permissions = permissions
	return nil
}

// ServeHTTP implements the http.Handler interface for the InterfaceManager
func (im *InterfaceManager) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		im.handleGetClients(w, r)
	case http.MethodPost:
		im.handleAddClient(w, r)
	case http.MethodDelete:
		im.handleRemoveClient(w, r)
	case http.MethodPut:
		im.handleUpdateClient(w, r)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (im *InterfaceManager) handleGetClients(w http.ResponseWriter, r *http.Request) {
	clients := im.ListClients()
	response, _ := json.Marshal(clients)
	w.Header().Set("Content-Type", "application/json")
	w.Write(response)
}

func (im *InterfaceManager) handleAddClient(w http.ResponseWriter, r *http.Request) {
	var client Client
	if err := json.NewDecoder(r.Body).Decode(&client); err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	if err := im.AddClient(client.ID, client.DisplayName, client.Role, client.Permissions); err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}

	w.WriteHeader(http.StatusCreated)
}

func (im *InterfaceManager) handleRemoveClient(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" {
		http.Error(w, "Missing client ID", http.StatusBadRequest)
		return
	}

	if err := im.RemoveClient(id); err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func (im *InterfaceManager) handleUpdateClient(w http.ResponseWriter, r *http.Request) {
	var client Client
	if err := json.NewDecoder(r.Body).Decode(&client); err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	if err := im.UpdateClient(client.ID, client.DisplayName, client.Role, client.Permissions); err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	w.WriteHeader(http.StatusOK)
}

// StartServer starts the HTTP server for the InterfaceManager
func (im *InterfaceManager) StartServer(port int) {
	http.Handle("/clients", im)
	address := fmt.Sprintf(":%d", port)
	fmt.Printf("Starting server at %s\n", address)
	http.ListenAndServe(address, nil)
}
