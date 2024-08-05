package calendar

import (
	"encoding/json"
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"golang.org/x/crypto/scrypt"
)

// InteractiveFeature represents an interactive feature for events
type InteractiveFeature struct {
	ID        string
	EventID   string
	Type      string
	Content   string
	CreatedAt time.Time
	UpdatedAt time.Time
}

// InteractiveFeatureManager manages interactive features for events
type InteractiveFeatureManager struct {
	Features map[string]*InteractiveFeature
	Lock     sync.Mutex
}

// NewInteractiveFeatureManager creates a new InteractiveFeatureManager instance
func NewInteractiveFeatureManager() *InteractiveFeatureManager {
	return &InteractiveFeatureManager{
		Features: make(map[string]*InteractiveFeature),
	}
}

// AddInteractiveFeature adds a new interactive feature to an event
func (manager *InteractiveFeatureManager) AddInteractiveFeature(eventID, featureType, content string) (*InteractiveFeature, error) {
	manager.Lock.Lock()
	defer manager.Lock.Unlock()

	id, err := generateUniqueID(eventID + featureType + content)
	if err != nil {
		return nil, err
	}

	feature := &InteractiveFeature{
		ID:        id,
		EventID:   eventID,
		Type:      featureType,
		Content:   content,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	manager.Features[id] = feature
	return feature, nil
}

// GetInteractiveFeature retrieves an interactive feature by ID
func (manager *InteractiveFeatureManager) GetInteractiveFeature(id string) (*InteractiveFeature, error) {
	manager.Lock.Lock()
	defer manager.Lock.Unlock()

	feature, exists := manager.Features[id]
	if !exists {
		return nil, errors.New("interactive feature not found")
	}
	return feature, nil
}

// UpdateInteractiveFeature updates an existing interactive feature
func (manager *InteractiveFeatureManager) UpdateInteractiveFeature(id, featureType, content string) (*InteractiveFeature, error) {
	manager.Lock.Lock()
	defer manager.Lock.Unlock()

	feature, exists := manager.Features[id]
	if !exists {
		return nil, errors.New("interactive feature not found")
	}

	feature.Type = featureType
	feature.Content = content
	feature.UpdatedAt = time.Now()

	return feature, nil
}

// DeleteInteractiveFeature deletes an interactive feature by ID
func (manager *InteractiveFeatureManager) DeleteInteractiveFeature(id string) error {
	manager.Lock.Lock()
	defer manager.Lock.Unlock()

	_, exists := manager.Features[id]
	if !exists {
		return errors.New("interactive feature not found")
	}

	delete(manager.Features, id)
	return nil
}

// generateUniqueID generates a unique ID for the interactive feature
func generateUniqueID(input string) (string, error) {
	salt, err := generateSalt()
	if err != nil {
		return "", err
	}
	dk, err := scrypt.Key([]byte(input), salt, 32768, 8, 1, 32)
	if err != nil {
		return "", err
	}
	return string(dk), nil
}

func generateSalt() ([]byte, error) {
	salt := make([]byte, 16)
	_, err := rand.Read(salt)
	return salt, err
}

// WebSocketHandler handles WebSocket connections for real-time interactivity
type WebSocketHandler struct {
	upgrader websocket.Upgrader
	manager  *InteractiveFeatureManager
	clients  map[*websocket.Conn]bool
	broadcast chan []byte
}

// NewWebSocketHandler creates a new WebSocketHandler
func NewWebSocketHandler(manager *InteractiveFeatureManager) *WebSocketHandler {
	return &WebSocketHandler{
		upgrader: websocket.Upgrader{
			ReadBufferSize:  1024,
			WriteBufferSize: 1024,
			CheckOrigin:     func(r *http.Request) bool { return true },
		},
		manager:  manager,
		clients:  make(map[*websocket.Conn]bool),
		broadcast: make(chan []byte),
	}
}

// HandleConnections handles WebSocket connections
func (handler *WebSocketHandler) HandleConnections(w http.ResponseWriter, r *http.Request) {
	ws, err := handler.upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer ws.Close()

	handler.clients[ws] = true

	for {
		var msg map[string]interface{}
		err := ws.ReadJSON(&msg)
		if err != nil {
			delete(handler.clients, ws)
			break
		}
		handler.broadcast <- msg
	}
}

// HandleMessages handles broadcasting messages to all clients
func (handler *WebSocketHandler) HandleMessages() {
	for {
		msg := <-handler.broadcast
		for client := range handler.clients {
			err := client.WriteJSON(msg)
			if err != nil {
				client.Close()
				delete(handler.clients, client)
			}
		}
	}
}

// APIHandler handles HTTP requests for managing interactive features
type APIHandler struct {
	manager *InteractiveFeatureManager
}

// NewAPIHandler creates a new APIHandler
func NewAPIHandler(manager *InteractiveFeatureManager) *APIHandler {
	return &APIHandler{manager: manager}
}

// AddInteractiveFeatureHandler handles adding a new interactive feature
func (handler *APIHandler) AddInteractiveFeatureHandler(w http.ResponseWriter, r *http.Request) {
	var feature InteractiveFeature
	err := json.NewDecoder(r.Body).Decode(&feature)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	newFeature, err := handler.manager.AddInteractiveFeature(feature.EventID, feature.Type, feature.Content)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(newFeature)
}

// GetInteractiveFeatureHandler handles retrieving an interactive feature
func (handler *APIHandler) GetInteractiveFeatureHandler(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	feature, err := handler.manager.GetInteractiveFeature(id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(feature)
}

// UpdateInteractiveFeatureHandler handles updating an existing interactive feature
func (handler *APIHandler) UpdateInteractiveFeatureHandler(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	var feature InteractiveFeature
	err := json.NewDecoder(r.Body).Decode(&feature)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	updatedFeature, err := handler.manager.UpdateInteractiveFeature(id, feature.Type, feature.Content)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(updatedFeature)
}

// DeleteInteractiveFeatureHandler handles deleting an interactive feature
func (handler *APIHandler) DeleteInteractiveFeatureHandler(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	err := handler.manager.DeleteInteractiveFeature(id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func main() {
	manager := NewInteractiveFeatureManager()
	apiHandler := NewAPIHandler(manager)
	webSocketHandler := NewWebSocketHandler(manager)

	go webSocketHandler.HandleMessages()

	http.HandleFunc("/ws", webSocketHandler.HandleConnections)
	http.HandleFunc("/add", apiHandler.AddInteractiveFeatureHandler)
	http.HandleFunc("/get", apiHandler.GetInteractiveFeatureHandler)
	http.HandleFunc("/update", apiHandler.UpdateInteractiveFeatureHandler)
	http.HandleFunc("/delete", apiHandler.DeleteInteractiveFeatureHandler)

	http.ListenAndServe(":8080", nil)
}
