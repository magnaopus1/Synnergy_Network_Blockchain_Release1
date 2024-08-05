package calendar

import (
	"encoding/json"
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/mux"
	"golang.org/x/crypto/scrypt"
	"math/rand"
)

// LaunchEvent represents an event on the launch calendar
type LaunchEvent struct {
	ID          string    `json:"id"`
	Title       string    `json:"title"`
	Description string    `json:"description"`
	StartTime   time.Time `json:"start_time"`
	EndTime     time.Time `json:"end_time"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// LaunchCalendarManager manages the launch calendar events
type LaunchCalendarManager struct {
	Events map[string]*LaunchEvent
	Lock   sync.Mutex
}

// NewLaunchCalendarManager creates a new LaunchCalendarManager instance
func NewLaunchCalendarManager() *LaunchCalendarManager {
	return &LaunchCalendarManager{
		Events: make(map[string]*LaunchEvent),
	}
}

// AddLaunchEvent adds a new event to the launch calendar
func (manager *LaunchCalendarManager) AddLaunchEvent(title, description string, startTime, endTime time.Time) (*LaunchEvent, error) {
	manager.Lock.Lock()
	defer manager.Lock.Unlock()

	id, err := generateUniqueID(title + description + startTime.String() + endTime.String())
	if err != nil {
		return nil, err
	}

	event := &LaunchEvent{
		ID:          id,
		Title:       title,
		Description: description,
		StartTime:   startTime,
		EndTime:     endTime,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	manager.Events[id] = event
	return event, nil
}

// GetLaunchEvent retrieves a launch event by ID
func (manager *LaunchCalendarManager) GetLaunchEvent(id string) (*LaunchEvent, error) {
	manager.Lock.Lock()
	defer manager.Lock.Unlock()

	event, exists := manager.Events[id]
	if !exists {
		return nil, errors.New("launch event not found")
	}
	return event, nil
}

// UpdateLaunchEvent updates an existing launch event
func (manager *LaunchCalendarManager) UpdateLaunchEvent(id, title, description string, startTime, endTime time.Time) (*LaunchEvent, error) {
	manager.Lock.Lock()
	defer manager.Lock.Unlock()

	event, exists := manager.Events[id]
	if !exists {
		return nil, errors.New("launch event not found")
	}

	event.Title = title
	event.Description = description
	event.StartTime = startTime
	event.EndTime = endTime
	event.UpdatedAt = time.Now()

	return event, nil
}

// DeleteLaunchEvent deletes a launch event by ID
func (manager *LaunchCalendarManager) DeleteLaunchEvent(id string) error {
	manager.Lock.Lock()
	defer manager.Lock.Unlock()

	_, exists := manager.Events[id]
	if !exists {
		return errors.New("launch event not found")
	}

	delete(manager.Events, id)
	return nil
}

// ListLaunchEvents lists all launch events
func (manager *LaunchCalendarManager) ListLaunchEvents() []*LaunchEvent {
	manager.Lock.Lock()
	defer manager.Lock.Unlock()

	events := make([]*LaunchEvent, 0, len(manager.Events))
	for _, event := range manager.Events {
		events = append(events, event)
	}
	return events
}

// generateUniqueID generates a unique ID for the launch event
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

// APIHandler handles HTTP requests for managing launch calendar events
type APIHandler struct {
	manager *LaunchCalendarManager
}

// NewAPIHandler creates a new APIHandler
func NewAPIHandler(manager *LaunchCalendarManager) *APIHandler {
	return &APIHandler{manager: manager}
}

// AddLaunchEventHandler handles adding a new launch event
func (handler *APIHandler) AddLaunchEventHandler(w http.ResponseWriter, r *http.Request) {
	var event LaunchEvent
	err := json.NewDecoder(r.Body).Decode(&event)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	newEvent, err := handler.manager.AddLaunchEvent(event.Title, event.Description, event.StartTime, event.EndTime)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(newEvent)
}

// GetLaunchEventHandler handles retrieving a launch event
func (handler *APIHandler) GetLaunchEventHandler(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	event, err := handler.manager.GetLaunchEvent(id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(event)
}

// UpdateLaunchEventHandler handles updating an existing launch event
func (handler *APIHandler) UpdateLaunchEventHandler(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	var event LaunchEvent
	err := json.NewDecoder(r.Body).Decode(&event)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	updatedEvent, err := handler.manager.UpdateLaunchEvent(id, event.Title, event.Description, event.StartTime, event.EndTime)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(updatedEvent)
}

// DeleteLaunchEventHandler handles deleting a launch event
func (handler *APIHandler) DeleteLaunchEventHandler(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	err := handler.manager.DeleteLaunchEvent(id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// ListLaunchEventsHandler handles listing all launch events
func (handler *APIHandler) ListLaunchEventsHandler(w http.ResponseWriter, r *http.Request) {
	events := handler.manager.ListLaunchEvents()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(events)
}

func main() {
	manager := NewLaunchCalendarManager()
	apiHandler := NewAPIHandler(manager)

	router := mux.NewRouter()
	router.HandleFunc("/events", apiHandler.AddLaunchEventHandler).Methods("POST")
	router.HandleFunc("/events", apiHandler.ListLaunchEventsHandler).Methods("GET")
	router.HandleFunc("/events/{id}", apiHandler.GetLaunchEventHandler).Methods("GET")
	router.HandleFunc("/events/{id}", apiHandler.UpdateLaunchEventHandler).Methods("PUT")
	router.HandleFunc("/events/{id}", apiHandler.DeleteLaunchEventHandler).Methods("DELETE")

	http.ListenAndServe(":8080", router)
}
