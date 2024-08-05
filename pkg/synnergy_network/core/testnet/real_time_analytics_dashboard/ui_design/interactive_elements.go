package ui_design

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// InteractiveElement defines the structure for an interactive UI component
type InteractiveElement struct {
	ID          string                 `json:"id"`
	Type        string                 `json:"type"`
	Data        map[string]interface{} `json:"data"`
	LastUpdated time.Time              `json:"last_updated"`
}

var interactiveElements sync.Map

// AddElement adds a new interactive element to the UI
func AddElement(id string, elementType string, data map[string]interface{}) {
	element := &InteractiveElement{
		ID:          id,
		Type:        elementType,
		Data:        data,
		LastUpdated: time.Now(),
	}
	interactiveElements.Store(id, element)
}

// UpdateElement updates an existing interactive element
func UpdateElement(id string, data map[string]interface{}) error {
	value, ok := interactiveElements.Load(id)
	if !ok {
		return fmt.Errorf("element with id %s not found", id)
	}

	element := value.(*InteractiveElement)
	element.Data = data
	element.LastUpdated = time.Now()
	interactiveElements.Store(id, element)
	return nil
}

// GetElement retrieves an interactive element by its ID
func GetElement(id string) (*InteractiveElement, error) {
	value, ok := interactiveElements.Load(id)
	if !ok {
		return nil, fmt.Errorf("element with id %s not found", id)
	}
	return value.(*InteractiveElement), nil
}

// DeleteElement removes an interactive element from the UI
func DeleteElement(id string) {
	interactiveElements.Delete(id)
}

// ListElements returns all interactive elements
func ListElements() []*InteractiveElement {
	var elements []*InteractiveElement
	interactiveElements.Range(func(key, value interface{}) bool {
		elements = append(elements, value.(*InteractiveElement))
		return true
	})
	return elements
}

// HandleInteractiveElementRequest handles HTTP requests for interactive elements
func HandleInteractiveElementRequest(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		var element InteractiveElement
		if err := json.NewDecoder(r.Body).Decode(&element); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		AddElement(element.ID, element.Type, element.Data)
		w.WriteHeader(http.StatusCreated)
	case http.MethodGet:
		id := r.URL.Query().Get("id")
		if id != "" {
			element, err := GetElement(id)
			if err != nil {
				http.Error(w, err.Error(), http.StatusNotFound)
				return
			}
			json.NewEncoder(w).Encode(element)
		} else {
			elements := ListElements()
			json.NewEncoder(w).Encode(elements)
		}
	case http.MethodPut:
		id := r.URL.Query().Get("id")
		if id == "" {
			http.Error(w, "id parameter is required", http.StatusBadRequest)
			return
		}
		var data map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := UpdateElement(id, data); err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	case http.MethodDelete:
		id := r.URL.Query().Get("id")
		if id == "" {
			http.Error(w, "id parameter is required", http.StatusBadRequest)
			return
		}
		DeleteElement(id)
		w.WriteHeader(http.StatusNoContent)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// SecureMiddleware provides basic authentication for the interactive elements
func SecureMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username, password, ok := r.BasicAuth()
		if !ok || username != "admin" || password != "password" {
			w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
			http.Error(w, "Unauthorized.", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/interactive_elements", HandleInteractiveElementRequest)
	http.ListenAndServe(":8080", SecureMiddleware(mux))
}
