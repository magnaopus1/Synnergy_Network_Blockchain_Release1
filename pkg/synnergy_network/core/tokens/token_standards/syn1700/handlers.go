package syn1700

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// Handler contains all dependencies for event ticket handlers.
type Handler struct {
	Storage Storage
}

// NewHandler creates a new Handler with the provided storage.
func NewHandler(storage Storage) *Handler {
	return &Handler{
		Storage: storage,
	}
}

// RegisterRoutes sets up the routes for event ticket management.
func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/events/create", h.CreateEvent)
	mux.HandleFunc("/api/events/info", h.GetEvent)
	mux.HandleFunc("/api/events/list", h.ListEvents)
	mux.HandleFunc("/api/tickets/sell", h.SellTicket)
}

// CreateEvent handles the creation of a new event.
func (h *Handler) CreateEvent(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var event Event
	if err := json.NewDecoder(r.Body).Decode(&event); err != nil {
		http.Error(w, fmt.Sprintf("Invalid request body: %v", err), http.StatusBadRequest)
		return
	}

	if err := h.Storage.SaveEvent(event); err != nil {
		http.Error(w, fmt.Sprintf("Error saving event: %v", err), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(event)
}

// GetEvent handles retrieving details about a specific event.
func (h *Handler) GetEvent(w http.ResponseWriter, r *http.Request) {
	eventID := r.URL.Query().Get("id")
	if eventID == "" {
		http.Error(w, "Event ID is required", http.StatusBadRequest)
		return
	}

	event, err := h.Storage.GetEvent(eventID)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error retrieving event: %v", err), http.StatusNotFound)
		return
	}

	json.NewEncoder(w).Encode(event)
}

// ListEvents returns a list of all available events.
func (h *Handler) ListEvents(w http.ResponseWriter, r *http.Request) {
	events, err := h.Storage.ListEvents()
	if err != nil {
		http.Error(w, fmt.Sprintf("Error listing events: %v", err), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(events)
}

// SellTicket marks a ticket as sold.
func (h *Handler) SellTicket(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	type sellTicketRequest struct {
		EventID  string `json:"eventId"`
		TicketID string `json:"ticketId"`
	}
	var req sellTicketRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf("Invalid request body: %v", err), http.StatusBadRequest)
		return
	}

	if err := h.Storage.SellTicket(req.EventID, req.TicketID); err != nil {
		http.Error(w, fmt.Sprintf("Error selling ticket: %v", err), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	fmt.Fprintln(w, "Ticket sold successfully")
}
