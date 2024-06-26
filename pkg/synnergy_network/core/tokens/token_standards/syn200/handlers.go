package syn200

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/gorilla/mux"
)

// Handlers struct contains the services needed by the handlers
type Handlers struct {
	Storage *Storage
}

// NewHandlers initializes a new Handlers struct
func NewHandlers(storage *Storage) *Handlers {
	return &Handlers{Storage: storage}
}

// RegisterRoutes sets up the routing for SYN200 token operations
func (h *Handlers) RegisterRoutes(router *mux.Router) {
	router.HandleFunc("/api/carbon_credits", h.CreateCarbonCredit).Methods("POST")
	router.HandleFunc("/api/carbon_credits/{id}", h.GetCarbonCredit).Methods("GET")
	router.HandleFunc("/api/carbon_credits/{id}", h.UpdateCarbonCredit).Methods("PUT")
	router.HandleFunc("/api/carbon_credits/{id}", h.DeleteCarbonCredit).Methods("DELETE")
}

// CreateCarbonCredit handles the creation of new carbon credits
func (h *Handlers) CreateCarbonCredit(w http.ResponseWriter, r *http.Request) {
	var credit CarbonCredit
	if err := json.NewDecoder(r.Body).Decode(&credit); err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	if err := h.Storage.SaveCarbonCredit(&credit); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(credit)
}

// GetCarbonCredit handles retrieval of a specific carbon credit
func (h *Handlers) GetCarbonCredit(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	creditID := vars["id"]

	credit, err := h.Storage.GetCarbonCredit(creditID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(credit)
}

// UpdateCarbonCredit handles the updating of an existing carbon credit
func (h *Handlers) UpdateCarbonCredit(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	creditID := vars["id"]

	var credit CarbonCredit
	if err := json.NewDecoder(r.Body).Decode(&credit); err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}
	credit.ID = creditID

	if err := h.Storage.UpdateCarbonCredit(&credit); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(credit)
}

// DeleteCarbonCredit handles the deletion of a carbon credit
func (h *Handlers) DeleteCarbonCredit(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	creditID := vars["id"]

	if err := h.Storage.DeleteCarbonCredit(creditID); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}

// CarbonCredit struct for handling data
type CarbonCredit struct {
	ID             string  `json:"id"`
	Owner          string  `json:"owner"`
	Credits        float64 `json:"credits"`
	IssuedDate     string  `json:"issued_date"`
	ExpirationDate string  `json:"expiration_date"`
	Verified       bool    `json:"verified"`
}
