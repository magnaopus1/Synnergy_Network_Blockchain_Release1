package syn3000

import (
    "encoding/json"
    "net/http"
    "time"

    "github.com/gorilla/mux"
)

// Ledger is a global instance of RentalLedger, which acts as our in-memory database.
var Ledger = NewRentalLedger()

// RegisterHandlers sets up the routing of the HTTP handlers.
func RegisterHandlers(router *mux.Router) {
    router.HandleFunc("/tokens/issue", IssueTokenHandler).Methods("POST")
    router.HandleFunc("/tokens/terminate/{tokenID}", TerminateLeaseHandler).Methods("POST")
    router.HandleFunc("/tokens/{tokenID}", GetTokenHandler).Methods("GET")
    router.HandleFunc("/tokens/active", ListActiveLeasesHandler).Methods("GET")
}

// IssueTokenHandler handles the creation of new rental tokens.
func IssueTokenHandler(w http.ResponseWriter, r *http.Request) {
    var data struct {
        Property        Property  `json:"property"`
        Tenant          string    `json:"tenant"`
        LeaseStartDate  string    `json:"leaseStartDate"`
        LeaseEndDate    string    `json:"leaseEndDate"`
        MonthlyRent     float64   `json:"monthlyRent"`
        Deposit         float64   `json:"deposit"`
    }

    if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
        http.Error(w, "Invalid request body", http.StatusBadRequest)
        return
    }

    startDate, _ := time.Parse(time.RFC3339, data.LeaseStartDate)
    endDate, _ := time.Parse(time.RFC3339, data.LeaseEndDate)

    token, err := Ledger.IssueToken(data.Property, data.Tenant, startDate, endDate, data.MonthlyRent, data.Deposit)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    w.WriteHeader(http.StatusCreated)
    json.NewEncoder(w).Encode(token)
}

// TerminateLeaseHandler handles the termination of a lease.
func TerminateLeaseHandler(w http.ResponseWriter, r *http.Request) {
    vars := mux.Vars(r)
    tokenID := vars["tokenID"]

    if err := Ledger.TerminateLease(tokenID); err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    w.WriteHeader(http.StatusOK)
    json.NewEncoder(w).Encode("Lease terminated successfully")
}

// GetTokenHandler retrieves a specific rental token by its ID.
func GetTokenHandler(w http.ResponseWriter, r *http.Request) {
    vars := mux.Vars(r)
    tokenID := vars["tokenID"]

    token, err := Ledger.GetToken(tokenID)
    if err != nil {
        http.Error(w, err.Error(), http.StatusNotFound)
        return
    }

    json.NewEncoder(w).Encode(token)
}

// ListActiveLeasesHandler lists all active rental leases.
func ListActiveLeasesHandler(w http.ResponseWriter, r *http.Request) {
    tokens, err := Ledger.ListActiveLeases("active", "true")
    if err != nil {
        http.Error(w, err.Error(), http.StatusNotFound)
        return
    }

    json.NewEncoder(w).Encode(tokens)
}
