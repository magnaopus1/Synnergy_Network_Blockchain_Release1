package syn845

import (
    "encoding/json"
    "log"
    "net/http"
    "time"
)

// DebtHandler handles HTTP requests related to debt instruments.
type DebtHandler struct {
    Storage *DebtStorage
}

// NewDebtHandler initializes a new handler with the necessary storage component.
func NewDebtHandler(storage *DebtStorage) *DebtHandler {
    return &DebtHandler{
        Storage: storage,
    }
}

// CreateDebtInstrument handles the creation of new debt instruments via HTTP POST requests.
func (dh *DebtHandler) CreateDebtInstrument(w http.ResponseWriter, r *http.Request) {
    decoder := json.NewDecoder(r.Body)
    var params struct {
        ID            string  `json:"id"`
        Owner         string  `json:"owner"`
        Principal     float64 `json:"principal"`
        InterestRate  float64 `json:"interest_rate"`
        PenaltyRate   float64 `json:"penalty_rate"`
        LoanTermYears int     `json:"loan_term_years"`
    }
    if err := decoder.Decode(&params); err != nil {
        http.Error(w, "Invalid request body", http.StatusBadRequest)
        log.Printf("Error decoding create debt request: %v", err)
        return
    }

    loanTerm := time.Duration(params.LoanTermYears) * 365 * 24 * time.Hour // Convert years to duration
    debtInstrument := NewDebtInstrument(params.ID, params.Owner, params.Principal, params.InterestRate, params.PenaltyRate, loanTerm)
    if err := dh.Storage.SaveDebtInstrument(debtInstrument); err != nil {
        http.Error(w, "Failed to create debt instrument", http.StatusInternalServerError)
        log.Printf("Error saving debt instrument: %v", err)
        return
    }

    w.WriteHeader(http.StatusCreated)
    json.NewEncoder(w).Encode(debtInstrument)
    log.Printf("Debt instrument created successfully: %v", debtInstrument)
}

// MakePayment handles making payments towards debt instruments.
func (dh *DebtHandler) MakePayment(w http.ResponseWriter, r *http.Request) {
    decoder := json.NewDecoder(r.Body)
    var paymentInfo struct {
        ID     string  `json:"id"`
        Amount float64 `json:"amount"`
    }
    if err := decoder.Decode(&paymentInfo); err != nil {
        http.Error(w, "Invalid payment data", http.StatusBadRequest)
        log.Printf("Error decoding payment request: %v", err)
        return
    }

    debtInstrument, err := dh.Storage.LoadDebtInstrument(paymentInfo.ID)
    if err != nil {
        http.Error(w, "Debt instrument not found", http.StatusNotFound)
        log.Printf("Debt instrument not found: %v", err)
        return
    }

    if err := debtInstrument.MakePayment(paymentInfo.Amount); err != nil {
        http.Error(w, "Payment failed", http.StatusInternalServerError)
        log.Printf("Error processing payment: %v", err)
        return
    }

    dh.Storage.SaveDebtInstrument(debtInstrument)
    w.WriteHeader(http.StatusOK)
    json.NewEncoder(w).Encode(debtInstrument)
    log.Printf("Payment processed successfully for debt instrument %s", paymentInfo.ID)
}

// RegisterHandlers registers the HTTP handlers for debt management.
func (dh *DebtHandler) RegisterHandlers(mux *http.ServeMux) {
    mux.HandleFunc("/createDebtInstrument", dh.CreateDebtInstrument)
    mux.HandleFunc("/makePayment", dh.MakePayment)
    log.Println("Debt instrument handlers registered.")
}
