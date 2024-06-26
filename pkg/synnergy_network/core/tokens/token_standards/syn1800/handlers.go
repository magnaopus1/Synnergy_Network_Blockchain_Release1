package syn1800

import (
    "encoding/json"
    "fmt"
    "net/http"
    "time"
    "github.com/gorilla/mux"
)

type Handlers struct {
    Ledger *SYN1800Ledger
}

func NewHandlers(ledger *SYN1800Ledger) *Handlers {
    return &Handlers{Ledger: ledger}
}

func (h *Handlers) RegisterRoutes(router *mux.Router) {
    router.HandleFunc("/api/tokens/events", h.CreateEvent).Methods("POST")
    router.HandleFunc("/api/tokens/sell", h.SellTicket).Methods("POST")
    router.HandleFunc("/api/tokens/{owner}", h.GetAccountInfo).Methods("GET")
}

func (h *Handlers) CreateEvent(w http.ResponseWriter, r *http.Request) {
    var event Event
    if err := json.NewDecoder(r.Body).Decode(&event); err != nil {
        http.Error(w, "Invalid request payload", http.StatusBadRequest)
        return
    }
    event.ID = generateID()
    event.Timestamp = time.Now()

    if err := h.Ledger.CreateEvent(event); err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }
    w.WriteHeader(http.StatusCreated)
    json.NewEncoder(w).Encode(event)
}

func (h *Handlers) SellTicket(w http.ResponseWriter, r *http.Request) {
    var sale struct {
        EventID  string `json:"eventID"`
        TicketID string `json:"ticketID"`
    }
    if err := json.NewDecoder(r.Body).Decode(&sale); err != nil {
        http.Error(w, "Invalid request payload", http.StatusBadRequest)
        return
    }

    if err := h.Ledger.SellTicket(sale.EventID, sale.TicketID); err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }
    w.WriteHeader(http.StatusOK)
    json.NewEncoder(w).Encode(map[string]string{"message": "Ticket sold successfully"})
}

func (h *Handlers) GetAccountInfo(w http.ResponseWriter, r *http.Request) {
    vars := mux.Vars(r)
    owner := vars["owner"]
    account, err := h.Ledger.GetAccountInfo(owner)
    if err != nil {
        http.Error(w, err.Error(), http.StatusNotFound)
        return
    }
    json.NewEncoder(w).Encode(account)
}

func generateID() string {
    return fmt.Sprintf("%d", time.Now().UnixNano())
}

