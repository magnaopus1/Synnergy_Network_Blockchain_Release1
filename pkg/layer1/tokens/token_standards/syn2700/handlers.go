package syn2700

import (
    "encoding/json"
    "net/http"
    "github.com/gorilla/mux"
)

// Assuming that Ledger is properly defined and initialized elsewhere.
var Ledger *PensionLedger

func RegisterRoutes(router *mux.Router) {
    router.HandleFunc("/tokens/issue", IssueTokenHandler).Methods("POST")
    router.HandleFunc("/tokens/{tokenID}", GetTokenHandler).Methods("GET")
    router.HandleFunc("/tokens/{tokenID}/transfer", TransferTokenHandler).Methods("POST")
    router.HandleFunc("/tokens/{tokenID}/redeem", RedeemTokenHandler).Methods("POST")
    router.HandleFunc("/owner/{ownerID}/tokens", ListTokensByOwnerHandler).Methods("GET")
}

// IssueTokenHandler creates a pension token.
func IssueTokenHandler(w http.ResponseWriter, r *http.Request) {
    var token PensionToken
    if err := json.NewDecoder(r.Body).Decode(&token); err != nil {
        http.Error(w, "Invalid request body", http.StatusBadRequest)
        return
    }

    issuedToken, err := Ledger.IssueToken(token) // Assuming IssueToken accepts a PensionToken object
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    w.WriteHeader(http.StatusCreated)
    json.NewEncoder(w).Encode(issuedToken)
}

// GetTokenHandler retrieves a specific pension token by its ID.
func GetTokenHandler(w http.ResponseWriter, r *http.Request) {
    vars := mux.Vars(r)
    tokenID := vars["tokenID"]
    token, err := Ledger.GetToken(tokenID) // Ensure this method is implemented
    if err != nil {
        http.Error(w, err.Error(), http.StatusNotFound)
        return
    }

    json.NewEncoder(w).Encode(token)
}

// TransferTokenHandler transfers ownership of a specific pension token to a new owner.
func TransferTokenHandler(w http.ResponseWriter, r *http.Request) {
    vars := mux.Vars(r)
    tokenID := vars["tokenID"]
    var req struct {
        NewOwner string `json:"newOwner"`
    }
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        http.Error(w, "Invalid request body", http.StatusBadRequest)
        return
    }

    if err := Ledger.TransferToken(tokenID, req.NewOwner); err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    w.WriteHeader(http.StatusOK)
}

// RedeemTokenHandler handles the redemption of a pension token.
func RedeemTokenHandler(w http.ResponseWriter, r *http.Request) {
    vars := mux.Vars(r)
    tokenID := vars["tokenID"]
    if err := Ledger.RedeemToken(tokenID); err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    w.WriteHeader(http.StatusOK)
}

// ListTokensByOwnerHandler lists all tokens for a specific owner.
func ListTokensByOwnerHandler(w http.ResponseWriter, r *http.Request) {
    vars := mux.Vars(r)
    ownerID := vars["ownerID"]
    tokens, err := Ledger.ListTokensByOwner(ownerID) // Ensure this method is implemented
    if err != nil {
        http.Error(w, err.Error(), http.StatusNotFound)
        return
    }

    json.NewEncoder(w).Encode(tokens)
}
