package syn2800

import (
    "encoding/json"
    "net/http"
    "github.com/gorilla/mux"
)

var Ledger *InsuranceLedger

func InitializeHandlers(router *mux.Router) {
    Ledger = NewInsuranceLedger()

    router.HandleFunc("/tokens", CreateTokenHandler).Methods("POST")
    router.HandleFunc("/tokens/{tokenID}", GetTokenHandler).Methods("GET")
    router.HandleFunc("/tokens/{tokenID}/activate", ActivateTokenHandler).Methods("PUT")
    router.HandleFunc("/tokens/{tokenID}/deactivate", DeactivateTokenHandler).Methods("PUT")
    router.HandleFunc("/tokens/owner/{ownerID}", ListTokensByOwnerHandler).Methods("GET")
}

func CreateTokenHandler(w http.ResponseWriter, r *http.Request) {
    var policy InsurancePolicy
    if err := json.NewDecoder(r.Body).Decode(&policy); err != nil {
        http.Error(w, "Invalid request body", http.StatusBadRequest)
        return
    }

    token, err := Ledger.IssueToken(policy, "InsuranceCompanyXYZ")
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    w.WriteHeader(http.StatusCreated)
    json.NewEncoder(w).Encode(token)
}

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

func ActivateTokenHandler(w http.ResponseWriter, r *http.Request) {
    vars := mux.Vars(r)
    tokenID := vars["tokenID"]

    if err := Ledger.ActivateToken(tokenID); err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }

    w.WriteHeader(http.StatusOK)
    w.Write([]byte("Token activated successfully"))
}

func DeactivateTokenHandler(w http.ResponseWriter, r *http.Request) {
    vars := mux.Vars(r)
    tokenID := vars["tokenID"]

    if err := Ledger.DeactivateToken(tokenID); err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }

    w.WriteHeader(http.StatusOK)
    w.Write([]byte("Token deactivated successfully"))
}

func ListTokensByOwnerHandler(w http.ResponseWriter, r *http.Request) {
    vars := mux.Vars(r)
    ownerID := vars["ownerID"]

    tokens, err := Ledger.ListTokensByOwner(ownerID)
    if err != nil {
        http.Error(w, err.Error(), http.StatusNotFound)
        return
    }

    json.NewEncoder(w).Encode(tokens)
}
