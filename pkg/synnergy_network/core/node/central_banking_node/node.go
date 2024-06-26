package main

import (
    "encoding/json"
    "log"
    "net/http"

    "github.com/gorilla/mux"
    "synthron_blockchain/security"
    "synthron_blockchain/finance"
    "synthron_blockchain/compliance"
)

type CentralBankNode struct {
    Router          *mux.Router
    FinancialCore   *finance.FinancialCore
    SecurityModule  *security.Module
    ComplianceCheck *compliance.Auditor
}

func (cbn *CentralBankNode) Initialize() {
    cbn.Router = mux.NewRouter()
    cbn.FinancialCore = finance.NewFinancialCore()
    cbn.SecurityModule = security.NewSecurityModule()
    cbn.ComplianceCheck = compliance.NewAuditor()

    cbn.setupRoutes()
}

func (cbn *CentralBankNode) setupRoutes() {
    cbn.Router.HandleFunc("/monetaryPolicy", cbn.handleMonetaryPolicy).Methods("POST")
    cbn.Router.HandleFunc("/complianceCheck", cbn.handleCompliance).Methods("GET")
    cbn.Router.HandleFunc("/transaction", cbn.handleTransaction).Methods("POST")
}

func (cbn *CentralBankNode) handleMonetaryPolicy(w http.ResponseWriter, r *http.Request) {
    var policy finance.MonetaryPolicy
    err := json.NewDecoder(r.Body).Decode(&policy)
    if err != nil {
        http.Error(w, "Error decoding request body", http.StatusBadRequest)
        return
    }

    err = cbn.FinancialCore.AdjustMonetaryPolicy(policy)
    if err != nil {
        http.Error(w, "Failed to adjust monetary policy: "+err.Error(), http.StatusInternalServerError)
        return
    }

    w.WriteHeader(http.StatusOK)
    json.NewEncoder(w).Encode("Monetary policy adjusted successfully")
}

func (cbn *CentralBankNode) handleCompliance(w http.ResponseWriter, r *http.Request) {
    results, err := cbn.ComplianceCheck.PerformAudit()
    if err != nil {
        http.Error(w, "Compliance audit failed: "+err.Error(), http.StatusInternalServerError)
        return
    }

    w.WriteHeader(http.StatusOK)
    json.NewEncoder(w).Encode(results)
}

func (cbn *CentralBankNode) handleTransaction(w http.ResponseWriter, r *http.Request) {
    var transaction finance.Transaction
    err := json.NewDecoder(r.Body).Decode(&transaction)
    if err != nil {
        http.Error(w, "Error decoding transaction data", http.StatusBadRequest)
        return
    }

    receipt, err := cbn.FinancialCore.ProcessTransaction(transaction)
    if err != nil {
        http.Error(w, "Transaction processing failed: "+err.Error(), http.StatusInternalServerError)
        return
    }

    w.WriteHeader(http.StatusOK)
    json.NewEncoder(w).Encode(receipt)
}

func (cbn *CentralBankNode) Start(port string) {
    log.Printf("Starting Central Banking Node on port %s", port)
    log.Fatal(http.ListenAndServe(":"+port, cbn.Router))
}

func main() {
    node := CentralBankNode{}
    node.Initialize()
    node.Start("8000")
}
