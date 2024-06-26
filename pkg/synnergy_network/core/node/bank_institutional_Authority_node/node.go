package main

import (
    "encoding/json"
    "io/ioutil"
    "log"
    "net/http"
    "os"

    "github.com/gorilla/mux"
    "synthron_blockchain/compliance"
    "synthron_blockchain/security"
    "synthron_blockchain/transaction"
    "synthron_blockchain/finance"
)

// BankInstitutionalNode represents a node specialized for banking and institutional authority operations.
type BankInstitutionalNode struct {
    Router            *mux.Router
    ComplianceManager *compliance.Manager
    SecurityModule    *security.Module
    TransactionEngine *transaction.Engine
    FinancialCore     *finance.Core
}

// TransactionRequest represents the structure for incoming transaction requests.
type TransactionRequest struct {
    TransactionID string `json:"transaction_id"`
    Details       string `json:"details"`
}

// NewBankInstitutionalNode initializes a new node with necessary modules and middleware.
func NewBankInstitutionalNode() *BankInstitutionalNode {
    node := &BankInstitutionalNode{
        Router:            mux.NewRouter(),
        ComplianceManager: compliance.NewManager(),
        SecurityModule:    security.NewModule(),
        TransactionEngine: transaction.NewEngine(),
        FinancialCore:     finance.NewCore(),
    }
    node.setupRoutes()
    return node
}

// setupRoutes configures the API endpoints and associates them with handler functions.
func (bin *BankInstitutionalNode) setupRoutes() {
    bin.Router.HandleFunc("/transaction/verify", bin.verifyTransaction).Methods("POST")
    bin.Router.HandleFunc("/compliance/report", bin.generateComplianceReport).Methods("GET")
    bin.Router.HandleFunc("/data/exchange", bin.handleDataExchange).Methods("POST")
}

// verifyTransaction handles the verification of transactions against compliance rules.
func (bin *BankInstitutionalNode) verifyTransaction(w http.ResponseWriter, r *http.Request) {
    log.Println("Verifying transaction for compliance...")

    var req TransactionRequest
    body, err := ioutil.ReadAll(r.Body)
    if err != nil {
        http.Error(w, "Error reading request body", http.StatusInternalServerError)
        return
    }
    err = json.Unmarshal(body, &req)
    if err != nil {
        http.Error(w, "Error parsing transaction data", http.StatusBadRequest)
        return
    }

    valid, err := bin.ComplianceManager.VerifyTransaction(req.TransactionID, req.Details)
    if err != nil {
        http.Error(w, "Compliance verification failed", http.StatusInternalServerError)
        return
    }

    if !valid {
        http.Error(w, "Transaction does not comply with policies", http.StatusForbidden)
        return
    }

    w.WriteHeader(http.StatusOK)
    w.Write([]byte("Transaction verified successfully"))
}

// generateComplianceReport automatically creates and sends compliance reports to regulatory bodies.
func (bin *BankInstitutionalNode) generateComplianceReport(w http.ResponseWriter, r *http.Request) {
    log.Println("Generating compliance report...")
    report, err := bin.ComplianceManager.GenerateReport()
    if err != nil {
        http.Error(w, "Failed to generate compliance report", http.StatusInternalServerError)
        return
    }
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(report)
}

// handleDataExchange manages secure data exchange with external financial systems.
func (bin *BankInstitutionalNode) handleDataExchange(w http.ResponseWriter, r *http.Request) {
    log.Println("Handling secure data exchange...")
    if err := bin.FinancialCore.ExchangeData(); err != nil {
        http.Error(w, "Data exchange failed", http.StatusInternalServerError)
        return
    }
    w.WriteHeader(http.StatusOK)
    w.Write([]byte("Data exchange successful"))
}

// Start launches the node on the specified port and handles incoming requests.
func (bin *BankInstitutionalNode) Start(port string) {
    log.Printf("Starting Bank/Institutional Authority Node on port %s\n", port)
    log.Fatal(http.ListenAndServe(":"+port, bin.Router))
}

func main() {
    port := os.Getenv("NODE_PORT")
    if port == "" {
        port = "8080" // default port
    }
    node := NewBankInstitutionalNode()
    node.Start(port)
}
