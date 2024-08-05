package operator

import (
    "encoding/json"
    "errors"
    "log"
    "net/http"
    "sync"
    "time"

    "github.com/synnergy_network_blockchain/plasma/child_chain"
    "github.com/synnergy_network_blockchain/plasma/client"
    "github.com/synnergy_network_blockchain/plasma/contract"
    "github.com/synnergy_network_blockchain/plasma/node"
)

// FraudProof represents a fraud proof to be submitted
type FraudProof struct {
    TransactionID string    `json:"transaction_id"`
    Proof         []byte    `json:"proof"`
    Timestamp     time.Time `json:"timestamp"`
}

// Operator represents the blockchain operator with fraud proof submission capabilities
type Operator struct {
    ChainManager    *child_chain.ChainManager
    ClientManager   *client.ClientManager
    ContractManager *contract.ContractManager
    NodeManager     *node.NodeManager
    fraudProofs     map[string]FraudProof
    mu              sync.Mutex
}

// NewOperator initializes a new Operator
func NewOperator(cm *child_chain.ChainManager, clm *client.ClientManager, ctm *contract.ContractManager, nm *node.NodeManager) *Operator {
    return &Operator{
        ChainManager:    cm,
        ClientManager:   clm,
        ContractManager: ctm,
        NodeManager:     nm,
        fraudProofs:     make(map[string]FraudProof),
    }
}

// SubmitFraudProof submits a fraud proof
func (o *Operator) SubmitFraudProof(proof FraudProof) error {
    o.mu.Lock()
    defer o.mu.Unlock()

    if _, exists := o.fraudProofs[proof.TransactionID]; exists {
        return errors.New("fraud proof already exists for this transaction")
    }

    o.fraudProofs[proof.TransactionID] = proof
    return nil
}

// GetFraudProof retrieves a fraud proof
func (o *Operator) GetFraudProof(transactionID string) (FraudProof, error) {
    o.mu.Lock()
    defer o.mu.Unlock()

    proof, exists := o.fraudProofs[transactionID]
    if !exists {
        return FraudProof{}, errors.New("fraud proof not found")
    }

    return proof, nil
}

// HandleFraudProofSubmission handles incoming fraud proof submissions
func (o *Operator) HandleFraudProofSubmission(w http.ResponseWriter, r *http.Request) {
    var proof FraudProof
    if err := json.NewDecoder(r.Body).Decode(&proof); err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }

    err := o.SubmitFraudProof(proof)
    if err != nil {
        http.Error(w, err.Error(), http.StatusConflict)
        return
    }

    w.WriteHeader(http.StatusOK)
}

// HandleGetFraudProof handles incoming requests to retrieve fraud proofs
func (o *Operator) HandleGetFraudProof(w http.ResponseWriter, r *http.Request) {
    transactionID := r.URL.Query().Get("transaction_id")
    if transactionID == "" {
        http.Error(w, "transaction_id is required", http.StatusBadRequest)
        return
    }

    proof, err := o.GetFraudProof(transactionID)
    if err != nil {
        http.Error(w, err.Error(), http.StatusNotFound)
        return
    }

    responseJSON, err := json.Marshal(proof)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    w.Header().Set("Content-Type", "application/json")
    w.Write(responseJSON)
}

// RegisterFraudProofRoutes registers the HTTP routes for fraud proof submissions
func (o *Operator) RegisterFraudProofRoutes() {
    http.HandleFunc("/submit_fraud_proof", o.HandleFraudProofSubmission)
    http.HandleFunc("/get_fraud_proof", o.HandleGetFraudProof)
    log.Fatal(http.ListenAndServe(":8083", nil))
}
