package server

import (
    "net/http"
    "encoding/json"
    "sync"

    "github.com/synthron_blockchain_final/pkg/layer0/core/blockchain"
    "github.com/synthron_blockchain_final/pkg/layer0/core/consensus"
    "github.com/synthron_blockchain_final/pkg/layer0/core/network/peer"
    "github.com/synthron_blockchain_final/pkg/layer0/core/transaction"
)

// ServerHandler manages incoming requests and blockchain interactions.
type ServerHandler struct {
    Blockchain *blockchain.Blockchain
    TxPool     *transaction.Pool
    Peers      *peer.Manager
    Consensus  consensus.Protocol
    lock       sync.Mutex
}

// NewServerHandler creates a new handler with necessary dependencies.
func NewServerHandler(blockchain *blockchain.Blockchain, txPool *transaction.Pool, peers *peer.Manager, consensus consensus.Protocol) *ServerHandler {
    return &ServerHandler{
        Blockchain: blockchain,
        TxPool:     txPool,
        Peers:      peers,
        Consensus:  consensus,
    }
}

// HandleTransaction receives and processes new transactions.
func (sh *ServerHandler) HandleTransaction(w http.ResponseWriter, r *http.Request) {
    var tx transaction.Transaction
    if err := json.NewDecoder(r.Body).Decode(&tx); err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }

    if err := sh.TxPool.AddTransaction(&tx); err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    // Broadcast transaction to peers
    sh.Peers.BroadcastTransaction(tx)

    w.WriteHeader(http.StatusAccepted)
    json.NewEncoder(w).Encode("Transaction accepted")
}

// HandleBlockProcessing handles block creation and consensus.
func (sh *ServerHandler) HandleBlockProcessing(w http.ResponseWriter, r *http.Request) {
    sh.lock.Lock()
    defer sh.lock.Unlock()

    // Attempt to create new block from transactions in the pool
    block, err := sh.Consensus.GenerateBlock(sh.Blockchain, sh.TxPool)
    if err != nil {
        http.Error(w, "Failed to generate block: "+err.Error(), http.StatusInternalServerError)
        return
    }

    // Add block to the blockchain
    if _, err := sh.Blockchain.AddBlock(block); err != nil {
        http.Error(w, "Failed to add block: "+err.Error(), http.StatusInternalServerError)
        return
    }

    // Broadcast new block to peers
    sh.Peers.BroadcastBlock(*block)

    w.WriteHeader(http.StatusOK)
    json.NewEncoder(w).Encode("Block processed and added to the blockchain")
}

// StartServer initializes the HTTP server routes.
func (sh *ServerHandler) StartServer(port string) {
    http.HandleFunc("/transaction", sh.HandleTransaction)
    http.HandleFunc("/block", sh.HandleBlockProcessing)

    // Server security enhancements like TLS should be configured here
    log.Fatal(http.ListenAndServe(":"+port, nil))
}

