package child_chain

// other code

import (
    "encoding/json"
    "errors"
    "fmt"
    "log"
    "net/http"
    "sync"
)

type BlockchainServer struct {
    blockchain *Blockchain
    mu         sync.Mutex
}

func NewBlockchainServer() *BlockchainServer {
    return &BlockchainServer{
        blockchain: initializeBlockchain(),
    }
}

func (server *BlockchainServer) handleGetBlockchain(w http.ResponseWriter, r *http.Request) {
    server.mu.Lock()
    defer server.mu.Unlock()

    bytes, err := json.MarshalIndent(server.blockchain.Chain, "", "  ")
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }
    w.Header().Set("Content-Type", "application/json")
    w.Write(bytes)
}

func (server *BlockchainServer) handleAddTransaction(w http.ResponseWriter, r *http.Request) {
    var t Transaction
    decoder := json.NewDecoder(r.Body)
    if err := decoder.Decode(&t); err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }

    err := server.blockchain.addTransaction(t)
    if err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }
    w.WriteHeader(http.StatusCreated)
}

func (server *BlockchainServer) handleMineBlock(w http.ResponseWriter, r *http.Request) {
    type Miner struct {
        Address string `json:"address"`
    }
    var m Miner
    decoder := json.NewDecoder(r.Body)
    if err := decoder.Decode(&m); err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }

    block, err := server.blockchain.minePendingTransactions(m.Address)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    bytes, err := json.MarshalIndent(block, "", "  ")
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    w.Header().Set("Content-Type", "application/json")
    w.Write(bytes)
}

func (server *BlockchainServer) handleGetBalance(w http.ResponseWriter, r *http.Request) {
    type Address struct {
        Address string `json:"address"`
    }
    var a Address
    decoder := json.NewDecoder(r.Body)
    if err := decoder.Decode(&a); err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }

    balance := server.blockchain.getBalance(a.Address)
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]int{"balance": balance})
}

func (server *BlockchainServer) handleValidateChain(w http.ResponseWriter, r *http.Request) {
    isValid := server.blockchain.isChainValid()
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]bool{"isValid": isValid})
}

func (server *BlockchainServer) Run() {
    http.HandleFunc("/blockchain", server.handleGetBlockchain)
    http.HandleFunc("/transactions", server.handleAddTransaction)
    http.HandleFunc("/mine", server.handleMineBlock)
    http.HandleFunc("/balance", server.handleGetBalance)
    http.HandleFunc("/validate", server.handleValidateChain)
    log.Fatal(http.ListenAndServe(":8080", nil))
}

func main() {
    server := NewBlockchainServer()
    fmt.Println("Blockchain server is running on port 8080")
    server.Run()
}
