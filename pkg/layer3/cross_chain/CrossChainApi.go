package cross_chain

import (
    "encoding/json"
    "fmt"
    "net/http"
    "sync"
)

// CrossChainAPI provides an HTTP interface for cross-chain operations.
type CrossChainAPI struct {
    coordinator *CrossChainCoordinator
    server      *http.Server
}

// NewCrossChainAPI creates a new API service for managing cross-chain interactions.
func NewCrossChainAPI(coordinator *CrossChainCoordinator) *CrossChainAPI {
    api := &CrossChainAPI{
        coordinator: coordinator,
    }
    api.setupRoutes()
    return api
}

// setupRoutes initializes the routes for the HTTP server.
func (api *CrossChainAPI) setupRoutes() {
    mux := http.NewServeMux()
    mux.HandleFunc("/transferAsset", api.handleTransferAsset)
    mux.HandleFunc("/invokeContract", api.handleInvokeContract)
    mux.HandleFunc("/establishBridge", api.handleEstablishBridge)
    mux.HandleFunc("/linkChains", api.handleLinkChains)
    mux.HandleFunc("/listActivities", api.handleListActivities)

    api.server = &http.Server{
        Addr:    ":8080", // Listen on port 8080
        Handler: mux,
    }
}

// Start starts the HTTP server.
func (api *CrossChainAPI) Start() error {
    fmt.Println("Starting Cross-Chain API server on port 8080")
    return api.server.ListenAndServe()
}

// handleTransferAsset processes requests to transfer assets between chains.
func (api *CrossChainAPI) handleTransferAsset(w http.ResponseWriter, r *http.Request) {
    if r.Method != "POST" {
        http.Error(w, "Only POST method is allowed", http.StatusMethodNotAllowed)
        return
    }

    var req struct {
        SourceChain      string  `json:"sourceChain"`
        DestinationChain string  `json:"destinationChain"`
        AssetType        string  `json:"assetType"`
        Amount           float64 `json:"amount"`
    }
    err := json.NewDecoder(r.Body).Decode(&req)
    if err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }

    transfer, err := api.coordinator.InitiateAssetTransfer(req.SourceChain, req.DestinationChain, req.AssetType, req.Amount)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    response, _ := json.Marshal(transfer)
    w.Header().Set("Content-Type", "application/json")
    w.Write(response)
}

// handleInvokeContract processes requests to invoke a contract on another chain.
func (api *CrossChainAPI) handleInvokeContract(w http.ResponseWriter, r *http.Request) {
    // Similar to handleTransferAsset, but for invoking contracts
}

// handleEstablishBridge processes requests to establish a bridge between two chains.
func (api *CrossChainAPI) handleEstablishBridge(w http.ResponseWriter, r *http.Request) {
    // Implementation for handling bridge establishment requests
}

// handleLinkChains processes requests to establish links between chains for data synchronization.
func (api *CrossChainAPI) handleLinkChains(w http.ResponseWriter, r *http.Request) {
    // Implementation for handling chain link establishment requests
}

// handleListActivities provides a summary of all cross-chain activities.
func (api *CrossChainAPI) handleListActivities(w http.ResponseWriter, r *http.Request) {
    if r.Method != "GET" {
        http.Error(w, "Only GET method is allowed", http.StatusMethodNotAllowed)
        return
    }

    activities := api.coordinator.ListAllCrossChainActivities()
    response, _ := json.Marshal(activities)
    w.Header().Set("Content-Type", "application/json")
    w.Write(response)
}
