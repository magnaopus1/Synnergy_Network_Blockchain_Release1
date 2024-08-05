package operator

import (
    "encoding/json"
    "errors"
    "log"
    "net/http"
    "sync"

    "github.com/synnergy_network_blockchain/plasma/child_chain"
    "github.com/synnergy_network_blockchain/plasma/client"
    "github.com/synnergy_network_blockchain/plasma/contract"
    "github.com/synnergy_network_blockchain/plasma/node"
)

// Operator represents the blockchain operator with data availability protocols
type Operator struct {
    ChainManager  *child_chain.ChainManager
    ClientManager *client.ClientManager
    ContractManager *contract.ContractManager
    NodeManager   *node.NodeManager
    data          map[string][]byte
    mu            sync.Mutex
}

// NewOperator initializes a new Operator
func NewOperator(cm *child_chain.ChainManager, clm *client.ClientManager, ctm *contract.ContractManager, nm *node.NodeManager) *Operator {
    return &Operator{
        ChainManager:  cm,
        ClientManager: clm,
        ContractManager: ctm,
        NodeManager:   nm,
        data:          make(map[string][]byte),
    }
}

// DataRequest represents a request for data availability
type DataRequest struct {
    DataID string `json:"data_id"`
}

// DataResponse represents a response for data availability
type DataResponse struct {
    DataID string `json:"data_id"`
    Data   []byte `json:"data"`
}

// StoreData stores data and ensures its availability
func (o *Operator) StoreData(dataID string, data []byte) {
    o.mu.Lock()
    defer o.mu.Unlock()
    o.data[dataID] = data
}

// GetData retrieves stored data
func (o *Operator) GetData(dataID string) ([]byte, error) {
    o.mu.Lock()
    defer o.mu.Unlock()
    data, exists := o.data[dataID]
    if !exists {
        return nil, errors.New("data not found")
    }
    return data, nil
}

// HandleDataAvailabilityRequest handles incoming data availability requests
func (o *Operator) HandleDataAvailabilityRequest(w http.ResponseWriter, r *http.Request) {
    var request DataRequest
    if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }

    data, err := o.GetData(request.DataID)
    if err != nil {
        http.Error(w, err.Error(), http.StatusNotFound)
        return
    }

    response := DataResponse{
        DataID: request.DataID,
        Data:   data,
    }
    responseJSON, err := json.Marshal(response)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    w.Header().Set("Content-Type", "application/json")
    w.Write(responseJSON)
}

// RegisterDataAvailabilityRoutes registers the HTTP routes for data availability protocols
func (o *Operator) RegisterDataAvailabilityRoutes() {
    http.HandleFunc("/request_data", o.HandleDataAvailabilityRequest)
    log.Fatal(http.ListenAndServe(":8082", nil))
}
