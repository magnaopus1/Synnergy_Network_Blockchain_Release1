package cross_chain

import (
    "errors"
    "fmt"
    "sync"
    "time"
)

// Oracle represents a service that fetches and verifies external data for blockchain use.
type Oracle struct {
    ID          string
    ServiceURL  string
    DataType    string
    Active      bool
}

// OracleService manages multiple oracles, facilitating data verification and retrieval.
type OracleService struct {
    mu       sync.Mutex
    oracles  map[string]*Oracle // Oracles are keyed by their unique ID.
}

// NewOracleService creates a new oracle service manager.
func NewOracleService() *OracleService {
    return &OracleService{
        oracles: make(map[string]*Oracle),
    }
}

// RegisterOracle adds a new oracle to the service.
func (os *OracleService) RegisterOracle(id, serviceURL, dataType string) error {
    os.mu.Lock()
    defer os.mu.Unlock()

    if _, exists := os.oracles[id]; exists {
        return fmt.Errorf("oracle with id %s already exists", id)
    }

    os.oracles[id] = &Oracle{
        ID:         id,
        ServiceURL: serviceURL,
        DataType:   dataType,
        Active:     true,
    }
    return nil
}

// ActivateOracle activates a specific oracle for use.
func (os *OracleService) ActivateOracle(id string) error {
    os.mu.Lock()
    defer os.mu.Unlock()

    oracle, exists := os.oracles[id]
    if !exists {
        return errors.New("oracle not found")
    }

    oracle.Active = true
    fmt.Printf("Oracle %s activated.\n", id)
    return nil
}

// DeactivateOracle deactivates a specific oracle.
func (os *OracleService) DeactivateOracle(id string) error {
    os.mu.Lock()
    defer os.mu.Unlock()

    oracle, exists := os.oracles[id]
    if !exists {
        return errors.New("oracle not found")
    }

    oracle.Active = false
    fmt.Printf("Oracle %s deactivated.\n", id)
    return nil
}

// FetchData uses an oracle to fetch data from an external source.
func (os *OracleService) FetchData(oracleID string) (interface{}, error) {
    os.mu.Lock()
    defer os.mu.Unlock()

    oracle, exists := os.oracles[oracleID]
    if !exists {
        return nil, errors.New("oracle not found")
    }

    if !oracle.Active {
        return nil, errors.New("oracle is not active")
    }

    // Simulate fetching data from the oracle's external service URL
    data, err := os.retrieveExternalData(oracle.ServiceURL)
    if err != nil {
        return nil, fmt.Errorf("failed to fetch data from %s: %v", oracle.ServiceURL, err)
    }

    return data, nil
}

// retrieveExternalData simulates retrieving data from an external service.
func (os *OracleService) retrieveExternalData(serviceURL string) (interface{}, error) {
    // This should be implemented to interact with real external services/APIs.
    // For demonstration, return a static response.
    return fmt.Sprintf("Data retrieved from %s at %s", serviceURL, time.Now()), nil
}

// ListOracles provides a summary of all registered oracles.
func (os *OracleService) ListOracles() []string {
    os.mu.Lock()
    defer os.mu.Unlock()

    var list []string
    for id, oracle := range os.oracles {
        status := "inactive"
        if oracle.Active {
            status = "active"
        }
        list = append(list, fmt.Sprintf("Oracle ID: %s, URL: %s, Status: %s", id, oracle.ServiceURL, status))
    }
    return list
}
