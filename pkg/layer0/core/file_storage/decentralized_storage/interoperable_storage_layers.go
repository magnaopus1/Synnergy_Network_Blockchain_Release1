// Package decentralized_storage manages the interoperability of different blockchain-based storage protocols within the Synnergy Network.
// This file implements interoperable storage layers to facilitate seamless integration across various decentralized storage solutions.
package decentralized_storage

import (
	"fmt"
	"net/http"

	"synthron_blockchain/pkg/network"
)

// StorageAPI defines the standard interface for interacting with different blockchain storage protocols.
type StorageAPI interface {
	Store(data []byte, key string) error
	Retrieve(key string) ([]byte, error)
}

// InteroperableStorageManager handles the integration of various storage protocols into the Synnergy Network.
type InteroperableStorageManager struct {
	storageProviders map[string]StorageAPI
}

// NewInteroperableStorageManager creates a new manager for interoperable storage layers.
func NewInteroperableStorageManager() *InteroperableStorageManager {
	return &InteroperableStorageManager{
		storageProviders: make(map[string]StorageAPI),
	}
}

// RegisterStorageProvider adds a new storage provider to the network.
func (ism *InteroperableStorageManager) RegisterStorageProvider(protocolName string, api StorageAPI) {
	ism.storageProviders[protocolName] = api
	fmt.Printf("Storage provider %s registered successfully.\n", protocolName)
}

// StoreData delegates data storage to the appropriate storage provider based on the protocol.
func (ism *InteroperableStorageManager) StoreData(protocolName string, data []byte, key string) error {
	if api, exists := ism.storageProviders[protocolName]; exists {
		return api.Store(data, key)
	}
	return fmt.Errorf("storage protocol %s is not supported", protocolName)
}

// RetrieveData retrieves data from the appropriate storage provider using the specified protocol.
func (ism *InteroperableStorageManager) RetrieveData(protocolName string, key string) ([]byte, error) {
	if api, exists := ism.storageProviders[protocolName]; exists {
		return api.Retrieve(key)
	}
	return nil, fmt.Errorf("storage protocol %s is not supported", protocolName)
}

// APIHandler handles HTTP requests for storing and retrieving data via different storage protocols.
func (ism *InteroperableStorageManager) APIHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "POST":
		protocol := r.URL.Query().Get("protocol")
		key := r.URL.Query().Get("key")
		data := []byte(r.FormValue("data"))
		if err := ism.StoreData(protocol, data, key); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		} else {
			fmt.Fprintln(w, "Data stored successfully")
		}
	case "GET":
		protocol := r.URL.Query().Get("protocol")
		key := r.URL.Query().Get("key")
		data, err := ism.RetrieveData(protocol, key)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		} else {
			w.Write(data)
		}
	default:
		http.Error(w, "Unsupported HTTP method", http.StatusMethodNotAllowed)
	}
}

// Example usage of the InteroperableStorageManager
func main() {
	manager := NewInteroperableStorageManager()
	// Example: Registering a hypothetical storage provider
	manager.RegisterStorageProvider("customBlockchainStorage", &network.CustomStorageAPI{})

	http.HandleFunc("/api/storage", manager.APIHandler)
	fmt.Println("Server listening on port 8080")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		fmt.Println("Failed to start server:", err)
	}
}
