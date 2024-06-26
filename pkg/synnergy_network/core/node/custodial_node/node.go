package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"

	"github.com/dgraph-io/badger"
	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
	"net/http"
	"time"
)

// NodeConfig holds configuration for the Custodial Node
type NodeConfig struct {
	Port            string
	EncryptionKey   string
	DatabasePath    string
	HotStoragePath  string
	ColdStoragePath string
}

// CustodialNode represents a node in the Synthron blockchain responsible for asset custody
type CustodialNode struct {
	config       NodeConfig
	db           *badger.DB
	privateKey   *rsa.PrivateKey
	storageMutex sync.RWMutex
}

// LoadConfig loads configuration from the .env file
func LoadConfig() (NodeConfig, error) {
	err := godotenv.Load()
	if err != nil {
		return NodeConfig{}, errors.New("Error loading .env file")
	}

	config := NodeConfig{
		Port:            os.Getenv("NODE_PORT"),
		EncryptionKey:   os.Getenv("ENCRYPTION_KEY"),
		DatabasePath:    os.Getenv("DATABASE_PATH"),
		HotStoragePath:  os.Getenv("HOT_STORAGE_PATH"),
		ColdStoragePath: os.Getenv("COLD_STORAGE_PATH"),
	}

	return config, nil
}

// NewCustodialNode initializes a new Custodial Node with the given configuration
func NewCustodialNode(config NodeConfig) (*CustodialNode, error) {
	opts := badger.DefaultOptions(config.DatabasePath)
	db, err := badger.Open(opts)
	if err != nil {
		return nil, err
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	node := &CustodialNode{
		config:     config,
		db:         db,
		privateKey: privateKey,
	}

	return node, nil
}

// EncryptData encrypts the given data using RSA encryption
func (node *CustodialNode) EncryptData(data []byte) (string, error) {
	label := []byte("")
	hash := sha256.New()
	ciphertext, err := rsa.EncryptOAEP(hash, rand.Reader, &node.privateKey.PublicKey, data, label)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(ciphertext), nil
}

// DecryptData decrypts the given data using RSA decryption
func (node *CustodialNode) DecryptData(ciphertext string) ([]byte, error) {
	label := []byte("")
	hash := sha256.New()
	encryptedData, err := hex.DecodeString(ciphertext)
	if err != nil {
		return nil, err
	}
	plaintext, err := rsa.DecryptOAEP(hash, rand.Reader, node.privateKey, encryptedData, label)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

// StoreAsset securely stores the asset data in the hot storage
func (node *CustodialNode) StoreAsset(assetID string, assetData []byte) error {
	node.storageMutex.Lock()
	defer node.storageMutex.Unlock()

	err := node.db.Update(func(txn *badger.Txn) error {
		return txn.Set([]byte(assetID), assetData)
	})
	if err != nil {
		return err
	}

	return nil
}

// RetrieveAsset securely retrieves the asset data from the hot storage
func (node *CustodialNode) RetrieveAsset(assetID string) ([]byte, error) {
	node.storageMutex.RLock()
	defer node.storageMutex.RUnlock()

	var assetData []byte
	err := node.db.View(func(txn *badger.Txn) error {
		item, err := txn.Get([]byte(assetID))
		if err != nil {
			return err
		}
		assetData, err = item.ValueCopy(nil)
		if err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	return assetData, nil
}

// HealthCheckHandler handles the health check requests
func (node *CustodialNode) HealthCheckHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintln(w, "Custodial Node is running")
}

// StoreAssetHandler handles the asset storage requests
func (node *CustodialNode) StoreAssetHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	assetID := vars["assetID"]

	var assetData []byte
	err := json.NewDecoder(r.Body).Decode(&assetData)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	err = node.StoreAsset(assetID, assetData)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	fmt.Fprintln(w, "Asset stored successfully")
}

// RetrieveAssetHandler handles the asset retrieval requests
func (node *CustodialNode) RetrieveAssetHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	assetID := vars["assetID"]

	assetData, err := node.RetrieveAsset(assetID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(assetData)
}

// StartServer starts the HTTP server for handling API requests
func (node *CustodialNode) StartServer() {
	router := mux.NewRouter()
	router.HandleFunc("/health", node.HealthCheckHandler).Methods("GET")
	router.HandleFunc("/store/{assetID}", node.StoreAssetHandler).Methods("POST")
	router.HandleFunc("/retrieve/{assetID}", node.RetrieveAssetHandler).Methods("GET")

	log.Println("Starting Custodial Node on port", node.config.Port)
	if err := http.ListenAndServe(":"+node.config.Port, router); err != nil {
		log.Fatal("Failed to start server:", err)
	}
}

func main() {
	config, err := LoadConfig()
	if err != nil {
		log.Fatal("Error loading configuration:", err)
	}

	node, err := NewCustodialNode(config)
	if err != nil {
		log.Fatal("Error initializing Custodial Node:", err)
	}

	node.StartServer()
}
