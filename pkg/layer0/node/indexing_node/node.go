package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/dgraph-io/badger/v3"
	"github.com/gorilla/mux"
)

type Config struct {
	Port               string `json:"port"`
	DatabasePath       string `json:"database_path"`
	MaxMemoryUsage     int64  `json:"max_memory_usage"`
	QueryOptimization  bool   `json:"query_optimization"`
	HighBandwidthLimit int64  `json:"high_bandwidth_limit"`
}

type IndexingNode struct {
	DB               *badger.DB
	Config           Config
	TransactionIndex map[string]string // Simplified index: TransactionID -> Data
}

func main() {
	// Load configuration
	config := loadConfig("config.json")

	// Initialize the database
	db, err := badger.Open(badger.DefaultOptions(config.DatabasePath))
	if err != nil {
		log.Fatalf("Failed to open database: %v", err)
	}
	defer db.Close()

	node := IndexingNode{
		DB:               db,
		Config:           config,
		TransactionIndex: make(map[string]string),
	}

	// Setup routes
	r := mux.NewRouter()
	r.HandleFunc("/indexTransaction", node.indexTransactionHandler).Methods("POST")
	r.HandleFunc("/queryTransaction/{id}", node.queryTransactionHandler).Methods("GET")
	r.HandleFunc("/health", node.healthCheckHandler).Methods("GET")

	// Start the server
	srv := &http.Server{
		Handler:      r,
		Addr:         fmt.Sprintf(":%s", config.Port),
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
	}

	log.Printf("Starting Indexing Node on port %s", config.Port)
	log.Fatal(srv.ListenAndServe())
}

func loadConfig(filePath string) Config {
	configFile, err := os.Open(filePath)
	if err != nil {
		log.Fatalf("Failed to open config file: %v", err)
	}
	defer configFile.Close()

	var config Config
	if err := json.NewDecoder(configFile).Decode(&config); err != nil {
		log.Fatalf("Failed to decode config file: %v", err)
	}

	return config
}

func (node *IndexingNode) indexTransactionHandler(w http.ResponseWriter, r *http.Request) {
	var transaction map[string]string
	if err := json.NewDecoder(r.Body).Decode(&transaction); err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	transactionID, exists := transaction["id"]
	if !exists {
		http.Error(w, "Transaction ID is required", http.StatusBadRequest)
		return
	}

	transactionData, err := json.Marshal(transaction)
	if err != nil {
		http.Error(w, "Failed to encode transaction data", http.StatusInternalServerError)
		return
	}

	err = node.DB.Update(func(txn *badger.Txn) error {
		return txn.Set([]byte(transactionID), transactionData)
	})
	if err != nil {
		http.Error(w, "Failed to store transaction", http.StatusInternalServerError)
		return
	}

	node.TransactionIndex[transactionID] = string(transactionData)

	w.WriteHeader(http.StatusCreated)
	fmt.Fprintf(w, "Transaction %s indexed successfully", transactionID)
}

func (node *IndexingNode) queryTransactionHandler(w http.ResponseWriter, r *http.Request) {
	params := mux.Vars(r)
	transactionID := params["id"]

	var transactionData []byte
	err := node.DB.View(func(txn *badger.Txn) error {
		item, err := txn.Get([]byte(transactionID))
		if err != nil {
			return err
		}
		return item.Value(func(val []byte) error {
			transactionData = append([]byte{}, val...)
			return nil
		})
	})

	if err != nil {
		if err == badger.ErrKeyNotFound {
			http.Error(w, "Transaction not found", http.StatusNotFound)
		} else {
			http.Error(w, "Failed to query transaction", http.StatusInternalServerError)
		}
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(transactionData)
}

func (node *IndexingNode) healthCheckHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status": "healthy",
	})
}
