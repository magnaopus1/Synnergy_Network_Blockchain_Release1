// Package tools provides utilities for simulation and testing purposes.
package tools

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"golang.org/x/crypto/scrypt"
	"io"
	"log"
	"math/rand"
	"sync"
	"time"
)

// TrafficType defines different types of network traffic
type TrafficType string

const (
	Transaction TrafficType = "Transaction"
	Block       TrafficType = "Block"
)

// TrafficGenerator generates network traffic for testing.
type TrafficGenerator struct {
	Nodes           []*Node
	Mutex           sync.Mutex
	Duration        time.Duration
	CheckInterval   time.Duration
	TrafficRecords  map[string][]TrafficRecord
	EncryptionKey   []byte
	Salt            []byte
}

// TrafficRecord represents a record of generated traffic.
type TrafficRecord struct {
	NodeID       string
	TrafficType  TrafficType
	Timestamp    time.Time
	PayloadSize  int
	EncryptedPayload []byte
}

// NewTrafficGenerator creates a new TrafficGenerator instance.
func NewTrafficGenerator(duration, checkInterval time.Duration) *TrafficGenerator {
	salt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		log.Fatal(err)
	}

	encryptionKey, err := scrypt.Key([]byte("passphrase"), salt, 32768, 8, 1, 32)
	if err != nil {
		log.Fatal(err)
	}

	return &TrafficGenerator{
		Nodes:          []*Node{},
		Duration:       duration,
		CheckInterval:  checkInterval,
		TrafficRecords: make(map[string][]TrafficRecord),
		EncryptionKey:  encryptionKey,
		Salt:           salt,
	}
}

// AddNode adds a new node to the traffic generator.
func (tg *TrafficGenerator) AddNode(node *Node) {
	tg.Mutex.Lock()
	defer tg.Mutex.Unlock()
	tg.Nodes = append(tg.Nodes, node)
}

// GenerateTraffic simulates network traffic for a single node.
func (tg *TrafficGenerator) GenerateTraffic(node *Node) {
	tg.Mutex.Lock()
	defer tg.Mutex.Unlock()

	// Simulate traffic generation
	trafficType := TrafficType("Transaction")
	if rand.Float32() < 0.5 {
		trafficType = TrafficType("Block")
	}

	payloadSize := rand.Intn(1024) + 256 // Random payload size between 256 and 1280 bytes
	payload := make([]byte, payloadSize)
	if _, err := io.ReadFull(rand.Reader, payload); err != nil {
		log.Fatal(err)
	}

	encryptedPayload, err := tg.EncryptData(payload)
	if err != nil {
		log.Fatal(err)
	}

	record := TrafficRecord{
		NodeID:          node.ID,
		TrafficType:     trafficType,
		Timestamp:       time.Now(),
		PayloadSize:     payloadSize,
		EncryptedPayload: encryptedPayload,
	}

	node.LastChecked = time.Now()
	tg.TrafficRecords[node.ID] = append(tg.TrafficRecords[node.ID], record)
}

// Start initiates the traffic generation simulation.
func (tg *TrafficGenerator) Start() {
	fmt.Println("Starting traffic generation simulation...")
	ticker := time.NewTicker(tg.CheckInterval)
	end := time.Now().Add(tg.Duration)

	for now := range ticker.C {
		if now.After(end) {
			ticker.Stop()
			break
		}
		for _, node := range tg.Nodes {
			tg.GenerateTraffic(node)
			fmt.Printf("Generated traffic for node %s\n", node.ID)
		}
	}
	fmt.Println("Traffic generation simulation completed.")
}

// GetNodeTrafficRecords retrieves the traffic records of a node by ID.
func (tg *TrafficGenerator) GetNodeTrafficRecords(nodeID string) ([]TrafficRecord, error) {
	tg.Mutex.Lock()
	defer tg.Mutex.Unlock()

	if records, ok := tg.TrafficRecords[nodeID]; ok {
		return records, nil
	}
	return nil, fmt.Errorf("node with ID %s not found", nodeID)
}

// GenerateReport generates a report of the simulation results.
func (tg *TrafficGenerator) GenerateReport() {
	tg.Mutex.Lock()
	defer tg.Mutex.Unlock()

	fmt.Println("Generating traffic generation report...")
	for _, node := range tg.Nodes {
		fmt.Printf("Node %s - Last Checked: %s\n", node.ID, node.LastChecked)
		for _, record := range tg.TrafficRecords[node.ID] {
			fmt.Printf("Traffic Record - Type: %s - Timestamp: %s - Payload Size: %d bytes\n", record.TrafficType, record.Timestamp, record.PayloadSize)
		}
	}
}

// ExportTrafficData exports the traffic data for all nodes.
func (tg *TrafficGenerator) ExportTrafficData() map[string][]TrafficRecord {
	tg.Mutex.Lock()
	defer tg.Mutex.Unlock()

	data := make(map[string][]TrafficRecord)
	for id, records := range tg.TrafficRecords {
		data[id] = records
	}
	return data
}

// EncryptData encrypts the provided data using AES.
func (tg *TrafficGenerator) EncryptData(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(tg.EncryptionKey)
	if err != nil {
		return nil, err
	}

	ciphertext := make([]byte, aes.BlockSize+len(data))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], data)

	return ciphertext, nil
}

// DecryptData decrypts the provided data using AES.
func (tg *TrafficGenerator) DecryptData(ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(tg.EncryptionKey)
	if err != nil {
		return nil, err
	}

	if len(ciphertext) < aes.BlockSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(ciphertext, ciphertext)

	return ciphertext, nil
}

// SaveReportToBlockchain saves the generated report to the blockchain for immutable record-keeping.
func (tg *TrafficGenerator) SaveReportToBlockchain() {
	// Placeholder for blockchain integration
	fmt.Println("Saving report to blockchain... (not implemented)")
}

// AdvancedTrafficAnalysis performs an advanced analysis of the traffic data.
func (tg *TrafficGenerator) AdvancedTrafficAnalysis() {
	// Placeholder for advanced analysis logic
	fmt.Println("Performing advanced traffic analysis... (not implemented)")
}
