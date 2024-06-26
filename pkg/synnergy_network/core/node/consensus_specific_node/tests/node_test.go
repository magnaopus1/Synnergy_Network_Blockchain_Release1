package main

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"testing"
	"time"
)

// MockStorage is a mock implementation of the Storage interface for testing purposes.
type MockStorage struct {
	Data map[string][]byte
}

func (ms *MockStorage) StoreData(data []byte) error {
	key := fmt.Sprintf("%d", time.Now().UnixNano())
	ms.Data[key] = data
	return nil
}

func (ms *MockStorage) RetrieveData(key string) ([]byte, error) {
	data, exists := ms.Data[key]
	if !exists {
		return nil, fmt.Errorf("data not found")
	}
	return data, nil
}

// TestNewConsensusSpecificNode tests the creation of a new Consensus-Specific Node.
func TestNewConsensusSpecificNode(t *testing.T) {
	storage := &MockStorage{Data: make(map[string][]byte)}
	node := NewConsensusSpecificNode("node-1", "PoW", ":8080", storage)

	if node.ID != "node-1" {
		t.Errorf("Expected node ID to be 'node-1', got %s", node.ID)
	}

	if node.ConsensusType != "PoW" {
		t.Errorf("Expected consensus type to be 'PoW', got %s", node.ConsensusType)
	}

	if node.NetworkAddress != ":8080" {
		t.Errorf("Expected network address to be ':8080', got %s", node.NetworkAddress)
	}
}

// TestStoreData tests storing data in the node's storage.
func TestStoreData(t *testing.T) {
	storage := &MockStorage{Data: make(map[string][]byte)}
	data := []byte("test data")
	err := storage.StoreData(data)
	if err != nil {
		t.Errorf("Failed to store data: %v", err)
	}

	// Ensure data is stored
	found := false
	for _, storedData := range storage.Data {
		if bytes.Equal(storedData, data) {
			found = true
			break
		}
	}

	if !found {
		t.Error("Stored data not found")
	}
}

// TestRetrieveData tests retrieving data from the node's storage.
func TestRetrieveData(t *testing.T) {
	storage := &MockStorage{Data: make(map[string][]byte)}
	data := []byte("test data")
	key := fmt.Sprintf("%d", time.Now().UnixNano())
	storage.Data[key] = data

	retrievedData, err := storage.RetrieveData(key)
	if err != nil {
		t.Errorf("Failed to retrieve data: %v", err)
	}

	if !bytes.Equal(retrievedData, data) {
		t.Errorf("Expected %s, got %s", data, retrievedData)
	}
}

// TestNodeStartStop tests starting and stopping the node.
func TestNodeStartStop(t *testing.T) {
	storage := &MockStorage{Data: make(map[string][]byte)}
	node := NewConsensusSpecificNode("node-1", "PoW", ":8081", storage)

	go node.Start()
	defer node.Stop()

	// Wait for the server to start
	time.Sleep(1 * time.Second)

	conn, err := net.Dial("tcp", ":8081")
	if err != nil {
		t.Errorf("Failed to connect to node: %v", err)
	}
	defer conn.Close()

	message := []byte("Hello Node")
	_, err = conn.Write(message)
	if err != nil {
		t.Errorf("Failed to send data: %v", err)
	}

	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err != nil {
		t.Errorf("Failed to read response: %v", err)
	}

	response := buffer[:n]
	expectedResponse := "Node node-1 received data: Hello Node"
	if string(response) != expectedResponse {
		t.Errorf("Expected '%s', got '%s'", expectedResponse, response)
	}
}

// TestMain function for setting up and tearing down tests
func TestMain(m *testing.M) {
	// Setup code
	os.Mkdir("./data", 0755)
	defer os.RemoveAll("./data")

	code := m.Run()

	// Teardown code
	os.Exit(code)
}
