package main

import (
	"bytes"
	"log"
	"net"
	"os"
	"testing"
	"time"
)

func TestForensicNode_StartStop(t *testing.T) {
	storage := &FileSystemStorage{BasePath: "./test_data"}
	node := NewForensicNode("forensic-node-1", "0.0.0.0:9090", storage)

	go node.Start()

	// Allow some time for the server to start
	time.Sleep(2 * time.Second)

	// Check if the node started correctly
	if !node.IsRunning() {
		t.Fatalf("Forensic Node did not start as expected")
	}

	// Stop the node
	node.Stop()

	// Allow some time for the server to stop
	time.Sleep(2 * time.Second)

	// Check if the node stopped correctly
	if node.IsRunning() {
		t.Fatalf("Forensic Node did not stop as expected")
	}
}

func TestForensicNode_HandleConnection(t *testing.T) {
	storage := &FileSystemStorage{BasePath: "./test_data"}
	node := NewForensicNode("forensic-node-1", "0.0.0.0:9090", storage)

	go node.Start()

	// Allow some time for the server to start
	time.Sleep(2 * time.Second)

	conn, err := net.Dial("tcp", "0.0.0.0:9090")
	if err != nil {
		t.Fatalf("Failed to connect to Forensic Node: %v", err)
	}
	defer conn.Close()

	// Send test data
	testData := []byte("test transaction data")
	_, err = conn.Write(testData)
	if err != nil {
		t.Fatalf("Failed to send data to Forensic Node: %v", err)
	}

	// Allow some time for the node to process the data
	time.Sleep(2 * time.Second)

	// Verify data was stored correctly
	storedData, err := storage.RetrieveData(time.Now().Format("20060102150405"))
	if err != nil {
		t.Fatalf("Failed to retrieve stored data: %v", err)
	}

	if !bytes.Equal(storedData, testData) {
		t.Fatalf("Stored data does not match sent data: got %s, want %s", storedData, testData)
	}

	node.Stop()
}

func TestForensicNode_Security(t *testing.T) {
	// Implement tests for encryption, access controls, and other security features.
	// These tests would typically involve ensuring that data is encrypted at rest,
	// access controls are enforced, and so on.

	// Example: Test encryption of stored data
	storage := &FileSystemStorage{BasePath: "./test_data"}
	node := NewForensicNode("forensic-node-1", "0.0.0.0:9090", storage)

	// Simulate data storage
	testData := []byte("sensitive transaction data")
	err := node.Storage.StoreData(testData)
	if err != nil {
		t.Fatalf("Failed to store data: %v", err)
	}

	// Retrieve and check if data is encrypted
	storedData, err := storage.RetrieveData(time.Now().Format("20060102150405"))
	if err != nil {
		t.Fatalf("Failed to retrieve stored data: %v", err)
	}

	if bytes.Equal(storedData, testData) {
		t.Fatalf("Data is not encrypted at rest")
	}

	node.Stop()
}

func TestForensicNode_Compliance(t *testing.T) {
	// Implement tests to ensure the node adheres to regulatory compliance checks.
	// These tests would typically involve simulating transactions and verifying
	// that they are assessed against regulatory frameworks.

	// Example: Test automated compliance checks
	storage := &FileSystemStorage{BasePath: "./test_data"}
	node := NewForensicNode("forensic-node-1", "0.0.0.0:9090", storage)

	// Simulate a non-compliant transaction
	nonCompliantData := []byte("non-compliant transaction data")
	err := node.Storage.StoreData(nonCompliantData)
	if err != nil {
		t.Fatalf("Failed to store non-compliant data: %v", err)
	}

	// Verify compliance check was performed
	complianceCheckPassed := node.CheckCompliance(nonCompliantData)
	if complianceCheckPassed {
		t.Fatalf("Non-compliant data passed compliance check")
	}

	node.Stop()
}

func TestMain(m *testing.M) {
	// Setup code before running tests
	log.Println("Setting up tests...")
	err := os.Mkdir("./test_data", 0755)
	if err != nil && !os.IsExist(err) {
		log.Fatalf("Failed to create test data directory: %v", err)
	}

	// Run the tests
	exitCode := m.Run()

	// Cleanup code after running tests
	log.Println("Cleaning up tests...")
	err = os.RemoveAll("./test_data")
	if err != nil {
		log.Fatalf("Failed to clean up test data directory: %v", err)
	}

	os.Exit(exitCode)
}
