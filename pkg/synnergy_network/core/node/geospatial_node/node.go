package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/golang/geo/s2"
)

// GeospatialNode represents a node dedicated to handling geospatial data.
type GeospatialNode struct {
	ID             string
	NetworkAddress string
	DataChannel    net.Conn
	Storage        Storage
}

// Storage interface defines the methods required for the node's storage system.
type Storage interface {
	StoreData(key string, data []byte) error
	RetrieveData(key string) ([]byte, error)
}

// FileSystemStorage is a simple file system based storage.
type FileSystemStorage struct {
	BasePath string
}

// StoreData stores data in the file system.
func (fs *FileSystemStorage) StoreData(key string, data []byte) error {
	filePath := fmt.Sprintf("%s/%s.dat", fs.BasePath, key)
	file, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = file.Write(data)
	return err
}

// RetrieveData retrieves data from the file system.
func (fs *FileSystemStorage) RetrieveData(key string) ([]byte, error) {
	filePath := fmt.Sprintf("%s/%s.dat", fs.BasePath, key)
	data, err := os.ReadFile(filePath)
	return data, err
}

// NewGeospatialNode creates a new geospatial-specific node.
func NewGeospatialNode(id, address string, storage Storage) *GeospatialNode {
	return &GeospatialNode{
		ID:             id,
		NetworkAddress: address,
		Storage:        storage,
	}
}

// Start initiates the node's operation.
func (node *GeospatialNode) Start() {
	// Start the network listener
	listener, err := net.Listen("tcp", node.NetworkAddress)
	if err != nil {
		log.Fatalf("Failed to start node: %v", err)
	}
	defer listener.Close()
	log.Printf("Node %s started at %s", node.ID, node.NetworkAddress)

	// Handle incoming connections
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Failed to accept connection: %v", err)
			continue
		}
		node.DataChannel = conn
		go node.handleConnection(conn)
	}
}

// Stop gracefully stops the node's operation.
func (node *GeospatialNode) Stop() {
	if node.DataChannel != nil {
		node.DataChannel.Close()
	}
	log.Printf("Node %s stopped", node.ID)
}

// handleConnection handles incoming data connections.
func (node *GeospatialNode) handleConnection(conn net.Conn) {
	defer conn.Close()

	buffer := make([]byte, 1024)
	for {
		n, err := conn.Read(buffer)
		if err != nil {
			if err != net.EOF {
				log.Printf("Error reading data: %v", err)
			}
			break
		}

		data := buffer[:n]
		log.Printf("Node %s received data: %s", node.ID, string(data))
		var geoData map[string]interface{}
		if err := json.Unmarshal(data, &geoData); err != nil {
			log.Printf("Error unmarshalling data: %v", err)
			continue
		}

		// Example geospatial processing: validate geospatial coordinates
		if err := node.validateAndStoreGeoData(geoData); err != nil {
			log.Printf("Error processing geospatial data: %v", err)
		}
	}
}

// validateAndStoreGeoData performs basic validation and stores the geospatial data.
func (node *GeospatialNode) validateAndStoreGeoData(geoData map[string]interface{}) error {
	lat, ok := geoData["latitude"].(float64)
	if !ok || lat < -90 || lat > 90 {
		return fmt.Errorf("invalid latitude value: %v", geoData["latitude"])
	}
	lng, ok := geoData["longitude"].(float64)
	if !ok || lng < -180 || lng > 180 {
		return fmt.Errorf("invalid longitude value: %v", geoData["longitude"])
	}

	// Use s2 library for geospatial validation
	point := s2.PointFromLatLng(s2.LatLngFromDegrees(lat, lng))
	if point.IsValid() {
		key := fmt.Sprintf("geo_%d", time.Now().UnixNano())
		data, err := json.Marshal(geoData)
		if err != nil {
			return fmt.Errorf("error marshalling geo data: %v", err)
		}
		return node.Storage.StoreData(key, data)
	}
	return fmt.Errorf("invalid geospatial point")
}

// main function initializes and starts the geospatial node.
func main() {
	storage := &FileSystemStorage{BasePath: "./data"}
	node := NewGeospatialNode("geo-node-1", ":8081", storage)

	go node.Start()

	// Handle graceful shutdown
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	<-sigs
	node.Stop()
}
