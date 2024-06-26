package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"
)

// ConsensusSpecificNode represents a node dedicated to a specific consensus algorithm.
type ConsensusSpecificNode struct {
	ID             string
	ConsensusType  string
	NetworkAddress string
	DataChannel    net.Conn
	Storage        Storage
	Config         NodeConfig
}

// NodeConfig holds configuration details for the node.
type NodeConfig struct {
	EncryptionKey string
}

// Storage interface defines the methods required for the node's storage system.
type Storage interface {
	StoreData(data []byte) error
	RetrieveData(key string) ([]byte, error)
}

// FileSystemStorage is a simple file system based storage.
type FileSystemStorage struct {
	BasePath string
}

// StoreData stores data in the file system.
func (fs *FileSystemStorage) StoreData(data []byte) error {
	fileName := fmt.Sprintf("%s/%d.dat", fs.BasePath, time.Now().UnixNano())
	file, err := os.Create(fileName)
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

// NewConsensusSpecificNode creates a new consensus-specific node.
func NewConsensusSpecificNode(id, consensusType, address string, storage Storage, config NodeConfig) *ConsensusSpecificNode {
	return &ConsensusSpecificNode{
		ID:             id,
		ConsensusType:  consensusType,
		NetworkAddress: address,
		Storage:        storage,
		Config:         config,
	}
}

// EncryptData encrypts data using AES encryption.
func (node *ConsensusSpecificNode) EncryptData(data []byte) ([]byte, error) {
	key, err := hex.DecodeString(node.Config.EncryptionKey)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return ciphertext, nil
}

// DecryptData decrypts data using AES encryption.
func (node *ConsensusSpecificNode) DecryptData(data []byte) ([]byte, error) {
	key, err := hex.DecodeString(node.Config.EncryptionKey)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// Start initiates the node's operation.
func (node *ConsensusSpecificNode) Start() {
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
func (node *ConsensusSpecificNode) Stop() {
	if node.DataChannel != nil {
		node.DataChannel.Close()
	}
	log.Printf("Node %s stopped", node.ID)
}

// handleConnection handles incoming data connections.
func (node *ConsensusSpecificNode) handleConnection(conn net.Conn) {
	defer conn.Close()

	buffer := make([]byte, 1024)
	for {
		n, err := conn.Read(buffer)
		if err != nil {
			if err != io.EOF {
				log.Printf("Error reading data: %v", err)
			}
			break
		}

		data := buffer[:n]
		log.Printf("Node %s received data", node.ID)

		decryptedData, err := node.DecryptData(data)
		if err != nil {
			log.Printf("Error decrypting data: %v", err)
			continue
		}

		log.Printf("Node %s decrypted data: %s", node.ID, string(decryptedData))
		err = node.Storage.StoreData(decryptedData)
		if err != nil {
			log.Printf("Error storing data: %v", err)
		}
	}
}

// loadConfig loads the node configuration from a file.
func loadConfig(filePath string) (NodeConfig, error) {
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		return NodeConfig{}, err
	}

	config := NodeConfig{}
	err = json.Unmarshal(data, &config)
	if err != nil {
		return NodeConfig{}, err
	}

	return config, nil
}

// main function initializes and starts the consensus-specific node.
func main() {
	config, err := loadConfig("./config.json")
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	storage := &FileSystemStorage{BasePath: "./data"}
	node := NewConsensusSpecificNode("node-1", "PoW", ":8080", storage, config)

	go node.Start()

	// Handle graceful shutdown
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	<-sigs

	node.Stop()
}
