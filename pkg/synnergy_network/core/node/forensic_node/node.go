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
	"github.com/golang/protobuf/proto"
	"golang.org/x/crypto/scrypt"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
)

// ForensicNode represents a node dedicated to forensic analysis on the blockchain.
type ForensicNode struct {
	ID             string
	NetworkAddress string
	DataChannel    net.Conn
	Storage        Storage
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

// NewForensicNode creates a new forensic node.
func NewForensicNode(id, address string, storage Storage) *ForensicNode {
	return &ForensicNode{
		ID:             id,
		NetworkAddress: address,
		Storage:        storage,
	}
}

// Start initiates the node's operation.
func (node *ForensicNode) Start() {
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
func (node *ForensicNode) Stop() {
	if node.DataChannel != nil {
		node.DataChannel.Close()
	}
	log.Printf("Node %s stopped", node.ID)
}

// handleConnection handles incoming data connections.
func (node *ForensicNode) handleConnection(conn net.Conn) {
	defer conn.Close()

	buffer := make([]byte, 4096)
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
		node.Storage.StoreData(data)

		// Perform forensic analysis on the received data
		node.performForensicAnalysis(data)
	}
}

// performForensicAnalysis performs forensic analysis on the received data.
func (node *ForensicNode) performForensicAnalysis(data []byte) {
	// Placeholder for actual forensic analysis logic
	log.Printf("Performing forensic analysis on data: %s", string(data))

	// Simulating analysis delay
	time.Sleep(2 * time.Second)

	log.Printf("Forensic analysis completed for data: %s", string(data))
}

// EncryptData encrypts data using AES encryption.
func EncryptData(data, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
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

// DecryptData decrypts data using AES encryption.
func DecryptData(ciphertext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
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

// GenerateKey generates a secure key using scrypt.
func GenerateKey(password, salt []byte) ([]byte, error) {
	dk, err := scrypt.Key(password, salt, 16384, 8, 1, 32)
	if err != nil {
		return nil, err
	}
	return dk, nil
}

// main function initializes and starts the forensic node.
func main() {
	storage := &FileSystemStorage{BasePath: "./data"}
	node := NewForensicNode("forensic-node-1", ":8080", storage)

	go node.Start()

	// Handle graceful shutdown
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	<-sigs

	node.Stop()
}
