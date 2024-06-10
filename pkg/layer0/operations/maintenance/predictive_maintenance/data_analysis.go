package predictive_maintenance

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/csv"
	"errors"
	"fmt"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/scrypt"
	"io"
	"log"
	"os"
	"strconv"
	"time"
)

// Node represents a blockchain node with operational data
type Node struct {
	ID             string
	IPAddress      string
	Role           string
	LastHeartbeat  time.Time
	IsHealthy      bool
	PublicKey      string
	PerformanceData []PerformanceMetric
}

// PerformanceMetric represents a single performance data point for a node
type PerformanceMetric struct {
	Timestamp   time.Time
	CPUUsage    float64
	MemoryUsage float64
	DiskUsage   float64
}

// DataAnalysis provides methods for predictive maintenance using data analysis
type DataAnalysis struct {
	Nodes []Node
}

// NewDataAnalysis initializes a new DataAnalysis instance
func NewDataAnalysis(nodes []Node) *DataAnalysis {
	return &DataAnalysis{
		Nodes: nodes,
	}
}

// EncryptData encrypts data using AES with Argon2 key derivation
func EncryptData(plainText, password string) (string, error) {
	salt := make([]byte, 16)
	_, err := rand.Read(salt)
	if err != nil {
		return "", err
	}

	key := argon2.IDKey([]byte(password), salt, 1, 64*1024, 4, 32)
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	_, err = io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return "", err
	}

	cipherText := gcm.Seal(nonce, nonce, []byte(plainText), nil)
	return base64.StdEncoding.EncodeToString(cipherText), nil
}

// DecryptData decrypts data using AES with Argon2 key derivation
func DecryptData(cipherText, password string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(cipherText)
	if err != nil {
		return "", err
	}

	salt := data[:16]
	key := argon2.IDKey([]byte(password), salt, 1, 64*1024, 4, 32)
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return "", errors.New("ciphertext too short")
	}

	nonce, cipherText := data[:nonceSize], data[nonceSize:]
	plainText, err := gcm.Open(nil, nonce, cipherText, nil)
	if err != nil {
		return "", err
	}

	return string(plainText), nil
}

// CollectData collects operational data from nodes and saves it to a CSV file
func (da *DataAnalysis) CollectData(filePath string) error {
	file, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	headers := []string{"NodeID", "Timestamp", "CPUUsage", "MemoryUsage", "DiskUsage"}
	if err := writer.Write(headers); err != nil {
		return err
	}

	for _, node := range da.Nodes {
		for _, metric := range node.PerformanceData {
			record := []string{
				node.ID,
				metric.Timestamp.Format(time.RFC3339),
				strconv.FormatFloat(metric.CPUUsage, 'f', 2, 64),
				strconv.FormatFloat(metric.MemoryUsage, 'f', 2, 64),
				strconv.FormatFloat(metric.DiskUsage, 'f', 2, 64),
			}
			if err := writer.Write(record); err != nil {
				return err
			}
		}
	}
	return nil
}

// LoadData loads operational data from a CSV file into the nodes
func (da *DataAnalysis) LoadData(filePath string) error {
	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	reader := csv.NewReader(file)
	records, err := reader.ReadAll()
	if err != nil {
		return err
	}

	for i, record := range records {
		if i == 0 {
			continue
		}
		nodeID := record[0]
		timestamp, _ := time.Parse(time.RFC3339, record[1])
		cpuUsage, _ := strconv.ParseFloat(record[2], 64)
		memoryUsage, _ := strconv.ParseFloat(record[3], 64)
		diskUsage, _ := strconv.ParseFloat(record[4], 64)

		metric := PerformanceMetric{
			Timestamp:   timestamp,
			CPUUsage:    cpuUsage,
			MemoryUsage: memoryUsage,
			DiskUsage:   diskUsage,
		}

		for j := range da.Nodes {
			if da.Nodes[j].ID == nodeID {
				da.Nodes[j].PerformanceData = append(da.Nodes[j].PerformanceData, metric)
			}
		}
	}
	return nil
}

// AnalyzePerformanceData performs data analysis to predict potential failures
func (da *DataAnalysis) AnalyzePerformanceData() {
	for _, node := range da.Nodes {
		for _, metric := range node.PerformanceData {
			if metric.CPUUsage > 80.0 || metric.MemoryUsage > 80.0 || metric.DiskUsage > 80.0 {
				log.Printf("Warning: Node %s is experiencing high resource usage at %s", node.ID, metric.Timestamp)
			}
		}
	}
}

// PredictFailures uses historical data to predict potential node failures
func (da *DataAnalysis) PredictFailures() {
	for _, node := range da.Nodes {
		highUsageCount := 0
		for _, metric := range node.PerformanceData {
			if metric.CPUUsage > 80.0 || metric.MemoryUsage > 80.0 || metric.DiskUsage > 80.0 {
				highUsageCount++
			}
		}
		if highUsageCount > len(node.PerformanceData)/2 {
			log.Printf("Predicting potential failure for node %s based on historical performance data", node.ID)
		}
	}
}

// Argon2Mining performs mining using Argon2 for proof of work
func Argon2Mining(input string) string {
	salt := []byte("somesalt")
	hash := argon2.IDKey([]byte(input), salt, 1, 64*1024, 4, 32)
	return base64.StdEncoding.EncodeToString(hash)
}

// ScryptMining performs mining using Scrypt for proof of work
func ScryptMining(input string) (string, error) {
	salt := []byte("somesalt")
	hash, err := scrypt.Key([]byte(input), salt, 16384, 8, 1, 32)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(hash), nil
}

func main() {
	// Example usage of the DataAnalysis system
	nodes := []Node{
		{ID: "node1", IPAddress: "192.168.1.1", Role: "validator", PublicKey: "publicKey1"},
		{ID: "node2", IPAddress: "192.168.1.2", Role: "super", PublicKey: "publicKey2"},
	}

	dataAnalysis := NewDataAnalysis(nodes)

	// Collect data from nodes
	filePath := "performance_data.csv"
	if err := dataAnalysis.CollectData(filePath); err != nil {
		log.Fatalf("Failed to collect data: %v", err)
	}

	// Load data into nodes
	if err := dataAnalysis.LoadData(filePath); err != nil {
		log.Fatalf("Failed to load data: %v", err)
	}

	// Analyze performance data
	dataAnalysis.AnalyzePerformanceData()

	// Predict potential failures
	dataAnalysis.PredictFailures()

	// Encrypt and decrypt data example
	password := "securepassword"
	plainText := "Sensitive blockchain data"
	encrypted, err := EncryptData(plainText, password)
	if err != nil {
		log.Fatalf("Failed to encrypt data: %v", err)
	}
	log.Printf("Encrypted data: %s", encrypted)

	decrypted, err := DecryptData(encrypted, password)
	if err != nil {
		log.Fatalf("Failed to decrypt data: %v", err)
	}
	log.Printf("Decrypted data: %s", decrypted)

	// Mining examples
	argon2Hash := Argon2Mining("example data")
	log.Printf("Argon2 hash: %s", argon2Hash)

	scryptHash, err := ScryptMining("example data")
	if err != nil {
		log.Fatalf("Failed to generate Scrypt hash: %v", err)
	}
	log.Printf("Scrypt hash: %s", scryptHash)
}
