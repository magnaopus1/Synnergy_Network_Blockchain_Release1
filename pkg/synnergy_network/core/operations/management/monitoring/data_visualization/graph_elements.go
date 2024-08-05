package data_visualization

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/crypto/scrypt"
	"io"
	"math"
	"os"
	"time"

	"go.uber.org/zap"
)

// GraphElement represents a single element in a data visualization graph.
type GraphElement struct {
	ID        string                 `json:"id"`
	Type      string                 `json:"type"`
	Data      map[string]interface{} `json:"data"`
	Metadata  map[string]interface{} `json:"metadata"`
	Timestamp time.Time              `json:"timestamp"`
}

// GraphManager manages a collection of graph elements for data visualization.
type GraphManager struct {
	elements []GraphElement
	logger   *zap.Logger
}

// NewGraphManager creates a new GraphManager.
func NewGraphManager(logger *zap.Logger) *GraphManager {
	return &GraphManager{
		elements: make([]GraphElement, 0),
		logger:   logger,
	}
}

// AddElement adds a new graph element to the manager.
func (gm *GraphManager) AddElement(element GraphElement) {
	element.Timestamp = time.Now()
	gm.elements = append(gm.elements, element)
	gm.logger.Info("Added new graph element", zap.String("id", element.ID), zap.String("type", element.Type))
}

// GetElement retrieves a graph element by its ID.
func (gm *GraphManager) GetElement(id string) (*GraphElement, error) {
	for _, element := range gm.elements {
		if element.ID == id {
			return &element, nil
		}
	}
	return nil, errors.New("element not found")
}

// RemoveElement removes a graph element by its ID.
func (gm *GraphManager) RemoveElement(id string) error {
	for i, element := range gm.elements {
		if element.ID == id {
			gm.elements = append(gm.elements[:i], gm.elements[i+1:]...)
			gm.logger.Info("Removed graph element", zap.String("id", id))
			return nil
		}
	}
	return errors.New("element not found")
}

// ListElements lists all graph elements.
func (gm *GraphManager) ListElements() []GraphElement {
	return gm.elements
}

// EncryptGraphElements encrypts the graph elements data.
func (gm *GraphManager) EncryptGraphElements(passphrase string) ([]byte, error) {
	gm.logger.Info("Encrypting graph elements")
	data, err := json.Marshal(gm.elements)
	if err != nil {
		return nil, err
	}

	salt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}

	key, err := scrypt.Key([]byte(passphrase), salt, 32768, 8, 1, 32)
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
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return append(salt, ciphertext...), nil
}

// DecryptGraphElements decrypts the graph elements data.
func (gm *GraphManager) DecryptGraphElements(encryptedData []byte, passphrase string) error {
	gm.logger.Info("Decrypting graph elements")
	if len(encryptedData) < 16 {
		return errors.New("invalid data")
	}

	salt := encryptedData[:16]
	encryptedData = encryptedData[16:]

	key, err := scrypt.Key([]byte(passphrase), salt, 32768, 8, 1, 32)
	if err != nil {
		return err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	nonceSize := gcm.NonceSize()
	if len(encryptedData) < nonceSize {
		return errors.New("invalid data")
	}

	nonce, ciphertext := encryptedData[:nonceSize], encryptedData[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return err
	}

	var elements []GraphElement
	err = json.Unmarshal(plaintext, &elements)
	if err != nil {
		return err
	}

	gm.elements = elements
	return nil
}

// SaveElementsToFile saves graph elements to a specified file.
func (gm *GraphManager) SaveElementsToFile(filename string) error {
	gm.logger.Info("Saving graph elements to file", zap.String("filename", filename))
	data, err := json.Marshal(gm.elements)
	if err != nil {
		return err
	}

	return os.WriteFile(filename, data, 0644)
}

// LoadElementsFromFile loads graph elements from a specified file.
func (gm *GraphManager) LoadElementsFromFile(filename string) error {
	gm.logger.Info("Loading graph elements from file", zap.String("filename", filename))
	data, err := os.ReadFile(filename)
	if err != nil {
		return err
	}

	var elements []GraphElement
	err = json.Unmarshal(data, &elements)
	if err != nil {
		return err
	}

	gm.elements = elements
	return nil
}

// GenerateGraphStatistics generates basic statistics for the graph elements.
func (gm *GraphManager) GenerateGraphStatistics() (map[string]float64, error) {
	gm.logger.Info("Generating graph statistics")
	stats := make(map[string]float64)
	count := float64(len(gm.elements))
	if count == 0 {
		return stats, nil
	}

	sum := 0.0
	for _, element := range gm.elements {
		value, ok := element.Data["value"].(float64)
		if ok {
			sum += value
		}
	}

	stats["count"] = count
	stats["sum"] = sum
	stats["mean"] = sum / count
	stats["variance"] = gm.calculateVariance(sum, count)
	stats["stddev"] = math.Sqrt(stats["variance"])

	return stats, nil
}

// calculateVariance calculates the variance of the graph elements.
func (gm *GraphManager) calculateVariance(sum, count float64) float64 {
	mean := sum / count
	variance := 0.0
	for _, element := range gm.elements {
		value, ok := element.Data["value"].(float64)
		if ok {
			variance += math.Pow(value-mean, 2)
		}
	}
	return variance / count
}

