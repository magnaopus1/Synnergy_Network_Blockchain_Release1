package holographicvisualization

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"io"
	"log"

	"github.com/synthron_blockchain_final/pkg/layer1/holographic_data_visualization/rendering"
)

// VisualizationConfig holds the settings for the visualization such as dimensions and color schemes.
type VisualizationConfig struct {
	Width       int    `json:"width"`
	Height      int    `json:"height"`
	ColorScheme string `json:"color_scheme"`
}

// HolographicVisualizer provides methods to visualize data in a holographic display.
type HolographicVisualizer struct {
	Config VisualizationConfig
}

// NewHolographicVisualizer creates a new holographic visualizer with specified configuration.
func NewHolographicVisualizer(config VisualizationConfig) *HolographicVisualizer {
	return &HolographicVisualizer{
		Config: config,
	}
}

// VisualizeData takes raw blockchain data, processes it, and renders it using the configured visual settings.
func (hv *HolographicVisualizer) VisualizeData(rawData []byte) error {
	decryptedData, err := hv.decryptData(rawData)
	if err != nil {
		return err
	}

	var data BlockchainData
	if err := json.Unmarshal(decryptedData, &data); err != nil {
		return err
	}

	return rendering.Render3DHologram(data, hv.Config)
}

// decryptData handles the decryption of raw data using AES-256.
func (hv *HolographicVisualizer) decryptData(data []byte) ([]byte, error) {
	key := []byte("the-key-has-to-be-32-bytes-long!")
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
		return nil, io.ErrUnexpectedEOF
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// BlockchainData structures the expected form of data from the blockchain.
type BlockchainData struct {
	Transactions []Transaction `json:"transactions"`
	Blocks       []Block       `json:"blocks"`
}

// Transaction models a blockchain transaction.
type Transaction struct {
	ID     string `json:"id"`
	Amount string `json:"amount"`
}

// Block represents a block in the blockchain.
type Block struct {
	Hash         string         `json:"hash"`
	Transactions []Transaction  `json:"transactions"`
	TimeStamp    string         `json:"time_stamp"`
}
