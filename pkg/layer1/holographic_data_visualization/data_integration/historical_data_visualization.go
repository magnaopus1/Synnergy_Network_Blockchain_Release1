package historicaldatavisualization

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"io"
	"log"

	"github.com/synthron_blockchain_final/pkg/layer1/holographic_data_visualization/rendering"
)

// HistoricalData represents the structured format of blockchain data for visualization.
type HistoricalData struct {
	Blocks      []BlockData `json:"blocks"`
	Transactions []TransactionData `json:"transactions"`
}

// BlockData structures the necessary block attributes for visualization.
type BlockData struct {
	BlockID        string `json:"block_id"`
	Timestamp      string `json:"timestamp"`
	TransactionIDs []string `json:"transaction_ids"`
}

// TransactionData structures the necessary transaction attributes for visualization.
type TransactionData struct {
	TransactionID string `json:"transaction_id"`
	Amount        float64 `json:"amount"`
	Sender        string  `json:"sender"`
	Receiver      string  `json:"receiver"`
}

// VisualizationConfig configures parameters for the holographic display.
type VisualizationConfig struct {
	DisplaySize     string `json:"display_size"`
	ColorScheme     string `json:"color_scheme"`
	RefreshInterval int    `json:"refresh_interval"` // in seconds
}

// LoadHistoricalData decrypts and unmarshals the historical blockchain data for visualization.
func LoadHistoricalData(encryptedData []byte, key []byte) (*HistoricalData, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(encryptedData) < nonceSize {
		return nil, io.ErrUnexpectedEOF
	}

	nonce, ciphertext := encryptedData[:nonceSize], encryptedData[nonceSize:]
	decryptedData, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	var data HistoricalData
	err = json.Unmarshal(decryptedData, &data)
	if err != nil {
		return nil, err
	}
	return &data, nil
}

// Generate3DVisualization generates a 3D holographic visualization from the historical data.
func Generate3DVisualization(data *HistoricalData, config *VisualizationConfig) error {
	// Utilize the rendering package to create a 3D holographic visualization
	err := rendering.Render3DHologram(data, config)
	if err != nil {
		return err
	}
	log.Println("Successfully generated holographic visualization of historical data.")
	return nil
}
