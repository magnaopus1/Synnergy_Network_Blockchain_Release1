package dataintegration

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"io"
	"log"

	"github.com/synthron_blockchain_final/pkg/layer1/holographic_data_visualization/rendering"
	"github.com/gorilla/websocket"
)

// RealTimeDataConfig contains configuration for real-time data visualization.
type RealTimeDataConfig struct {
	WebSocketURL string `json:"web_socket_url"`
	VisualizationConfig
}

// RealTimeDataHandler handles the streaming and visualization of real-time blockchain data.
type RealTimeDataHandler struct {
	Config *RealTimeDataConfig
	Conn   *websocket.Conn
}

// NewRealTimeDataHandler initializes a handler for real-time data visualization.
func NewRealTimeDataHandler(config *RealTimeDataConfig) (*RealTimeDataHandler, error) {
	conn, _, err := websocket.DefaultDialer.Dial(config.WebSocketURL, nil)
	if err != nil {
		return nil, err
	}
	return &RealTimeDataHandler{
		Config: config,
		Conn:   conn,
	}, nil
}

// StreamData starts the data streaming and visualization process.
func (handler *RealTimeDataHandler) StreamData() error {
	for {
		_, message, err := handler.Conn.ReadMessage()
		if err != nil {
			log.Printf("Error reading message: %v", err)
			continue
		}
		var data HistoricalData
		if err := json.Unmarshal(message, &data); err != nil {
			log.Printf("Error unmarshalling data: %v", err)
			continue
		}

		if err := Generate3DVisualization(&data, &handler.Config.VisualizationConfig); err != nil {
			log.Printf("Error generating visualization: %v", err)
			continue
		}
	}
}

// Generate3DVisualization generates a 3D holographic visualization from the real-time data.
func Generate3DVisualization(data *HistoricalData, config *VisualizationConfig) error {
	// Utilize the rendering package to create a 3D holographic visualization
	err := rendering.Render3DHologram(data, config)
	if err != nil {
		return err
	}
	log.Println("Successfully generated holographic visualization of real-time data.")
	return nil
}
