package geographical_visualization

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/gorilla/websocket"
)

const (
	encryptionKey = "your-32-byte-long-encryption-key-here"
)

var (
	upgrader = websocket.Upgrader{
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
	}
	mapDataRequests = promauto.NewCounter(prometheus.CounterOpts{
		Name: "map_data_requests_total",
		Help: "The total number of requests for map data",
	})
	mapDataErrors = promauto.NewCounter(prometheus.CounterOpts{
		Name: "map_data_errors_total",
		Help: "The total number of errors encountered in map data processing",
	})
)

type MapData struct {
	NodeID    string    `json:"node_id"`
	Location  string    `json:"location"`
	Lat       float64   `json:"lat"`
	Lon       float64   `json:"lon"`
	Timestamp time.Time `json:"timestamp"`
}

type VisualizationTools struct {
	db     map[string]string
	ctx    context.Context
	cancel context.CancelFunc
}

func NewVisualizationTools() *VisualizationTools {
	ctx, cancel := context.WithCancel(context.Background())
	return &VisualizationTools{
		db:     make(map[string]string),
		ctx:    ctx,
		cancel: cancel,
	}
}

// Encrypt encrypts data using AES.
func Encrypt(data []byte) (string, error) {
	block, err := aes.NewCipher([]byte(encryptionKey))
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return hex.EncodeToString(ciphertext), nil
}

// Decrypt decrypts data using AES.
func Decrypt(encryptedData string) ([]byte, error) {
	data, err := hex.DecodeString(encryptedData)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher([]byte(encryptionKey))
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

func (vt *VisualizationTools) StoreMapData(data *MapData) error {
	encryptedData, err := Encrypt([]byte(data.Location))
	if err != nil {
		mapDataErrors.Inc()
		return err
	}
	vt.db[data.NodeID] = encryptedData
	mapDataRequests.Inc()
	return nil
}

func (vt *VisualizationTools) FetchMapData(nodeID string) (*MapData, error) {
	encryptedData, exists := vt.db[nodeID]
	if !exists {
		mapDataErrors.Inc()
		return nil, errors.New("data not found")
	}
	decryptedData, err := Decrypt(encryptedData)
	if err != nil {
		mapDataErrors.Inc()
		return nil, err
	}
	mapDataRequests.Inc()
	return &MapData{
		NodeID:   nodeID,
		Location: string(decryptedData),
	}, nil
}

func (vt *VisualizationTools) HandleWebSocketConnection(ws *websocket.Conn) {
	defer ws.Close()
	for {
		var data MapData
		err := ws.ReadJSON(&data)
		if err != nil {
			log.Printf("Error reading JSON: %v", err)
			break
		}
		err = vt.StoreMapData(&data)
		if err != nil {
			log.Printf("Error storing map data: %v", err)
			break
		}
		err = ws.WriteJSON(data)
		if err != nil {
			log.Printf("Error writing JSON: %v", err)
			break
		}
	}
}

func (vt *VisualizationTools) Close() {
	vt.cancel()
}


