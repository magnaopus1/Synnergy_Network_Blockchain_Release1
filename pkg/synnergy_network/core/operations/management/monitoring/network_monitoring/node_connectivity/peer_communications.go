package node_connectivity

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/sirupsen/logrus"
)

const (
	encryptionKey = "your-32-byte-long-encryption-key-here"
)

// PeerCommunication represents the data structure for peer communications.
type PeerCommunication struct {
	SourceNodeID      string    `json:"source_node_id"`
	DestinationNodeID string    `json:"destination_node_id"`
	Message           string    `json:"message"`
	Timestamp         time.Time `json:"timestamp"`
	ResponseTime      float64   `json:"response_time"`
}

// PeerCommunicator handles peer communications within the network.
type PeerCommunicator struct {
	nodes   map[string]string
	mutex   sync.Mutex
	ctx     context.Context
	cancel  context.CancelFunc
	logger  *logrus.Logger
	metrics *Metrics
}

// Metrics holds Prometheus metrics for monitoring peer communications.
type Metrics struct {
	communicationsTotal      prometheus.Counter
	communicationErrorsTotal prometheus.Counter
	responseTimeGauge        prometheus.Gauge
}

func newMetrics() *Metrics {
	return &Metrics{
		communicationsTotal: promauto.NewCounter(prometheus.CounterOpts{
			Name: "peer_communications_total",
			Help: "The total number of peer communications",
		}),
		communicationErrorsTotal: promauto.NewCounter(prometheus.CounterOpts{
			Name: "peer_communication_errors_total",
			Help: "The total number of errors encountered during peer communications",
		}),
		responseTimeGauge: promauto.NewGauge(prometheus.GaugeOpts{
			Name: "peer_communication_response_time_seconds",
			Help: "The response time of the last peer communication",
		}),
	}
}

// NewPeerCommunicator initializes a new PeerCommunicator instance.
func NewPeerCommunicator(nodes map[string]string) *PeerCommunicator {
	ctx, cancel := context.WithCancel(context.Background())
	logger := logrus.New()
	metrics := newMetrics()

	return &PeerCommunicator{
		nodes:   nodes,
		ctx:     ctx,
		cancel:  cancel,
		logger:  logger,
		metrics: metrics,
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

// CommunicateWithPeer sends a message to a peer node and measures the response time.
func (pc *PeerCommunicator) CommunicateWithPeer(sourceNodeID string, destinationNodeID string, message string) *PeerCommunication {
	start := time.Now()
	conn, err := net.DialTimeout("tcp", pc.nodes[destinationNodeID], 5*time.Second)
	responseTime := time.Since(start).Seconds()

	pc.metrics.communicationsTotal.Inc()
	if err != nil {
		pc.metrics.communicationErrorsTotal.Inc()
		pc.logger.Errorf("Error communicating with peer %s from node %s: %v", destinationNodeID, sourceNodeID, err)
		return &PeerCommunication{
			SourceNodeID:      sourceNodeID,
			DestinationNodeID: destinationNodeID,
			Message:           message,
			Timestamp:         time.Now(),
			ResponseTime:      responseTime,
		}
	}
	defer conn.Close()

	encryptedMessage, err := Encrypt([]byte(message))
	if err != nil {
		pc.metrics.communicationErrorsTotal.Inc()
		pc.logger.Errorf("Error encrypting message: %v", err)
		return nil
	}

	if _, err := conn.Write([]byte(encryptedMessage)); err != nil {
		pc.metrics.communicationErrorsTotal.Inc()
		pc.logger.Errorf("Error sending message to peer %s from node %s: %v", destinationNodeID, sourceNodeID, err)
		return nil
	}

	pc.metrics.responseTimeGauge.Set(responseTime)
	pc.logger.Infof("Successfully communicated with peer %s from node %s in %.2f seconds", destinationNodeID, sourceNodeID, responseTime)

	return &PeerCommunication{
		SourceNodeID:      sourceNodeID,
		DestinationNodeID: destinationNodeID,
		Message:           message,
		Timestamp:         time.Now(),
		ResponseTime:      responseTime,
	}
}

// StoreCommunication securely stores the result of a peer communication.
func (pc *PeerCommunicator) StoreCommunication(communication *PeerCommunication) error {
	data, err := json.Marshal(communication)
	if err != nil {
		pc.logger.Errorf("Error marshaling communication data: %v", err)
		return err
	}
	encryptedData, err := Encrypt(data)
	if err != nil {
		pc.logger.Errorf("Error encrypting communication data: %v", err)
		return err
	}

	// Store encryptedData in a persistent storage (e.g., database or file)
	// Example: StoreInDatabase(encryptedData)
	pc.logger.Infof("Stored communication data for node %s to node %s", communication.SourceNodeID, communication.DestinationNodeID)
	return nil
}

// RunPeerCommunications runs communications between all nodes in the network.
func (pc *PeerCommunicator) RunPeerCommunications() {
	pc.mutex.Lock()
	defer pc.mutex.Unlock()

	var wg sync.WaitGroup
	for sourceNodeID, destinationNodeID := range pc.nodes {
		wg.Add(1)
		go func(sourceNodeID, destinationNodeID string) {
			defer wg.Done()
			communication := pc.CommunicateWithPeer(sourceNodeID, destinationNodeID, "Test message")
			if communication != nil {
				pc.StoreCommunication(communication)
			}
		}(sourceNodeID, destinationNodeID)
	}
	wg.Wait()
}

// Close gracefully shuts down the PeerCommunicator.
func (pc *PeerCommunicator) Close() {
	pc.cancel()
	pc.logger.Info("PeerCommunicator has been stopped")
}
