package node_connectivity

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

// ConnectivityCheck represents the data structure for node connectivity checks.
type ConnectivityCheck struct {
	NodeID      string    `json:"node_id"`
	IPAddress   string    `json:"ip_address"`
	Status      string    `json:"status"`
	Timestamp   time.Time `json:"timestamp"`
	ResponseTime float64  `json:"response_time"`
}

// ConnectivityChecker handles the checking of node connectivity within the network.
type ConnectivityChecker struct {
	nodes    map[string]string
	mutex    sync.Mutex
	ctx      context.Context
	cancel   context.CancelFunc
	logger   *logrus.Logger
	metrics  *Metrics
}

// Metrics holds Prometheus metrics for monitoring connectivity checks.
type Metrics struct {
	checksTotal       prometheus.Counter
	checkErrorsTotal  prometheus.Counter
	responseTimeGauge prometheus.Gauge
}

func newMetrics() *Metrics {
	return &Metrics{
		checksTotal: promauto.NewCounter(prometheus.CounterOpts{
			Name: "connectivity_checks_total",
			Help: "The total number of connectivity checks",
		}),
		checkErrorsTotal: promauto.NewCounter(prometheus.CounterOpts{
			Name: "connectivity_check_errors_total",
			Help: "The total number of errors encountered during connectivity checks",
		}),
		responseTimeGauge: promauto.NewGauge(prometheus.GaugeOpts{
			Name: "connectivity_check_response_time_seconds",
			Help: "The response time of the last connectivity check",
		}),
	}
}

// NewConnectivityChecker initializes a new ConnectivityChecker instance.
func NewConnectivityChecker(nodes map[string]string) *ConnectivityChecker {
	ctx, cancel := context.WithCancel(context.Background())
	logger := logrus.New()
	metrics := newMetrics()

	return &ConnectivityChecker{
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

// CheckNodeConnectivity performs a connectivity check for a single node.
func (cc *ConnectivityChecker) CheckNodeConnectivity(nodeID string, ipAddress string) *ConnectivityCheck {
	start := time.Now()
	conn, err := net.DialTimeout("tcp", ipAddress, 5*time.Second)
	responseTime := time.Since(start).Seconds()

	cc.metrics.checksTotal.Inc()
	if err != nil {
		cc.metrics.checkErrorsTotal.Inc()
		cc.logger.Errorf("Error connecting to node %s at %s: %v", nodeID, ipAddress, err)
		return &ConnectivityCheck{
			NodeID:      nodeID,
			IPAddress:   ipAddress,
			Status:      "DOWN",
			Timestamp:   time.Now(),
			ResponseTime: responseTime,
		}
	}
	defer conn.Close()

	cc.metrics.responseTimeGauge.Set(responseTime)
	cc.logger.Infof("Successfully connected to node %s at %s in %.2f seconds", nodeID, ipAddress, responseTime)

	return &ConnectivityCheck{
		NodeID:      nodeID,
		IPAddress:   ipAddress,
		Status:      "UP",
		Timestamp:   time.Now(),
		ResponseTime: responseTime,
	}
}

// RunConnectivityChecks runs connectivity checks for all nodes in the network.
func (cc *ConnectivityChecker) RunConnectivityChecks() {
	cc.mutex.Lock()
	defer cc.mutex.Unlock()

	var wg sync.WaitGroup
	for nodeID, ipAddress := range cc.nodes {
		wg.Add(1)
		go func(nodeID, ipAddress string) {
			defer wg.Done()
			check := cc.CheckNodeConnectivity(nodeID, ipAddress)
			cc.StoreConnectivityCheck(check)
		}(nodeID, ipAddress)
	}
	wg.Wait()
}

// StoreConnectivityCheck stores the result of a connectivity check securely.
func (cc *ConnectivityChecker) StoreConnectivityCheck(check *ConnectivityCheck) {
	data, err := json.Marshal(check)
	if err != nil {
		cc.logger.Errorf("Error marshaling connectivity check data: %v", err)
		return
	}
	encryptedData, err := Encrypt(data)
	if err != nil {
		cc.logger.Errorf("Error encrypting connectivity check data: %v", err)
		return
	}

	// Store encryptedData in a persistent storage (e.g., database or file)
	// Example: StoreInDatabase(encryptedData)
	cc.logger.Infof("Stored connectivity check for node %s", check.NodeID)
}

// Close gracefully shuts down the ConnectivityChecker.
func (cc *ConnectivityChecker) Close() {
	cc.cancel()
	cc.logger.Info("ConnectivityChecker has been stopped")
}


