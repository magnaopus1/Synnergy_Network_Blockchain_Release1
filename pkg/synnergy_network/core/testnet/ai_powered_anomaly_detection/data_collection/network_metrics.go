package data_collection

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"math/rand"
	"net"
	"os"
	"time"

	"golang.org/x/crypto/argon2"
)

// Metric represents a single network metric
type Metric struct {
	Timestamp time.Time `json:"timestamp"`
	Type      string    `json:"type"`
	Value     float64   `json:"value"`
}

// NetworkMetricsCollector collects various network metrics
type NetworkMetricsCollector struct {
	MetricsFilePath string
	EncryptionKey   []byte
}

// NewNetworkMetricsCollector creates a new NetworkMetricsCollector
func NewNetworkMetricsCollector(metricsFilePath string, encryptionKey []byte) *NetworkMetricsCollector {
	return &NetworkMetricsCollector{
		MetricsFilePath: metricsFilePath,
		EncryptionKey:   encryptionKey,
	}
}

// CollectLatency collects network latency metrics
func (collector *NetworkMetricsCollector) CollectLatency(target string) error {
	start := time.Now()
	_, err := net.Dial("tcp", target)
	if err != nil {
		return err
	}
	latency := time.Since(start).Seconds() * 1000 // Convert to milliseconds

	return collector.logMetric("latency", latency)
}

// CollectThroughput collects network throughput metrics
func (collector *NetworkMetricsCollector) CollectThroughput(bytesTransferred int, duration time.Duration) error {
	throughput := float64(bytesTransferred) / duration.Seconds() / 1024 // Convert to KBps

	return collector.logMetric("throughput", throughput)
}

// CollectResourceUtilization collects CPU and memory utilization metrics
func (collector *NetworkMetricsCollector) CollectResourceUtilization(cpuUtilization, memoryUtilization float64) error {
	if err := collector.logMetric("cpu_utilization", cpuUtilization); err != nil {
		return err
	}
	return collector.logMetric("memory_utilization", memoryUtilization)
}

// logMetric logs a network metric
func (collector *NetworkMetricsCollector) logMetric(metricType string, value float64) error {
	metric := Metric{
		Timestamp: time.Now(),
		Type:      metricType,
		Value:     value,
	}
	data, err := encryptMetric(metric, collector.EncryptionKey)
	if err != nil {
		return err
	}

	f, err := os.OpenFile(collector.MetricsFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = f.WriteString(data + "\n")
	return err
}

// GetMetrics retrieves and decrypts all metrics
func (collector *NetworkMetricsCollector) GetMetrics() ([]Metric, error) {
	data, err := ioutil.ReadFile(collector.MetricsFilePath)
	if err != nil {
		return nil, err
	}

	lines := string(data)
	var metrics []Metric
	for _, line := range strings.Split(lines, "\n") {
		if len(line) > 0 {
			metric, err := decryptMetric(line, collector.EncryptionKey)
			if err != nil {
				return nil, err
			}
			metrics = append(metrics, metric)
		}
	}

	return metrics, nil
}

// encryptMetric encrypts a metric using Argon2 and AES
func encryptMetric(metric Metric, key []byte) (string, error) {
	plaintext, err := json.Marshal(metric)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// decryptMetric decrypts a metric using Argon2 and AES
func decryptMetric(ciphertext string, key []byte) (Metric, error) {
	data, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return Metric{}, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return Metric{}, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return Metric{}, err
	}
	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return Metric{}, errors.New("ciphertext too short")
	}
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return Metric{}, err
	}

	var metric Metric
	err = json.Unmarshal(plaintext, &metric)
	if err != nil {
		return Metric{}, err
	}
	return metric, nil
}

// deriveKey derives a key using Argon2
func deriveKey(password []byte) []byte {
	salt := make([]byte, 16)
	_, _ = rand.Read(salt)
	key := argon2.IDKey(password, salt, 1, 64*1024, 4, 32)
	return key
}
