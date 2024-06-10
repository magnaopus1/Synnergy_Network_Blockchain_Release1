package metrics

import (
	"fmt"
	"sync"
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/crypto/argon2"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
)

// ExporterManager manages custom metric exporters and integrates with Prometheus.
type ExporterManager struct {
	exporters    map[string]prometheus.Collector
	mutex        sync.RWMutex
	alertChannel chan Alert
}

// NewExporterManager creates a new ExporterManager.
func NewExporterManager() *ExporterManager {
	return &ExporterManager{
		exporters:    make(map[string]prometheus.Collector),
		alertChannel: make(chan Alert, 100),
	}
}

// RegisterExporter registers a new custom metric exporter.
func (em *ExporterManager) RegisterExporter(name string, exporter prometheus.Collector) error {
	em.mutex.Lock()
	defer em.mutex.Unlock()

	if _, exists := em.exporters[name]; exists {
		return fmt.Errorf("exporter %s already registered", name)
	}

	em.exporters[name] = exporter
	prometheus.MustRegister(exporter)
	return nil
}

// UnregisterExporter unregisters an existing custom metric exporter.
func (em *ExporterManager) UnregisterExporter(name string) error {
	em.mutex.Lock()
	defer em.mutex.Unlock()

	exporter, exists := em.exporters[name]
	if !exists {
		return fmt.Errorf("exporter %s not found", name)
	}

	prometheus.Unregister(exporter)
	delete(em.exporters, name)
	return nil
}

// ServeMetrics starts an HTTP server to serve the metrics.
func (em *ExporterManager) ServeMetrics(port int) {
	http.Handle("/metrics", promhttp.Handler())
	go func() {
		if err := http.ListenAndServe(fmt.Sprintf(":%d", port), nil); err != nil {
			fmt.Printf("Error starting HTTP server: %v\n", err)
		}
	}()
}

// MonitorMetrics sets up an HTTP handler for exposing metrics and starts monitoring.
func (em *ExporterManager) MonitorMetrics(port int) {
	http.Handle("/metrics", promhttp.Handler())
	go func() {
		if err := http.ListenAndServe(fmt.Sprintf(":%d", port), nil); err != nil {
			fmt.Printf("Error starting HTTP server: %v\n", err)
		}
	}()
}

// EncryptAlert encrypts the alert message using AES encryption.
func (em *ExporterManager) EncryptAlert(alert Alert, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	ciphertext := make([]byte, aes.BlockSize+len(alert.AlertMessage))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], []byte(alert.AlertMessage))

	return ciphertext, nil
}

// DecryptAlert decrypts the alert message using AES encryption.
func (em *ExporterManager) DecryptAlert(ciphertext, key []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	if len(ciphertext) < aes.BlockSize {
		return "", fmt.Errorf("ciphertext too short")
	}
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(ciphertext, ciphertext)

	return string(ciphertext), nil
}

// Argon2KeyDerivation derives a key using Argon2.
func (em *ExporterManager) Argon2KeyDerivation(password, salt []byte) []byte {
	return argon2.IDKey(password, salt, 1, 64*1024, 4, 32)
}

// GetAlertChannel returns the alert channel for listening to triggered alerts.
func (em *ExporterManager) GetAlertChannel() <-chan Alert {
	return em.alertChannel
}

// Alert represents a structure for alert messages.
type Alert struct {
	MetricName   string
	CurrentValue float64
	AlertMessage string
	Timestamp    string
}

func main() {
	exporterManager := NewExporterManager()

	cpuUsage := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "cpu_usage",
		Help: "Current CPU usage",
	})

	exporterManager.RegisterExporter("cpu_usage", cpuUsage)

	exporterManager.MonitorMetrics(9090)

	go func() {
		for alert := range exporterManager.GetAlertChannel() {
			fmt.Printf("ALERT: %s - %f at %s\n", alert.AlertMessage, alert.CurrentValue, alert.Timestamp)
		}
	}()

	// Simulate metrics update
	for {
		value := float64(time.Now().UnixNano() % 100)
		cpuUsage.Set(value)
		time.Sleep(5 * time.Second)
	}
}
