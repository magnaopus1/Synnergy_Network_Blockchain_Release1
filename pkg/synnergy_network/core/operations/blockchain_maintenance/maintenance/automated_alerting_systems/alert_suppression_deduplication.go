package automated_alerting_systems

import (
	"log"
	"time"
	"sync"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"strings"
	"github.com/prometheus/client_golang/prometheus"
)

// Alert represents a basic alert structure
type Alert struct {
	ID          string
	Timestamp   time.Time
	Message     string
	Severity    string
	Source      string
}

// AlertManager manages incoming alerts and handles suppression and deduplication
type AlertManager struct {
	alerts              map[string]Alert
	suppressionDuration time.Duration
	mu                  sync.Mutex
	alertMetrics        *prometheus.CounterVec
	encryptionKey       []byte
}

// NewAlertManager creates a new AlertManager
func NewAlertManager(suppressionDuration time.Duration, encryptionKey string) (*AlertManager, error) {
	key, err := generateKey(encryptionKey)
	if err != nil {
		return nil, err
	}
	manager := &AlertManager{
		alerts:              make(map[string]Alert),
		suppressionDuration: suppressionDuration,
		alertMetrics: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "alerts_total",
				Help: "Total number of alerts",
			},
			[]string{"source", "severity"},
		),
		encryptionKey: key,
	}
	prometheus.MustRegister(manager.alertMetrics)
	return manager, nil
}

// AddAlert adds a new alert to the manager, handling suppression and deduplication
func (am *AlertManager) AddAlert(alert Alert) {
	am.mu.Lock()
	defer am.mu.Unlock()

	alertID := am.generateAlertID(alert)
	encryptedAlertID, err := am.encrypt(alertID)
	if err != nil {
		log.Printf("Error encrypting alert ID: %v", err)
		return
	}

	if existingAlert, exists := am.alerts[encryptedAlertID]; exists {
		if time.Since(existingAlert.Timestamp) < am.suppressionDuration {
			log.Printf("Alert suppressed: %s", alert.Message)
			return
		}
	}

	am.alerts[encryptedAlertID] = alert
	am.alertMetrics.With(prometheus.Labels{"source": alert.Source, "severity": alert.Severity}).Inc()
	log.Printf("Alert added: %s", alert.Message)
}

// generateAlertID generates a unique ID for an alert based on its content
func (am *AlertManager) generateAlertID(alert Alert) string {
	hash := sha256.New()
	hash.Write([]byte(strings.Join([]string{alert.Message, alert.Severity, alert.Source}, "|")))
	return hex.EncodeToString(hash.Sum(nil))
}

// encrypt encrypts a string using AES
func (am *AlertManager) encrypt(data string) (string, error) {
	block, err := aes.NewCipher(am.encryptionKey)
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

	ciphertext := gcm.Seal(nonce, nonce, []byte(data), nil)
	return hex.EncodeToString(ciphertext), nil
}

// generateKey generates a 32-byte key from a passphrase
func generateKey(passphrase string) ([]byte, error) {
	if len(passphrase) == 0 {
		return nil, errors.New("passphrase cannot be empty")
	}

	hash := sha256.New()
	hash.Write([]byte(passphrase))
	return hash.Sum(nil), nil
}

// PruneOldAlerts removes alerts that are older than the suppression duration
func (am *AlertManager) PruneOldAlerts() {
	am.mu.Lock()
	defer am.mu.Unlock()

	for id, alert := range am.alerts {
		if time.Since(alert.Timestamp) > am.suppressionDuration {
			delete(am.alerts, id)
		}
	}
}

// LogMetrics logs the alert metrics for monitoring
func (am *AlertManager) LogMetrics() {
	metrics := prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "alerts_metrics",
			Help: "Current alert metrics",
		},
		[]string{"source", "severity"},
	)
	prometheus.MustRegister(metrics)
	// Implementation for logging metrics
}
