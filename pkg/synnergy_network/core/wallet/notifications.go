package notifications

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"synnergy-network/blockchain/utils"
	"synnergy-network/core/security"
)

// AlertType defines the type of alert being issued.
type AlertType int

const (
	SecurityAlert AlertType = iota
	TransactionAlert
	SystemAlert
)

// Alert represents a notification or warning issued by the wallet.
type Alert struct {
	ID          string    `json:"id"`
	Type        AlertType `json:"type"`
	Description string    `json:"description"`
	Timestamp   time.Time `json:"timestamp"`
	Handled     bool      `json:"handled"`
}

// AlertManager manages the creation, storage, and handling of alerts.
type AlertManager struct {
	alerts   []Alert
	filePath string
	mu       sync.Mutex
}

// NewAlertManager creates a new instance of AlertManager.
func NewAlertManager(filePath string) *AlertManager {
	return &AlertManager{
		filePath: filePath,
		alerts:   []Alert{},
	}
}

// LoadAlerts loads alerts from a JSON file.
func (am *AlertManager) LoadAlerts() error {
	am.mu.Lock()
	defer am.mu.Unlock()

	file, err := os.ReadFile(am.filePath)
	if err != nil {
		return err
	}

	err = json.Unmarshal(file, &am.alerts)
	if err != nil {
		return err
	}

	return nil
}

// SaveAlerts saves the current alerts to a JSON file.
func (am *AlertManager) SaveAlerts() error {
	am.mu.Lock()
	defer am.mu.Unlock()

	data, err := json.Marshal(am.alerts)
	if err != nil {
		return err
	}

	err = os.WriteFile(am.filePath, data, 0600)
	if err != nil {
		return err
	}

	return nil
}

// AddAlert adds a new alert to the manager.
func (am *AlertManager) AddAlert(alertType AlertType, description string) error {
	am.mu.Lock()
	defer am.mu.Unlock()

	alert := Alert{
		ID:          utils.GenerateID(),
		Type:        alertType,
		Description: description,
		Timestamp:   time.Now(),
		Handled:     false,
	}

	am.alerts = append(am.alerts, alert)
	return am.SaveAlerts()
}

// HandleAlert marks an alert as handled.
func (am *AlertManager) HandleAlert(alertID string) error {
	am.mu.Lock()
	defer am.mu.Unlock()

	for i, alert := range am.alerts {
		if alert.ID == alertID {
			am.alerts[i].Handled = true
			return am.SaveAlerts()
		}
	}

	return errors.New("alert not found")
}

// ListAlerts returns a list of all alerts.
func (am *AlertManager) ListAlerts() ([]Alert, error) {
	am.mu.Lock()
	defer am.mu.Unlock()

	return am.alerts, nil
}

func main() {
	alertManager := NewAlertManager("alerts.json")
	err := alertManager.LoadAlerts()
	if err != nil {
		fmt.Printf("Error loading alerts: %v\n", err)
		return
	}

	err = alertManager.AddAlert(SecurityAlert, "Unauthorized login attempt detected.")
	if err != nil {
		fmt.Printf("Error adding alert: %v\n", err)
		return
	}

	alerts, err := alertManager.ListAlerts()
	if err != nil {
		fmt.Printf("Error listing alerts: %v\n", err)
		return
	}

	for _, alert := range alerts {
		fmt.Printf("Alert: %v\n", alert)
	}
}
package notifications

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/smtp"
	"sync"

	"github.com/gorilla/websocket"
	"github.com/synnergy-network/core/wallet/utils"
)

// NotificationService handles the sending of real-time notifications to users.
type NotificationService struct {
	encryptionKey []byte
	mailer        *Mailer
	wsPool        *WebSocketPool
}

// NewNotificationService creates a new NotificationService with the necessary dependencies.
func NewNotificationService(encKey string, mailer *Mailer, wsPool *WebSocketPool) *NotificationService {
	key := utils.SecureHash(encKey)
	return &NotificationService{
		encryptionKey: key,
		mailer:        mailer,
		wsPool:        wsPool,
	}
}

// SendNotification encrypts and sends a notification to a user via email and WebSocket.
func (ns *NotificationService) SendNotification(userID string, message NotificationMessage) error {
	encryptedMsg, err := ns.encryptMessage(message)
	if err != nil {
		return err
	}

	// Send via WebSocket
	if err := ns.wsPool.Send(userID, encryptedMsg); err != nil {
		log.Println("Failed to send WebSocket message:", err)
		// Continue to send via email
	}

	// Send via Email
	if err := ns.mailer.SendEmail(userID, "Notification", encryptedMsg); err != nil {
		return fmt.Errorf("failed to send email notification: %w", err)
	}

	return nil
}

// encryptMessage encrypts the notification message using AES.
func (ns *NotificationService) encryptMessage(message NotificationMessage) (string, error) {
	plainText, err := json.Marshal(message)
	if err != nil {
		return "", fmt.Errorf("failed to marshal message: %w", err)
	}

	block, err := aes.NewCipher(ns.encryptionKey)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %w", err)
	}

	cipherText := make([]byte, aes.BlockSize+len(plainText))
	iv := cipherText[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", fmt.Errorf("failed to generate IV: %w", err)
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(cipherText[aes.BlockSize:], plainText)
	return fmt.Sprintf("%x", cipherText), nil
}

// NotificationMessage represents the notification message structure.
type NotificationMessage struct {
	Title   string `json:"title"`
	Content string `json:"content"`
}

// Mailer handles sending emails.
type Mailer struct {
	smtpServer string
	from       string
	password   string
}

// NewMailer creates a new Mailer instance.
func NewMailer(smtpServer, from, password string) *Mailer {
	return &Mailer{
		smtpServer: smtpServer,
		from:       from,
		password:   password,
	}
}

// SendEmail sends an email.
func (m *Mailer) SendEmail(to, subject, body string) error {
	// Implement email sending logic.
	return nil
}

// WebSocketPool manages WebSocket connections.
type WebSocketPool struct {
	connections map[string]*websocket.Conn
	mutex       sync.Mutex
}

// NewWebSocketPool initializes a new WebSocket connection pool.
func NewWebSocketPool() *WebSocketPool {
	return &WebSocketPool{
		connections: make(map[string]*websocket.Conn),
	}
}

// Send sends a message via WebSocket to the specified user.
func (pool *WebSocketPool) Send(userID, message string) error {
	pool.mutex.Lock()
	defer pool.mutex.Unlock()

	conn, ok := pool.connections[userID]
	if !ok {
		return errors.New("no connection found")
	}

	err := conn.WriteMessage(websocket.TextMessage, []byte(message))
	if err != nil {
		return fmt.Errorf("failed to send WebSocket message: %w", err)
	}
	return nil
}

func main() {
	// Example of setting up and using the NotificationService
	mailer := NewMailer("smtp.example.com", "no-reply@example.com", "password")
	wsPool := NewWebSocketPool()
	notificationService := NewNotificationService("encryptionKey123", mailer, wsPool)

	message := NotificationMessage{
		Title:   "Alert",
		Content: "Your transaction is confirmed.",
	}

	err := notificationService.SendNotification("userID123", message)
	if err != nil {
		log.Fatalf("Failed to send notification: %v", err)
	}
}
package notifications

import (
	"errors"
	"sync"
)

// NotificationSettings manages user preferences for receiving notifications.
type NotificationSettings struct {
	mu             sync.Mutex
	emailEnabled   bool
	pushEnabled    bool
	smsEnabled     bool
	securityAlerts bool
	transactionUpdates bool
	performanceMetrics bool
}

// NewNotificationSettings initializes a default notification setting.
func NewNotificationSettings() *NotificationSettings {
	return &NotificationSettings{
		emailEnabled:       true,
		pushEnabled:        true,
		smsEnabled:         false,
		securityAlerts:     true,
		transactionUpdates: true,
		performanceMetrics: false,
	}
}

// EnableEmailNotifications enables email notifications.
func (ns *NotificationSettings) EnableEmailNotifications() {
	ns.mu.Lock()
	defer ns.mu.Unlock()
	ns.emailEnabled = true
}

// DisableEmailNotifications disables email notifications.
func (ns *NotificationSettings) DisableEmailNotifications() {
	ns.mu.Lock()
	defer ns.mu.Unlock()
	ns.emailEnabled = false
}

// EnablePushNotifications enables push notifications on devices.
func (ns *NotificationSettings) EnablePushNotifications() {
	ns.mu.Lock()
	defer ns.mu.Unlock()
	ns.pushEnabled = true
}

// DisablePushNotifications disables push notifications on devices.
func (ns *NotificationSettings) DisablePushNotifications() {
	ns.mu.Lock()
	defer ns.mu.Unlock()
	ns.pushEnabled = false
}

// EnableSMSNotifications enables SMS notifications.
func (ns *NotificationSettings) EnableSMSNotifications() {
	ns.mu.Lock()
	defer ns.mu.Unlock()
	ns.smsEnabled = true
}

// DisableSMSNotifications disables SMS notifications.
func (ns *NotificationSettings) DisableSMSNotifications() {
	ns.mu.Lock()
	defer ns.mu.Unlock()
	ns.smsEnabled = false
}

// EnableSecurityAlerts enables notifications for security-related events.
func (ns *NotificationSettings) EnableSecurityAlerts() {
	ns.mu.Lock()
	defer ns.mu.Unlock()
	ns.securityAlerts = true
}

// DisableSecurityAlerts disables notifications for security-related events.
func (ns *NotificationSettings) DisableSecurityAlerts() {
	ns.mu.Lock()
	defer ns.mu.Unlock()
	ns.securityAlerts = false
}

// EnableTransactionUpdates enables notifications for transaction updates.
func (ns *NotificationSettings) EnableTransactionUpdates() {
	ns.mu.Lock()
	defer ns.mu.Unlock()
	ns.transactionUpdates = true
}

// DisableTransactionUpdates disables notifications for transaction updates.
func (ns *NotificationSettings) DisableTransactionUpdates() {
	ns.mu.Lock()
	defer ns.mu.Unlock()
	ns.transactionUpdates = false
}

// EnablePerformanceMetrics enables notifications for performance metrics.
func (ns *NotificationSettings) EnablePerformanceMetrics() {
	ns.mu.Lock()
	defer ns.mu.Unlock()
	ns.performanceMetrics = true
}

// DisablePerformanceMetrics disables notifications for performance metrics.
func (ns *NotificationSettings) DisablePerformanceMetrics() {
	ns.mu.Lock()
	defer ns.mu.Unlock()
	ns.performanceMetrics = false
}

// GetSettings returns the current notification settings.
func (ns *NotificationSettings) GetSettings() (bool, bool, bool, bool, bool, bool) {
	ns.mu.Lock()
	defer ns.mu.Unlock()
	return ns.emailEnabled, ns.pushEnabled, ns.smsEnabled, ns.securityAlerts, ns.transactionUpdates, ns.performanceMetrics
}

// ValidateSettings checks the consistency of notification settings.
func (ns *NotificationSettings) ValidateSettings() error {
	if !ns.emailEnabled && !ns.pushEnabled && !ns.smsEnabled {
		return errors.New("at least one method of notification must be enabled")
	}
	return nil
}
package notifications

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "encoding/json"
    "io"
    "log"
    "net/http"
    "sync"

    "github.com/gorilla/websocket"
    "github.com/synnergy-network/core/blockchain"
    "github.com/synnergy-network/core/wallet/security"
)

// NotificationManager manages real-time notifications for wallet events.
type NotificationManager struct {
    conn      *websocket.Conn
    lock      sync.Mutex
    Encryptor *security.EncryptionService
}

// NewNotificationManager creates a new NotificationManager with necessary initializations.
func NewNotificationManager() *NotificationManager {
    return &NotificationManager{
        Encryptor: security.NewEncryptionService(),
    }
}

// Connect establishes a websocket connection to the notification server.
func (nm *NotificationManager) Connect(url string) error {
    var dialer websocket.Dialer
    conn, _, err := dialer.Dial(url, nil)
    if err != nil {
        return err
    }
    nm.conn = conn
    return nil
}

// SendNotification encrypts and sends a notification to the connected websocket.
func (nm *NotificationManager) SendNotification(event blockchain.Event) error {
    nm.lock.Lock()
    defer nm.lock.Unlock()

    encryptedData, err := nm.Encryptor.Encrypt(json.Marshal(event))
    if err != nil {
        return err
    }

    if err := nm.conn.WriteMessage(websocket.TextMessage, encryptedData); err != nil {
        return err
    }
    return nil
}

// ListenForNotifications listens for incoming notifications and decrypts them.
func (nm *NotificationManager) ListenForNotifications() {
    defer nm.conn.Close()
    for {
        _, message, err := nm.conn.ReadMessage()
        if err != nil {
            log.Println("Error reading message:", err)
            continue
        }

        decryptedMessage, err := nm.Encryptor.Decrypt(message)
        if err != nil {
            log.Println("Error decrypting message:", err)
            continue
        }

        var event blockchain.Event
        if err := json.Unmarshal(decryptedMessage, &event); err != nil {
            log.Println("Error unmarshalling message:", err)
            continue
        }

        // Process the event here
        log.Printf("Received event: %+v\n", event)
    }
}

// EncryptionService handles encryption and decryption of messages.
type EncryptionService struct {
    key []byte
}

// NewEncryptionService creates a new EncryptionService with a generated key.
func NewEncryptionService() *EncryptionService {
    key := make([]byte, 32) // AES-256
    if _, err := io.ReadFull(rand.Reader, key); err != nil {
        panic(err) // Key generation should not fail
    }
    return &EncryptionService{key: key}
}

// Encrypt encrypts data using AES-256.
func (es *EncryptionService) Encrypt(data []byte) ([]byte, error) {
    block, err := aes.NewCipher(es.key)
    if err != nil {
        return nil, err
    }
    ciphertext := make([]byte, aes.BlockSize+len(data))
    iv := ciphertext[:aes.BlockSize]
    if _, err := io.ReadFull(rand.Reader, iv); err != nil {
        return nil, err
    }

    stream := cipher.NewCFBEncrypter(block, iv)
    stream.XORKeyStream(ciphertext[aes.BlockSize:], data)
    return ciphertext, nil
}

// Decrypt decrypts data using AES-256.
func (es *EncryptionService) Decrypt(data []byte) ([]byte, error) {
    block, err := aes.NewCipher(es.key)
    if err != nil {
        return nil, err
    }
    if len(data) < aes.BlockSize {
        return nil, errors.New("ciphertext too short")
    }
    iv := data[:aes.BlockSize]
    data = data[aes.BlockSize:]

    stream := cipher.NewCFBDecrypter(block, iv)
    stream.XORKeyStream(data, data)
    return data, nil
}
