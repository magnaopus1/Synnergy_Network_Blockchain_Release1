package customizable_alert_system

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "crypto/sha256"
    "crypto/subtle"
    "encoding/base64"
    "errors"
    "io"
    "log"
    "sync"
    "time"
    
    "github.com/prometheus/client_golang/prometheus"
    "github.com/prometheus/client_golang/prometheus/promauto"
)

// AlertLevel defines the level of an alert
type AlertLevel int

const (
    Info AlertLevel = iota
    Warning
    Critical
)

// NotificationMechanism interface defines methods for notification mechanisms
type NotificationMechanism interface {
    SendAlert(alert Alert) error
}

// Alert structure represents an alert
type Alert struct {
    ID          string
    Timestamp   time.Time
    Level       AlertLevel
    Message     string
    Data        map[string]interface{}
}

// NotificationManager manages multiple notification mechanisms
type NotificationManager struct {
    mechanisms []NotificationMechanism
    alertCount prometheus.Counter
    lock       sync.Mutex
}

// NewNotificationManager creates a new NotificationManager
func NewNotificationManager() *NotificationManager {
    return &NotificationManager{
        mechanisms: []NotificationMechanism{},
        alertCount: promauto.NewCounter(prometheus.CounterOpts{
            Name: "alert_count_total",
            Help: "The total number of alerts sent",
        }),
    }
}

// RegisterMechanism registers a new notification mechanism
func (nm *NotificationManager) RegisterMechanism(mechanism NotificationMechanism) {
    nm.lock.Lock()
    defer nm.lock.Unlock()
    nm.mechanisms = append(nm.mechanisms, mechanism)
}

// SendAlert sends an alert through all registered mechanisms
func (nm *NotificationManager) SendAlert(alert Alert) {
    nm.lock.Lock()
    defer nm.lock.Unlock()

    for _, mechanism := range nm.mechanisms {
        err := mechanism.SendAlert(alert)
        if err != nil {
            log.Printf("Error sending alert: %v", err)
        }
    }
    nm.alertCount.Inc()
}

// EmailNotificationMechanism sends alerts via email
type EmailNotificationMechanism struct {
    smtpServer string
    username   string
    password   string
}

// NewEmailNotificationMechanism creates a new EmailNotificationMechanism
func NewEmailNotificationMechanism(smtpServer, username, password string) *EmailNotificationMechanism {
    return &EmailNotificationMechanism{
        smtpServer: smtpServer,
        username:   username,
        password:   password,
    }
}

// SendAlert sends an alert via email
func (enm *EmailNotificationMechanism) SendAlert(alert Alert) error {
    // Implement email sending logic here
    log.Printf("Sending email alert: %v", alert)
    return nil
}

// SMSNotificationMechanism sends alerts via SMS
type SMSNotificationMechanism struct {
    smsGateway string
    apiKey     string
}

// NewSMSNotificationMechanism creates a new SMSNotificationMechanism
func NewSMSNotificationMechanism(smsGateway, apiKey string) *SMSNotificationMechanism {
    return &SMSNotificationMechanism{
        smsGateway: smsGateway,
        apiKey:     apiKey,
    }
}

// SendAlert sends an alert via SMS
func (snm *SMSNotificationMechanism) SendAlert(alert Alert) error {
    // Implement SMS sending logic here
    log.Printf("Sending SMS alert: %v", alert)
    return nil
}

// Encryption utilities
func generateKey(password, salt []byte) []byte {
    key := sha256.Sum256(append(password, salt...))
    return key[:]
}

func encrypt(plainText, password []byte) (string, error) {
    block, err := aes.NewCipher(password)
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
    
    cipherText := gcm.Seal(nonce, nonce, plainText, nil)
    return base64.StdEncoding.EncodeToString(cipherText), nil
}

func decrypt(cipherText string, password []byte) ([]byte, error) {
    data, err := base64.StdEncoding.DecodeString(cipherText)
    if err != nil {
        return nil, err
    }
    
    block, err := aes.NewCipher(password)
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
    
    nonce, cipherText := data[:nonceSize], data[nonceSize:]
    return gcm.Open(nil, nonce, cipherText, nil)
}

// Alert database
type AlertDB struct {
    db map[string]Alert
    mu sync.Mutex
}

// NewAlertDB creates a new AlertDB
func NewAlertDB() *AlertDB {
    return &AlertDB{
        db: make(map[string]Alert),
    }
}

// StoreAlert stores an alert in the database
func (db *AlertDB) StoreAlert(alert Alert) {
    db.mu.Lock()
    defer db.mu.Unlock()
    db.db[alert.ID] = alert
}

// GetAlert retrieves an alert from the database
func (db *AlertDB) GetAlert(id string) (Alert, bool) {
    db.mu.Lock()
    defer db.mu.Unlock()
    alert, exists := db.db[id]
    return alert, exists
}

// DeleteAlert deletes an alert from the database
func (db *AlertDB) DeleteAlert(id string) {
    db.mu.Lock()
    defer db.mu.Unlock()
    delete(db.db, id)
}

