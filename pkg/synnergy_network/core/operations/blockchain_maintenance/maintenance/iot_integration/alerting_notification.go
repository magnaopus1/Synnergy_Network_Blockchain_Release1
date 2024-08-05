package iot_integration

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "encoding/base64"
    "errors"
    "fmt"
    "io"
    "time"
)

// Alert represents an alert message from an IoT device
type Alert struct {
    DeviceID    string    `json:"device_id"`
    Timestamp   time.Time `json:"timestamp"`
    AlertType   string    `json:"alert_type"`
    Description string    `json:"description"`
    Encrypted   bool      `json:"encrypted"`
}

// AlertManager manages alerts from IoT devices
type AlertManager struct {
    encryptionKey []byte
    alerts        []Alert
}

// NewAlertManager creates a new AlertManager
func NewAlertManager(encryptionKey []byte) *AlertManager {
    return &AlertManager{
        encryptionKey: encryptionKey,
        alerts:        []Alert{},
    }
}

// AddAlert adds a new alert to the manager
func (am *AlertManager) AddAlert(deviceID, alertType, description string, encrypt bool) error {
    alert := Alert{
        DeviceID:    deviceID,
        Timestamp:   time.Now(),
        AlertType:   alertType,
        Description: description,
        Encrypted:   encrypt,
    }

    if encrypt {
        encryptedDesc, err := encryptString(description, am.encryptionKey)
        if err != nil {
            return err
        }
        alert.Description = encryptedDesc
    }

    am.alerts = append(am.alerts, alert)
    return nil
}

// GetAlerts retrieves all alerts from the manager
func (am *AlertManager) GetAlerts(decrypt bool) ([]Alert, error) {
    if !decrypt {
        return am.alerts, nil
    }

    var decryptedAlerts []Alert
    for _, alert := range am.alerts {
        if alert.Encrypted {
            decryptedDesc, err := decryptString(alert.Description, am.encryptionKey)
            if err != nil {
                return nil, err
            }
            alert.Description = decryptedDesc
        }
        decryptedAlerts = append(decryptedAlerts, alert)
    }
    return decryptedAlerts, nil
}

// Encrypts a string using AES encryption
func encryptString(plaintext string, key []byte) (string, error) {
    block, err := aes.NewCipher(key)
    if err != nil {
        return "", err
    }

    ciphertext := make([]byte, aes.BlockSize+len(plaintext))
    iv := ciphertext[:aes.BlockSize]
    if _, err := io.ReadFull(rand.Reader, iv); err != nil {
        return "", err
    }

    stream := cipher.NewCFBEncrypter(block, iv)
    stream.XORKeyStream(ciphertext[aes.BlockSize:], []byte(plaintext))

    return base64.URLEncoding.EncodeToString(ciphertext), nil
}

// Decrypts an AES-encrypted string
func decryptString(ciphertext string, key []byte) (string, error) {
    ciphertextBytes, err := base64.URLEncoding.DecodeString(ciphertext)
    if err != nil {
        return "", err
    }

    block, err := aes.NewCipher(key)
    if err != nil {
        return "", err
    }

    if len(ciphertextBytes) < aes.BlockSize {
        return "", errors.New("ciphertext too short")
    }

    iv := ciphertextBytes[:aes.BlockSize]
    ciphertextBytes = ciphertextBytes[aes.BlockSize:]

    stream := cipher.NewCFBDecrypter(block, iv)
    stream.XORKeyStream(ciphertextBytes, ciphertextBytes)

    return string(ciphertextBytes), nil
}

// Notifies via email
func (am *AlertManager) NotifyByEmail(email string) error {
    // Integrate email sending logic here
    // Ensure the email contains the necessary alert information
    return nil
}

// Notifies via messaging platform
func (am *AlertManager) NotifyByMessage(platform, recipient string) error {
    // Integrate messaging platform sending logic here
    // Ensure the message contains the necessary alert information
    return nil
}


