package automated_alerting_systems

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "encoding/base64"
    "errors"
    "fmt"
    "io"
    "log"
    "net/http"
    "bytes"
    "time"
    "os"

    "github.com/synnergy_network/pkg/synnergy_network/core/utils/encryption_utils"
    "github.com/synnergy_network/pkg/synnergy_network/core/utils/logging_utils"
)

// MessagingPlatformIntegration handles the integration with various messaging platforms for alerting purposes.
type MessagingPlatformIntegration struct {
    PlatformURL string
    AuthToken   string
}

// NewMessagingPlatformIntegration creates a new instance of MessagingPlatformIntegration.
func NewMessagingPlatformIntegration(platformURL, authToken string) *MessagingPlatformIntegration {
    return &MessagingPlatformIntegration{
        PlatformURL: platformURL,
        AuthToken:   authToken,
    }
}

// SendAlert sends an alert message to the configured messaging platform.
func (mpi *MessagingPlatformIntegration) SendAlert(message string) error {
    encryptedMessage, err := encryption_utils.EncryptMessage(message, mpi.AuthToken)
    if err != nil {
        return fmt.Errorf("failed to encrypt message: %v", err)
    }

    req, err := http.NewRequest("POST", mpi.PlatformURL, bytes.NewBuffer([]byte(encryptedMessage)))
    if err != nil {
        return fmt.Errorf("failed to create request: %v", err)
    }

    req.Header.Set("Content-Type", "application/json")
    req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", mpi.AuthToken))

    client := &http.Client{Timeout: 10 * time.Second}
    resp, err := client.Do(req)
    if err != nil {
        return fmt.Errorf("failed to send alert: %v", err)
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
        return fmt.Errorf("received non-200 response: %d", resp.StatusCode)
    }

    logging_utils.LogInfo(fmt.Sprintf("Alert sent successfully to %s", mpi.PlatformURL))
    return nil
}

// Encryption utilities for message encryption
package encryption_utils

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "encoding/base64"
    "io"
)

// EncryptMessage encrypts a message using AES encryption.
func EncryptMessage(message, key string) (string, error) {
    block, err := aes.NewCipher([]byte(key))
    if err != nil {
        return "", err
    }

    ciphertext := make([]byte, aes.BlockSize+len(message))
    iv := ciphertext[:aes.BlockSize]
    if _, err := io.ReadFull(rand.Reader, iv); err != nil {
        return "", err
    }

    stream := cipher.NewCFBEncrypter(block, iv)
    stream.XORKeyStream(ciphertext[aes.BlockSize:], []byte(message))

    return base64.URLEncoding.EncodeToString(ciphertext), nil
}

// DecryptMessage decrypts an encrypted message using AES encryption.
func DecryptMessage(encryptedMessage, key string) (string, error) {
    ciphertext, _ := base64.URLEncoding.DecodeString(encryptedMessage)

    block, err := aes.NewCipher([]byte(key))
    if err != nil {
        return "", err
    }

    if len(ciphertext) < aes.BlockSize {
        return "", errors.New("ciphertext too short")
    }
    iv := ciphertext[:aes.BlockSize]
    ciphertext = ciphertext[aes.BlockSize:]

    stream := cipher.NewCFBDecrypter(block, iv)
    stream.XORKeyStream(ciphertext, ciphertext)

    return string(ciphertext), nil
}

// Logging utilities for consistent logging
package logging_utils

import (
    "log"
    "os"
)

var (
    infoLogger  *log.Logger
    errorLogger *log.Logger
)

func init() {
    infoLogger = log.New(os.Stdout, "INFO: ", log.Ldate|log.Ltime|log.Lshortfile)
    errorLogger = log.New(os.Stderr, "ERROR: ", log.Ldate|log.Ltime|log.Lshortfile)
}

// LogInfo logs informational messages.
func LogInfo(message string) {
    infoLogger.Println(message)
}

// LogError logs error messages.
func LogError(message string) {
    errorLogger.Println(message)
}
