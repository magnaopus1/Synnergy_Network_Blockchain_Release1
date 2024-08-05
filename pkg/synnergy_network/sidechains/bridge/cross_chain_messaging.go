package bridge

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "crypto/sha256"
    "encoding/hex"
    "encoding/json"
    "errors"
    "fmt"
    "io"
    "sync"
    "time"

    "github.com/synnergy_network/bridge/transfer_logs"
    "github.com/synnergy_network/bridge/security_protocols"
    "github.com/synnergy_network/bridge/state_verification"
)

// Message represents a cross-chain message
type Message struct {
    ID          string    `json:"id"`
    SourceChain string    `json:"source_chain"`
    TargetChain string    `json:"target_chain"`
    Payload     string    `json:"payload"`
    Timestamp   time.Time `json:"timestamp"`
    Status      string    `json:"status"`
}

// MessagingManager manages cross-chain messaging
type MessagingManager struct {
    messages []Message
    mu       sync.RWMutex
}

// NewMessagingManager creates a new MessagingManager
func NewMessagingManager() *MessagingManager {
    return &MessagingManager{
        messages: []Message{},
    }
}

// SendMessage sends a new cross-chain message
func (mm *MessagingManager) SendMessage(sourceChain, targetChain, payload string) (Message, error) {
    if sourceChain == "" || targetChain == "" || payload == "" {
        return Message{}, errors.New("invalid message parameters")
    }

    message := Message{
        ID:          generateMessageID(),
        SourceChain: sourceChain,
        TargetChain: targetChain,
        Payload:     payload,
        Timestamp:   time.Now(),
        Status:      "Pending",
    }

    encryptedMessage, err := mm.encryptMessage(message)
    if err != nil {
        return Message{}, err
    }

    mm.mu.Lock()
    mm.messages = append(mm.messages, encryptedMessage)
    mm.mu.Unlock()

    transfer_logs.LogMessageSent(encryptedMessage)

    return encryptedMessage, nil
}

// ReceiveMessage receives a cross-chain message
func (mm *MessagingManager) ReceiveMessage(messageID string) (Message, error) {
    mm.mu.RLock()
    defer mm.mu.RUnlock()

    for _, message := range mm.messages {
        if message.ID == messageID {
            decryptedMessage, err := mm.decryptMessage(message)
            if err != nil {
                return Message{}, err
            }
            return decryptedMessage, nil
        }
    }

    return Message{}, errors.New("message not found")
}

// ValidateMessage validates the integrity and authenticity of a message
func (mm *MessagingManager) ValidateMessage(message Message) (bool, error) {
    if message.Status != "Pending" {
        return false, errors.New("message is not pending")
    }

    if !state_verification.VerifyMessageState(message) {
        return false, errors.New("message state verification failed")
    }

    mm.mu.Lock()
    for i, msg := range mm.messages {
        if msg.ID == message.ID {
            mm.messages[i].Status = "Validated"
        }
    }
    mm.mu.Unlock()

    transfer_logs.LogMessageValidated(message)

    return true, nil
}

// CompleteMessage completes the processing of a message
func (mm *MessagingManager) CompleteMessage(messageID string) error {
    mm.mu.Lock()
    defer mm.mu.Unlock()

    for i, message := range mm.messages {
        if message.ID == messageID {
            if message.Status != "Validated" {
                return errors.New("message is not validated")
            }

            mm.messages[i].Status = "Completed"
            transfer_logs.LogMessageCompleted(message)

            return nil
        }
    }

    return errors.New("message not found")
}

// GenerateMessageID generates a unique ID for a message
func generateMessageID() string {
    hash := sha256.New()
    hash.Write([]byte(time.Now().String()))
    return hex.EncodeToString(hash.Sum(nil))
}

// EncryptMessage encrypts the message details
func (mm *MessagingManager) encryptMessage(message Message) (Message, error) {
    key := sha256.Sum256([]byte("securepassword"))
    block, err := aes.NewCipher(key[:])
    if err != nil {
        return message, err
    }

    messageData, err := json.Marshal(message)
    if err != nil {
        return message, err
    }

    ciphertext := make([]byte, aes.BlockSize+len(messageData))
    iv := ciphertext[:aes.BlockSize]

    if _, err := io.ReadFull(rand.Reader, iv); err != nil {
        return message, err
    }

    stream := cipher.NewCFBEncrypter(block, iv)
    stream.XORKeyStream(ciphertext[aes.BlockSize:], messageData)

    encryptedMessage := message
    encryptedMessage.Payload = hex.EncodeToString(ciphertext)

    return encryptedMessage, nil
}

// DecryptMessage decrypts the message details
func (mm *MessagingManager) decryptMessage(encryptedMessage Message) (Message, error) {
    key := sha256.Sum256([]byte("securepassword"))
    ciphertext, _ := hex.DecodeString(encryptedMessage.Payload)
    block, err := aes.NewCipher(key[:])
    if err != nil {
        return Message{}, err
    }

    if len(ciphertext) < aes.BlockSize {
        return Message{}, errors.New("ciphertext too short")
    }

    iv := ciphertext[:aes.BlockSize]
    ciphertext = ciphertext[aes.BlockSize:]

    stream := cipher.NewCFBDecrypter(block, iv)
    stream.XORKeyStream(ciphertext, ciphertext)

    var message Message
    if err := json.Unmarshal(ciphertext, &message); err != nil {
        return Message{}, err
    }

    return message, nil
}

// Example usage demonstrating comprehensive functionality
func ExampleComprehensiveFunctionality() {
    mm := NewMessagingManager()

    // Send a new message
    sentMessage, err := mm.SendMessage("ChainA", "ChainB", "Sample Payload")
    if err != nil {
        fmt.Println("Error sending message:", err)
        return
    }

    fmt.Println("Sent Message:", sentMessage)

    // Receive the sent message
    receivedMessage, err := mm.ReceiveMessage(sentMessage.ID)
    if err != nil {
        fmt.Println("Error receiving message:", err)
        return
    }

    fmt.Println("Received Message:", receivedMessage)

    // Validate the received message
    isValid, err := mm.ValidateMessage(receivedMessage)
    if !isValid || err != nil {
        fmt.Println("Error validating message:", err)
        return
    }

    fmt.Println("Validated Message:", receivedMessage)

    // Complete the message processing
    err = mm.CompleteMessage(receivedMessage.ID)
    if err != nil {
        fmt.Println("Error completing message:", err)
        return
    }

    fmt.Println("Completed Message:", receivedMessage)
}
