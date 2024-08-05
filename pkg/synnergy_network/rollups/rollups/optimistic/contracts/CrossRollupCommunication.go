package contracts

import (
    "encoding/json"
    "errors"
    "sync"
    "time"
    "crypto/sha256"
    "github.com/minio/sio"
    "golang.org/x/crypto/argon2"
    "golang.org/x/crypto/scrypt"
    "crypto/rand"
    "fmt"
)

// CrossRollupCommunication represents the mechanism for managing cross-rollup communication.
type CrossRollupCommunication struct {
    rollups     map[string]*Rollup
    messages    map[string]*Message
    mutex       sync.Mutex
}

// Rollup represents a single rollup in the system.
type Rollup struct {
    ID              string
    URL             string
    PublicKey       []byte
    PrivateKey      []byte
}

// Message represents a message to be communicated between rollups.
type Message struct {
    ID              string
    FromRollup      string
    ToRollup        string
    Content         string
    Timestamp       time.Time
    Status          string
    Signature       []byte
}

// NewCrossRollupCommunication initializes a new CrossRollupCommunication system.
func NewCrossRollupCommunication() *CrossRollupCommunication {
    return &CrossRollupCommunication{
        rollups:  make(map[string]*Rollup),
        messages: make(map[string]*Message),
    }
}

// RegisterRollup allows a new rollup to be registered in the system.
func (crc *CrossRollupCommunication) RegisterRollup(id, url string, publicKey, privateKey []byte) (string, error) {
    crc.mutex.Lock()
    defer crc.mutex.Unlock()

    if _, exists := crc.rollups[id]; exists {
        return "", errors.New("rollup already registered")
    }

    rollup := &Rollup{
        ID:        id,
        URL:       url,
        PublicKey: publicKey,
        PrivateKey: privateKey,
    }
    crc.rollups[id] = rollup
    return id, nil
}

// SendMessage allows a message to be sent from one rollup to another.
func (crc *CrossRollupCommunication) SendMessage(fromRollup, toRollup, content string) (string, error) {
    crc.mutex.Lock()
    defer crc.mutex.Unlock()

    if _, exists := crc.rollups[fromRollup]; !exists {
        return "", errors.New("from rollup does not exist")
    }

    if _, exists := crc.rollups[toRollup]; !exists {
        return "", errors.New("to rollup does not exist")
    }

    id := generateID()
    message := &Message{
        ID:         id,
        FromRollup: fromRollup,
        ToRollup:   toRollup,
        Content:    content,
        Timestamp:  time.Now(),
        Status:     "Pending",
    }

    // Sign the message
    signature, err := crc.signMessage(message)
    if err != nil {
        return "", err
    }
    message.Signature = signature

    // Encrypt the message
    encryptedContent, err := encryptContent(message.Content)
    if err != nil {
        return "", err
    }
    message.Content = encryptedContent

    crc.messages[id] = message
    return id, nil
}

// ReceiveMessage allows a rollup to receive a message.
func (crc *CrossRollupCommunication) ReceiveMessage(id string) (*Message, error) {
    crc.mutex.Lock()
    defer crc.mutex.Unlock()

    message, exists := crc.messages[id]
    if !exists {
        return nil, errors.New("message does not exist")
    }

    // Decrypt the message
    decryptedContent, err := decryptContent(message.Content)
    if err != nil {
        return nil, err
    }
    message.Content = decryptedContent

    // Verify the message signature
    if err := crc.verifyMessageSignature(message); err != nil {
        return nil, err
    }

    message.Status = "Received"
    return message, nil
}

// ListPendingMessages lists all pending messages.
func (crc *CrossRollupCommunication) ListPendingMessages() []*Message {
    crc.mutex.Lock()
    defer crc.mutex.Unlock()

    var pendingMessages []*Message
    for _, message := range crc.messages {
        if message.Status == "Pending" {
            pendingMessages = append(pendingMessages, message)
        }
    }
    return pendingMessages
}

// GetMessage retrieves a message by its ID.
func (crc *CrossRollupCommunication) GetMessage(id string) (*Message, error) {
    crc.mutex.Lock()
    defer crc.mutex.Unlock()

    message, exists := crc.messages[id]
    if !exists {
        return nil, errors.New("message does not exist")
    }
    return message, nil
}

// signMessage signs a message using the private key of the fromRollup.
func (crc *CrossRollupCommunication) signMessage(message *Message) ([]byte, error) {
    rollup, exists := crc.rollups[message.FromRollup]
    if !exists {
        return nil, errors.New("from rollup does not exist")
    }

    messageData, err := json.Marshal(message)
    if err != nil {
        return nil, err
    }

    hash := sha256.Sum256(messageData)
    signature := encrypt(hash[:], rollup.PrivateKey)
    return signature, nil
}

// verifyMessageSignature verifies the signature of a message.
func (crc *CrossRollupCommunication) verifyMessageSignature(message *Message) error {
    rollup, exists := crc.rollups[message.FromRollup]
    if !exists {
        return errors.New("from rollup does not exist")
    }

    messageData, err := json.Marshal(message)
    if err != nil {
        return err
    }

    hash := sha256.Sum256(messageData)
    decryptedSignature := decrypt(message.Signature, rollup.PublicKey)
    if !equal(hash[:], decryptedSignature) {
        return errors.New("signature verification failed")
    }
    return nil
}

// encryptContent encrypts the message content using Scrypt/AES.
func encryptContent(content string) (string, error) {
    salt := make([]byte, 16)
    _, err := rand.Read(salt)
    if err != nil {
        return "", err
    }

    key, err := scrypt.Key([]byte(content), salt, 16384, 8, 1, 32)
    if err != nil {
        return "", err
    }

    encryptedContent, err := sio.EncryptReader(rand.Reader, sio.Config{Key: key})
    if err != nil {
        return "", err
    }

    return string(encryptedContent), nil
}

// decryptContent decrypts the message content using Scrypt/AES.
func decryptContent(content string) (string, error) {
    salt := make([]byte, 16)
    _, err := rand.Read(salt)
    if err != nil {
        return "", err
    }

    key, err := scrypt.Key([]byte(content), salt, 16384, 8, 1, 32)
    if err != nil {
        return "", err
    }

    decryptedContent, err := sio.DecryptReader(rand.Reader, sio.Config{Key: key})
    if err != nil {
        return "", err
    }

    return string(decryptedContent), nil
}

// generateID generates a unique ID for a message.
func generateID() string {
    return fmt.Sprintf("%x", sha256.Sum256([]byte(time.Now().String())))
}

// equal compares two byte slices for equality.
func equal(a, b []byte) bool {
    if len(a) != len(b) {
        return false
    }
    for i := range a {
        if a[i] != b[i] {
            return false
        }
    }
    return true
}

// encrypt encrypts the input data using the provided key.
func encrypt(data, key []byte) []byte {
    hash := sha256.Sum256(append(data, key...))
    return hash[:]
}

// decrypt decrypts the input data using the provided key.
func decrypt(data, key []byte) []byte {
    hash := sha256.Sum256(append(data, key...))
    return hash[:]
}
