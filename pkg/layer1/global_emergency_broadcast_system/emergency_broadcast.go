package emergency_broadcast_system

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"io"
	"log"
	"time"

	"github.com/pkg/errors"
)

// EmergencyMessage encapsulates the details of an emergency broadcast.
type EmergencyMessage struct {
	ID        string    `json:"id"`
	Message   string    `json:"message"`
	Timestamp time.Time `json:"timestamp"`
	Severity  string    `json:"severity"`
}

// Broadcaster is responsible for sending and receiving emergency broadcasts across the network.
type Broadcaster struct {
	encryptionKey []byte
}

// NewBroadcaster creates a new broadcaster with a given encryption key.
func NewBroadcaster(key []byte) *Broadcaster {
	return &Broadcaster{
		encryptionKey: key,
	}
}

// BroadcastMessage encrypts and sends an emergency message to the network.
func (b *Broadcaster) BroadcastMessage(msg EmergencyMessage) error {
	data, err := json.Marshal(msg)
	if err != nil {
		return errors.Wrap(err, "failed to marshal emergency message")
	}

	encryptedData, err := b.encryptData(data)
	if err != nil {
		return errors.Wrap(err, "failed to encrypt message")
	}

	// Simulating network broadcast
	log.Printf("Broadcasting emergency message: %s", encryptedData)
	return nil
}

// ReceiveMessage decrypts received emergency messages.
func (b *Broadcaster) ReceiveMessage(data []byte) (*EmergencyMessage, error) {
	decryptedData, err := b.decryptData(data)
	if err != nil {
		return nil, errors.Wrap(err, "failed to decrypt message")
	}

	var msg EmergencyMessage
	err = json.Unmarshal(decryptedData, &msg)
	if err != nil {
		return nil, errors.Wrap(err, "failed to unmarshal emergency message")
	}

	return &msg, nil
}

// encryptData encrypts data using AES encryption.
func (b *Broadcaster) encryptData(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(b.encryptionKey)
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

// decryptData decrypts data using AES decryption.
func (b *Broadcaster) decryptData(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(b.encryptionKey)
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
