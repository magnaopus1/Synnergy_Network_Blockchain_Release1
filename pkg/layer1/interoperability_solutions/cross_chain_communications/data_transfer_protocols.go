package cross_chain_communications

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"

	"github.com/pkg/errors"
)

// DataTransferProtocol defines the standard for blockchain data transfer.
type DataTransferProtocol struct {
	ProtocolVersion string
	EncryptionKey   []byte
}

// EncryptedDataPacket represents a structure for securely transferring data.
type EncryptedDataPacket struct {
	Data      string
	Signature string
}

// NewDataTransferProtocol initializes a new data transfer protocol with AES encryption.
func NewDataTransferProtocol(version string, key []byte) *DataTransferProtocol {
	return &DataTransferProtocol{
		ProtocolVersion: version,
		EncryptionKey:   key,
	}
}

// EncryptData encrypts data using AES-256-GCM.
func (dtp *DataTransferProtocol) EncryptData(data []byte) (*EncryptedDataPacket, error) {
	block, err := aes.NewCipher(dtp.EncryptionKey)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create cipher block")
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create GCM")
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, errors.Wrap(err, "failed to generate nonce")
	}

	cipherText := gcm.Seal(nonce, nonce, data, nil)
	encodedData := base64.StdEncoding.EncodeToString(cipherText)
	return &EncryptedDataPacket{Data: encodedData}, nil
}

// DecryptData decrypts data from an encrypted packet.
func (dtp *DataTransferProtocol) DecryptData(packet *EncryptedDataPacket) ([]byte, error) {
	data, err := base64.StdEncoding.DecodeString(packet.Data)
	if err != nil {
		return nil, errors.Wrap(err, "failed to decode base64 data")
	}

	block, err := aes.NewCipher(dtp.EncryptionKey)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create cipher block")
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create GCM")
	}

	if len(data) < gcm.NonceSize() {
		return nil, errors.New("ciphertext too short")
	}

	nonce, ciphertext := data[:gcm.NonceSize()], data[gcm.NonceSize():]
	decryptedData, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, errors.Wrap(err, "failed to decrypt data")
	}

	return decryptedData, nil
}
