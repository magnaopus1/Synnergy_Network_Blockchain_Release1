package transactions

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"image/png"
	"io"
	"os"
	"time"

	"github.com/skip2/go-qrcode"
	"golang.org/x/crypto/scrypt"
)

// QRCodeTicketValidator handles the generation and validation of QR codes for event tickets
type QRCodeTicketValidator struct {
	aesKey []byte
	salt   []byte
}

// NewQRCodeTicketValidator creates a new instance of QRCodeTicketValidator
func NewQRCodeTicketValidator(passphrase string) (*QRCodeTicketValidator, error) {
	// Derive AES key from passphrase using scrypt
	salt := make([]byte, 16)
	_, err := io.ReadFull(rand.Reader, salt)
	if err != nil {
		return nil, err
	}

	key, err := scrypt.Key([]byte(passphrase), salt, 32768, 8, 1, 32)
	if err != nil {
		return nil, err
	}

	return &QRCodeTicketValidator{
		aesKey: key,
		salt:   salt,
	}, nil
}

// TicketData represents the data encoded in the QR code
type TicketData struct {
	EventID     string    `json:"event_id"`
	TicketID    string    `json:"ticket_id"`
	OwnerID     string    `json:"owner_id"`
	ValidUntil  time.Time `json:"valid_until"`
	IssuedAt    time.Time `json:"issued_at"`
	Signature   string    `json:"signature"`
}

// GenerateQRCode generates a QR code for the given ticket data
func (qv *QRCodeTicketValidator) GenerateQRCode(ticketData TicketData, filePath string) error {
	data, err := json.Marshal(ticketData)
	if err != nil {
		return err
	}

	encryptedData, err := qv.encrypt(data)
	if err != nil {
		return err
	}

	qrCode, err := qrcode.New(string(encryptedData), qrcode.High)
	if err != nil {
		return err
	}

	err = qrCode.WriteFile(256, filePath)
	if err != nil {
		return err
	}

	return nil
}

// ValidateQRCode validates the QR code and returns the decoded ticket data
func (qv *QRCodeTicketValidator) ValidateQRCode(filePath string) (*TicketData, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	img, err := png.Decode(file)
	if err != nil {
		return nil, err
	}

	qrCode, err := qrcode.Decode(img)
	if err != nil {
		return nil, err
	}

	decryptedData, err := qv.decrypt([]byte(qrCode.Content))
	if err != nil {
		return nil, err
	}

	var ticketData TicketData
	err = json.Unmarshal(decryptedData, &ticketData)
	if err != nil {
		return nil, err
	}

	// Verify the ticket validity
	if ticketData.ValidUntil.Before(time.Now()) {
		return nil, errors.New("ticket has expired")
	}

	return &ticketData, nil
}

// encrypt encrypts the data using AES-GCM
func (qv *QRCodeTicketValidator) encrypt(data []byte) (string, error) {
	block, err := aes.NewCipher(qv.aesKey)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	_, err = io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return "", err
	}

	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// decrypt decrypts the data using AES-GCM
func (qv *QRCodeTicketValidator) decrypt(data []byte) ([]byte, error) {
	decodedData, err := base64.StdEncoding.DecodeString(string(data))
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(qv.aesKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	if len(decodedData) < gcm.NonceSize() {
		return nil, errors.New("ciphertext too short")
	}

	nonce, ciphertext := decodedData[:gcm.NonceSize()], decodedData[gcm.NonceSize():]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

// Example usage
func main() {
	validator, err := NewQRCodeTicketValidator("your-passphrase")
	if err != nil {
		fmt.Println("Error creating validator:", err)
		return
	}

	ticketData := TicketData{
		EventID:    "event123",
		TicketID:   "ticket456",
		OwnerID:    "owner789",
		ValidUntil: time.Now().Add(24 * time.Hour),
		IssuedAt:   time.Now(),
		Signature:  "signature_example",
	}

	err = validator.GenerateQRCode(ticketData, "ticket_qr.png")
	if err != nil {
		fmt.Println("Error generating QR code:", err)
		return
	}

	decodedTicketData, err := validator.ValidateQRCode("ticket_qr.png")
	if err != nil {
		fmt.Println("Error validating QR code:", err)
		return
	}

	fmt.Printf("Decoded ticket data: %+v\n", decodedTicketData)
}
