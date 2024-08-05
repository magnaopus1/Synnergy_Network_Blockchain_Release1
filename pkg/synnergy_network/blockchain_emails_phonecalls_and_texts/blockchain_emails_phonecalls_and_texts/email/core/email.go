package core


import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"net/mail"
	"net/smtp"
	"time"

	"golang.org/x/crypto/scrypt"
)

// Email represents the structure of an email message.
type Email struct {
	From      string    `json:"from"`
	To        []string  `json:"to"`
	Subject   string    `json:"subject"`
	Body      string    `json:"body"`
	Timestamp time.Time `json:"timestamp"`
}

// EncryptEmail encrypts the email body using AES with the given passphrase.
func EncryptEmail(body string, passphrase string) (string, error) {
	salt := make([]byte, 8)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return "", err
	}

	key, err := scrypt.Key([]byte(passphrase), salt, 16384, 8, 1, 32)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
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

	ciphertext := gcm.Seal(nonce, nonce, []byte(body), nil)
	return base64.StdEncoding.EncodeToString(append(salt, ciphertext...)), nil
}

// DecryptEmail decrypts the email body using AES with the given passphrase.
func DecryptEmail(encryptedBody string, passphrase string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(encryptedBody)
	if err != nil {
		return "", err
	}

	salt := data[:8]
	data = data[8:]

	key, err := scrypt.Key([]byte(passphrase), salt, 16384, 8, 1, 32)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonceSize := gcm.NonceSize()
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

// GenerateHash generates a SHA256 hash for the email.
func GenerateHash(email Email) string {
	data := fmt.Sprintf("%s%s%s%s", email.From, email.To, email.Subject, email.Body)
	hash := sha256.Sum256([]byte(data))
	return base64.StdEncoding.EncodeToString(hash[:])
}

// LogEmail logs the email metadata.
func LogEmail(email Email) {
	log.Printf("Email: From=%s, To=%s, Subject=%s, Timestamp=%s",
		email.From, email.To, email.Subject, email.Timestamp)
}

// SendEmail sends an email using the provided SMTP server configuration.
func SendEmail(email Email, smtpHost string, smtpPort int, smtpUser string, smtpPass string) error {
	from := mail.Address{Name: "", Address: email.From}
	to := make([]mail.Address, len(email.To))
	for i, addr := range email.To {
		to[i] = mail.Address{Name: "", Address: addr}
	}

	header := make(map[string]string)
	header["From"] = from.String()
	header["To"] = to[0].String()
	for _, addr := range to[1:] {
		header["To"] += ", " + addr.String()
	}
	header["Subject"] = email.Subject
	header["MIME-Version"] = "1.0"
	header["Content-Type"] = "text/plain; charset=\"utf-8\""

	message := ""
	for k, v := range header {
		message += fmt.Sprintf("%s: %s\r\n", k, v)
	}
	message += "\r\n" + email.Body

	auth := smtp.PlainAuth("", smtpUser, smtpPass, smtpHost)
	err := smtp.SendMail(fmt.Sprintf("%s:%d", smtpHost, smtpPort), auth, from.Address, email.To, []byte(message))
	if err != nil {
		return err
	}

	return nil
}

// ValidateEmail validates the email structure.
func ValidateEmail(email Email) error {
	if email.From == "" {
		return errors.New("from address is required")
	}
	if len(email.To) == 0 {
		return errors.New("at least one recipient is required")
	}
	if email.Subject == "" {
		return errors.New("subject is required")
	}
	if email.Body == "" {
		return errors.New("body is required")
	}
	return nil
}
