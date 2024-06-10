package compliance

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"time"

	"golang.org/x/crypto/argon2"
)

// AuditTrail represents a single audit trail entry
type AuditTrail struct {
	Timestamp   time.Time
	UserID      string
	Action      string
	Description string
}

// AuditService handles the creation, encryption, decryption, and storage of audit trails
type AuditService struct {
	Passphrase string
	FilePath   string
}

// NewAuditService creates a new instance of AuditService
func NewAuditService(passphrase, filePath string) *AuditService {
	return &AuditService{
		Passphrase: passphrase,
		FilePath:   filePath,
	}
}

// LogAction logs an action into the audit trail
func (as *AuditService) LogAction(userID, action, description string) error {
	entry := AuditTrail{
		Timestamp:   time.Now(),
		UserID:      userID,
		Action:      action,
		Description: description,
	}
	encryptedEntry, err := as.encryptAuditTrail(entry)
	if err != nil {
		return err
	}
	return as.storeAuditTrail(encryptedEntry)
}

// encryptAuditTrail encrypts an audit trail entry using AES with Argon2 key derivation
func (as *AuditService) encryptAuditTrail(trail AuditTrail) (string, error) {
	salt := generateSalt()
	key := argon2.IDKey([]byte(as.Passphrase), salt, 1, 64*1024, 4, 32)

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

	plaintext := fmt.Sprintf("%v:%s:%s:%s", trail.Timestamp, trail.UserID, trail.Action, trail.Description)
	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return fmt.Sprintf("%x:%x", salt, ciphertext), nil
}

// decryptAuditTrail decrypts an encrypted audit trail entry
func (as *AuditService) decryptAuditTrail(encryptedTrail string) (AuditTrail, error) {
	parts := splitString(encryptedTrail, ":")
	if len(parts) != 2 {
		return AuditTrail{}, errors.New("invalid encrypted audit trail format")
	}

	salt, err := hex.DecodeString(parts[0])
	if err != nil {
		return AuditTrail{}, err
	}

	ciphertext, err := hex.DecodeString(parts[1])
	if err != nil {
		return AuditTrail{}, err
	}

	key := argon2.IDKey([]byte(as.Passphrase), salt, 1, 64*1024, 4, 32)

	block, err := aes.NewCipher(key)
	if err != nil {
		return AuditTrail{}, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return AuditTrail{}, err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return AuditTrail{}, errors.New("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return AuditTrail{}, err
	}

	trailParts := splitString(string(plaintext), ":")
	if len(trailParts) != 4 {
		return AuditTrail{}, errors.New("invalid decrypted audit trail format")
	}

	timestamp, err := time.Parse(time.RFC3339, trailParts[0])
	if err != nil {
		return AuditTrail{}, err
	}

	return AuditTrail{
		Timestamp:   timestamp,
		UserID:      trailParts[1],
		Action:      trailParts[2],
		Description: trailParts[3],
	}, nil
}

// storeAuditTrail stores an encrypted audit trail entry in a file
func (as *AuditService) storeAuditTrail(encryptedTrail string) error {
	file, err := os.OpenFile(as.FilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer file.Close()

	if _, err := file.WriteString(encryptedTrail + "\n"); err != nil {
		return err
	}
	return nil
}

// ListAuditTrails lists and decrypts all audit trails from the file
func (as *AuditService) ListAuditTrails() ([]AuditTrail, error) {
	file, err := os.Open(as.FilePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var trails []AuditTrail
	var encryptedTrail string
	for {
		_, err := fmt.Fscanf(file, "%s\n", &encryptedTrail)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}

		trail, err := as.decryptAuditTrail(encryptedTrail)
		if err != nil {
			log.Printf("Skipping corrupted audit trail entry: %v", err)
			continue
		}

		trails = append(trails, trail)
	}
	return trails, nil
}

// generateSalt generates a new random salt
func generateSalt() []byte {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		panic(err)
	}
	return salt
}

// splitString splits a string by a separator
func splitString(str, sep string) []string {
	var result []string
	part := ""
	for _, char := range str {
		if string(char) == sep {
			result = append(result, part)
			part = ""
		} else {
			part += string(char)
		}
	}
	result = append(result, part)
	return result
}
