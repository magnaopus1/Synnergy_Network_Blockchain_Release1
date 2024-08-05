package cloud_integration

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
	"os"
	"time"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/scrypt"
)

// Constants for encryption and hashing
const (
	SaltSize        = 16
	AESKeySize      = 32
	ScryptN         = 1 << 15
	ScryptR         = 8
	ScryptP         = 1
	Argon2Time      = 1
	Argon2Memory    = 64 * 1024
	Argon2Threads   = 4
	Argon2KeyLength = 32
)

// GenerateSalt generates a random salt for cryptographic functions
func GenerateSalt(size int) ([]byte, error) {
	salt := make([]byte, size)
	_, err := rand.Read(salt)
	if err != nil {
		return nil, fmt.Errorf("failed to generate salt: %v", err)
	}
	return salt, nil
}

// HashPassword hashes a password using Argon2
func HashPassword(password string, salt []byte) string {
	hash := argon2.Key([]byte(password), salt, Argon2Time, Argon2Memory, Argon2Threads, Argon2KeyLength)
	return base64.StdEncoding.EncodeToString(hash)
}

// Encrypt encrypts plain text using AES with Scrypt key derivation
func Encrypt(plainText, password string) (string, error) {
	salt, err := GenerateSalt(SaltSize)
	if err != nil {
		return "", err
	}

	key, err := scrypt.Key([]byte(password), salt, ScryptN, ScryptR, ScryptP, AESKeySize)
	if err != nil {
		return "", fmt.Errorf("failed to derive key: %v", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %v", err)
	}

	ciphertext := make([]byte, aes.BlockSize+len(plainText))
	iv := ciphertext[:aes.BlockSize]

	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", fmt.Errorf("failed to generate IV: %v", err)
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], []byte(plainText))

	return base64.StdEncoding.EncodeToString(append(salt, ciphertext...)), nil
}

// Decrypt decrypts cipher text using AES with Scrypt key derivation
func Decrypt(cipherText, password string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(cipherText)
	if err != nil {
		return "", fmt.Errorf("failed to decode cipher text: %v", err)
	}

	salt := data[:SaltSize]
	ciphertext := data[SaltSize:]

	key, err := scrypt.Key([]byte(password), salt, ScryptN, ScryptR, ScryptP, AESKeySize)
	if err != nil {
		return "", fmt.Errorf("failed to derive key: %v", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %v", err)
	}

	if len(ciphertext) < aes.BlockSize {
		return "", fmt.Errorf("ciphertext too short")
	}

	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(ciphertext, ciphertext)

	return string(ciphertext), nil
}

// HashSHA256 generates a SHA-256 hash of the input
func HashSHA256(data string) string {
	hash := sha256.Sum256([]byte(data))
	return base64.StdEncoding.EncodeToString(hash[:])
}

// GenerateUUID generates a random UUID
func GenerateUUID() (string, error) {
	uuid := make([]byte, 16)
	_, err := rand.Read(uuid)
	if err != nil {
		return "", fmt.Errorf("failed to generate UUID: %v", err)
	}
	uuid[8] = uuid[8]&^0xc0 | 0x80
	uuid[6] = uuid[6]&^0xf0 | 0x40
	return fmt.Sprintf("%x-%x-%x-%x-%x", uuid[0:4], uuid[4:6], uuid[6:8], uuid[8:10], uuid[10:]), nil
}

// LogAndPanic logs the error and panics
func LogAndPanic(err error) {
	if err != nil {
		log.Panicf("Critical error: %v", err)
	}
}

// AccessControl struct to manage user permissions
type AccessControl struct {
	Permissions map[string][]string // map[username][]permissions
}

// NewAccessControl initializes a new AccessControl
func NewAccessControl() *AccessControl {
	return &AccessControl{
		Permissions: make(map[string][]string),
	}
}

// GrantPermission grants a permission to a user
func (ac *AccessControl) GrantPermission(username, permission string) {
	ac.Permissions[username] = append(ac.Permissions[username], permission)
}

// RevokePermission revokes a permission from a user
func (ac *AccessControl) RevokePermission(username, permission string) {
	permissions := ac.Permissions[username]
	for i, p := range permissions {
		if p == permission {
			ac.Permissions[username] = append(permissions[:i], permissions[i+1:]...)
			break
		}
	}
}

// HasPermission checks if a user has a specific permission
func (ac *AccessControl) HasPermission(username, permission string) bool {
	for _, p := range ac.Permissions[username] {
		if p == permission {
			return true
		}
	}
	return false
}

// AuditLog struct to manage audit logging
type AuditLog struct {
	Entries []AuditEntry
}

// AuditEntry represents a single audit log entry
type AuditEntry struct {
	Timestamp time.Time
	User      string
	Action    string
	Details   string
}

// NewAuditLog initializes a new AuditLog
func NewAuditLog() *AuditLog {
	return &AuditLog{
		Entries: []AuditEntry{},
	}
}

// LogEntry logs a new entry to the audit log
func (al *AuditLog) LogEntry(user, action, details string) {
	entry := AuditEntry{
		Timestamp: time.Now(),
		User:      user,
		Action:    action,
		Details:   details,
	}
	al.Entries = append(al.Entries, entry)
}

// SaveToFile saves the audit log to a file
func (al *AuditLog) SaveToFile(filePath string) error {
	file, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("failed to create audit log file: %v", err)
	}
	defer file.Close()

	for _, entry := range al.Entries {
		line := fmt.Sprintf("%s | %s | %s | %s\n", entry.Timestamp.Format(time.RFC3339), entry.User, entry.Action, entry.Details)
		if _, err := file.WriteString(line); err != nil {
			return fmt.Errorf("failed to write to audit log file: %v", err)
		}
	}
	return nil
}

// LoadFromFile loads the audit log from a file
func (al *AuditLog) LoadFromFile(filePath string) error {
	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("failed to open audit log file: %v", err)
	}
	defer file.Close()

	var entries []AuditEntry
	for {
		var entry AuditEntry
		_, err := fmt.Fscanf(file, "%s | %s | %s | %s\n", &entry.Timestamp, &entry.User, &entry.Action, &entry.Details)
		if err != nil {
			break
		}
		entries = append(entries, entry)
	}
	al.Entries = entries
	return nil
}

// SecureStorage struct to manage secure data storage
type SecureStorage struct {
	data map[string]string
}

// NewSecureStorage initializes a new SecureStorage
func NewSecureStorage() *SecureStorage {
	return &SecureStorage{
		data: make(map[string]string),
	}
}

// Store securely stores data
func (ss *SecureStorage) Store(key, value, password string) error {
	encryptedValue, err := Encrypt(value, password)
	if err != nil {
		return fmt.Errorf("failed to encrypt data: %v", err)
	}
	ss.data[key] = encryptedValue
	return nil
}

// Retrieve securely retrieves data
func (ss *SecureStorage) Retrieve(key, password string) (string, error) {
	encryptedValue, exists := ss.data[key]
	if !exists {
		return "", errors.New("data not found")
	}

	value, err := Decrypt(encryptedValue, password)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt data: %v", err)
	}
	return value, nil
}
