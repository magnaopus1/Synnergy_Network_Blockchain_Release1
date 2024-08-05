package security

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"time"

	"golang.org/x/crypto/scrypt"
)

// Security represents the security configurations and methods for the node
type Security struct {
	tlsCertFile string
	tlsKeyFile  string
}

// Initialize initializes the security configuration
func (s *Security) Initialize(tlsCertFile, tlsKeyFile string) {
	s.tlsCertFile = tlsCertFile
	s.tlsKeyFile = tlsKeyFile
}

// LoadTLSConfig loads the TLS configuration
func (s *Security) LoadTLSConfig() (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(s.tlsCertFile, s.tlsKeyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load TLS certificates: %v", err)
	}

	return &tls.Config{Certificates: []tls.Certificate{cert}}, nil
}

// Encrypt encrypts data using AES
func (s *Security) Encrypt(data, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher block: %v", err)
	}

	ciphertext := make([]byte, aes.BlockSize+len(data))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, fmt.Errorf("failed to generate IV: %v", err)
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], data)

	return ciphertext, nil
}

// Decrypt decrypts data using AES
func (s *Security) Decrypt(ciphertext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher block: %v", err)
	}

	if len(ciphertext) < aes.BlockSize {
		return nil, errors.New("ciphertext too short")
	}

	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(ciphertext, ciphertext)

	return ciphertext, nil
}

// GenerateKey generates a random key for encryption
func (s *Security) GenerateKey() ([]byte, error) {
	key := make([]byte, 32) // 256-bit key
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("failed to generate random key: %v", err)
	}

	return key, nil
}

// HashData hashes data using scrypt
func (s *Security) HashData(data []byte) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("failed to generate salt: %v", err)
	}

	hash, err := scrypt.Key(data, salt, 1<<15, 8, 1, 32)
	if err != nil {
		return "", fmt.Errorf("failed to hash data: %v", err)
	}

	return fmt.Sprintf("%x$%x", salt, hash), nil
}

// VerifyHash verifies data against a hashed value using scrypt
func (s *Security) VerifyHash(data []byte, hashedValue string) (bool, error) {
	parts := splitHash(hashedValue)
	if len(parts) != 2 {
		return false, errors.New("invalid hash format")
	}

	salt, err := hex.DecodeString(parts[0])
	if err != nil {
		return false, fmt.Errorf("failed to decode salt: %v", err)
	}

	expectedHash, err := hex.DecodeString(parts[1])
	if err != nil {
		return false, fmt.Errorf("failed to decode hash: %v", err)
	}

	hash, err := scrypt.Key(data, salt, 1<<15, 8, 1, 32)
	if err != nil {
		return false, fmt.Errorf("failed to hash data: %v", err)
	}

	return string(hash) == string(expectedHash), nil
}

// splitHash splits the hash into salt and hash parts
func splitHash(hash string) []string {
	return splitAt(hash, '$')
}

// splitAt splits a string at the first occurrence of sep
func splitAt(s string, sep byte) []string {
	for i := 0; i < len(s); i++ {
		if s[i] == sep {
			return []string{s[:i], s[i+1:]}
		}
	}
	return []string{s}
}

// PerformSecurityAudit performs a security audit and logs the results
func (s *Security) PerformSecurityAudit() {
	log.Println("Performing security audit...")
	// Placeholder for performing actual security audit checks
	log.Println("Security audit completed.")
}

// UpdateFirewallRules updates the firewall rules based on predetermined security rules
func (s *Security) UpdateFirewallRules() error {
	// Placeholder for updating firewall rules
	log.Println("Updating firewall rules...")
	return nil
}

// BackupSecurityFiles creates backups of the security files
func (s *Security) BackupSecurityFiles(backupDir string) error {
	timestamp := time.Now().Format("20060102150405")
	keyBackupPath := fmt.Sprintf("%s/tls_key_%s.pem", backupDir, timestamp)
	certBackupPath := fmt.Sprintf("%s/tls_cert_%s.pem", backupDir, timestamp)

	if err := copyFile(s.tlsKeyFile, keyBackupPath); err != nil {
		return fmt.Errorf("failed to backup key file: %v", err)
	}
	if err := copyFile(s.tlsCertFile, certBackupPath); err != nil {
		return fmt.Errorf("failed to backup cert file: %v", err)
	}

	log.Println("Security files backup completed.")
	return nil
}

// copyFile copies a file from src to dst
func copyFile(src, dst string) error {
	sourceFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer sourceFile.Close()

	destinationFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer destinationFile.Close()

	if _, err := io.Copy(destinationFile, sourceFile); err != nil {
		return err
	}

	return nil
}
