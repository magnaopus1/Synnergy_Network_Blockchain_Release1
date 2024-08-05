package ledger

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
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"golang.org/x/crypto/argon2"
	"pkg/synnergy_network/core/tokens/token_standards/syn1967/assets"
)

// LedgerEntry represents a single entry in the blockchain ledger
type LedgerEntry struct {
	EntryID        string
	TokenID        string
	TransactionID  string
	Timestamp      time.Time
	Operation      string
	Details        string
	PreviousHash   string
	Hash           string
}

// BlockchainLedger manages the ledger entries
type BlockchainLedger struct {
	entries map[string]LedgerEntry
}

// NewBlockchainLedger creates a new blockchain ledger
func NewBlockchainLedger() *BlockchainLedger {
	return &BlockchainLedger{entries: make(map[string]LedgerEntry)}
}

// AddEntry adds a new entry to the ledger
func (l *BlockchainLedger) AddEntry(entry LedgerEntry) error {
	entry.Timestamp = time.Now()
	entry.Hash = l.generateHash(entry)
	l.entries[entry.EntryID] = entry
	return nil
}

// GetEntry retrieves an entry by its ID
func (l *BlockchainLedger) GetEntry(entryID string) (LedgerEntry, error) {
	entry, exists := l.entries[entryID]
	if !exists {
		return LedgerEntry{}, errors.New("entry not found")
	}
	return entry, nil
}

// ListEntries lists all entries in the ledger
func (l *BlockchainLedger) ListEntries() ([]LedgerEntry, error) {
	var entries []LedgerEntry
	for _, entry := range l.entries {
		entries = append(entries, entry)
	}
	return entries, nil
}

// generateHash generates a hash for a ledger entry
func (l *BlockchainLedger) generateHash(entry LedgerEntry) string {
	record := fmt.Sprintf("%s%s%s%s%s", entry.EntryID, entry.TokenID, entry.TransactionID, entry.Timestamp.String(), entry.Operation)
	hash := sha256.New()
	hash.Write([]byte(record))
	return hex.EncodeToString(hash.Sum(nil))
}

// ValidateLedger validates the integrity of the ledger
func (l *BlockchainLedger) ValidateLedger() (bool, error) {
	for _, entry := range l.entries {
		expectedHash := l.generateHash(entry)
		if entry.Hash != expectedHash {
			return false, fmt.Errorf("hash mismatch for entry %s", entry.EntryID)
		}
	}
	return true, nil
}

// SecureStorage handles secure storage of data
type SecureStorage struct {
	key []byte
}

// NewSecureStorage creates a new secure storage with a key
func NewSecureStorage(password string) *SecureStorage {
	salt := make([]byte, 16)
	_, err := rand.Read(salt)
	if err != nil {
		panic(err)
	}

	key := argon2.Key([]byte(password), salt, 3, 32*1024, 4, 32)
	return &SecureStorage{key: key}
}

// Encrypt encrypts data using AES
func (s *SecureStorage) Encrypt(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(s.key)
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

// Decrypt decrypts data using AES
func (s *SecureStorage) Decrypt(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(s.key)
	if err != nil {
		return nil, err
	}

	if len(data) < aes.BlockSize {
		return nil, errors.New("ciphertext too short")
	}

	iv := data[:aes.BlockSize]
	ciphertext := data[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(ciphertext, ciphertext)

	return ciphertext, nil
}

// SecureLedgerData securely stores ledger data
func (l *BlockchainLedger) SecureLedgerData(secureStorage *SecureStorage) (string, error) {
	jsonData, err := json.Marshal(l.entries)
	if err != nil {
		return "", err
	}

	encryptedData, err := secureStorage.Encrypt(jsonData)
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("%x", encryptedData), nil
}

// RetrieveLedgerData retrieves and decrypts ledger data
func (l *BlockchainLedger) RetrieveLedgerData(encryptedDataHex string, secureStorage *SecureStorage) error {
	encryptedData, err := hex.DecodeString(encryptedDataHex)
	if err != nil {
		return err
	}

	jsonData, err := secureStorage.Decrypt(encryptedData)
	if err != nil {
		return err
	}

	var entries map[string]LedgerEntry
	err = json.Unmarshal(jsonData, &entries)
	if err != nil {
		return err
	}

	l.entries = entries
	return nil
}

// GenerateComplianceReport generates a compliance report for the ledger
func (l *BlockchainLedger) GenerateComplianceReport() (string, error) {
	report := "Compliance Report for Blockchain Ledger\n"
	report += "--------------------------------------\n"

	for _, entry := range l.entries {
		report += fmt.Sprintf("Entry ID: %s\nToken ID: %s\nTransaction ID: %s\nTimestamp: %s\nOperation: %s\nDetails: %s\nHash: %s\nPrevious Hash: %s\n\n",
			entry.EntryID, entry.TokenID, entry.TransactionID, entry.Timestamp.String(), entry.Operation, entry.Details, entry.Hash, entry.PreviousHash)
	}

	return report, nil
}
