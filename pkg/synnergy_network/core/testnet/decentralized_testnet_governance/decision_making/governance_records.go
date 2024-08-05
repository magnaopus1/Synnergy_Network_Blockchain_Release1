package decision_making

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"time"
)

// GovernanceRecord represents a record of a governance decision.
type GovernanceRecord struct {
	ID           string
	Timestamp    time.Time
	ProposalID   string
	Decision     string
	VotesFor     int
	VotesAgainst int
	Notes        string
}

// GovernanceRecordsManager handles the management of governance records.
type GovernanceRecordsManager struct {
	records map[string]GovernanceRecord
	key     []byte
}

// NewGovernanceRecordsManager initializes a new GovernanceRecordsManager with encryption key.
func NewGovernanceRecordsManager(encryptionKey string) *GovernanceRecordsManager {
	hashedKey := sha256.Sum256([]byte(encryptionKey))
	return &GovernanceRecordsManager{
		records: make(map[string]GovernanceRecord),
		key:     hashedKey[:],
	}
}

// AddRecord adds a new governance record to the manager.
func (mgr *GovernanceRecordsManager) AddRecord(proposalID, decision string, votesFor, votesAgainst int, notes string) (string, error) {
	id := generateID()
	record := GovernanceRecord{
		ID:           id,
		Timestamp:    time.Now(),
		ProposalID:   proposalID,
		Decision:     decision,
		VotesFor:     votesFor,
		VotesAgainst: votesAgainst,
		Notes:        notes,
	}
	encryptedRecord, err := mgr.encryptRecord(record)
	if err != nil {
		return "", err
	}
	mgr.records[id] = encryptedRecord
	return id, nil
}

// GetRecord retrieves a governance record by its ID.
func (mgr *GovernanceRecordsManager) GetRecord(id string) (GovernanceRecord, error) {
	record, exists := mgr.records[id]
	if !exists {
		return GovernanceRecord{}, errors.New("record not found")
	}
	return mgr.decryptRecord(record)
}

// GetAllRecords retrieves all governance records.
func (mgr *GovernanceRecordsManager) GetAllRecords() ([]GovernanceRecord, error) {
	var records []GovernanceRecord
	for _, record := range mgr.records {
		decryptedRecord, err := mgr.decryptRecord(record)
		if err != nil {
			return nil, err
		}
		records = append(records, decryptedRecord)
	}
	return records, nil
}

// generateID generates a unique ID for a new governance record.
func generateID() string {
	b := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

// encryptRecord encrypts a governance record using AES encryption.
func (mgr *GovernanceRecordsManager) encryptRecord(record GovernanceRecord) (GovernanceRecord, error) {
	plaintext, err := encodeRecord(record)
	if err != nil {
		return GovernanceRecord{}, err
	}

	block, err := aes.NewCipher(mgr.key)
	if err != nil {
		return GovernanceRecord{}, err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return GovernanceRecord{}, err
	}

	nonce := make([]byte, aesGCM.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return GovernanceRecord{}, err
	}

	ciphertext := aesGCM.Seal(nonce, nonce, plaintext, nil)
	record.Notes = hex.EncodeToString(ciphertext)
	return record, nil
}

// decryptRecord decrypts a governance record using AES decryption.
func (mgr *GovernanceRecordsManager) decryptRecord(record GovernanceRecord) (GovernanceRecord, error) {
	ciphertext, err := hex.DecodeString(record.Notes)
	if err != nil {
		return GovernanceRecord{}, err
	}

	block, err := aes.NewCipher(mgr.key)
	if err != nil {
		return GovernanceRecord{}, err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return GovernanceRecord{}, err
	}

	nonceSize := aesGCM.NonceSize()
	if len(ciphertext) < nonceSize {
		return GovernanceRecord{}, errors.New("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return GovernanceRecord{}, err
	}

	return decodeRecord(plaintext)
}

// encodeRecord serializes a GovernanceRecord into a byte slice.
func encodeRecord(record GovernanceRecord) ([]byte, error) {
	return json.Marshal(record)
}

// decodeRecord deserializes a byte slice into a GovernanceRecord.
func decodeRecord(data []byte) (GovernanceRecord, error) {
	var record GovernanceRecord
	err := json.Unmarshal(data, &record)
	if err != nil {
		return GovernanceRecord{}, err
	}
	return record, nil
}

// DisplayRecord prints a governance record.
func (mgr *GovernanceRecordsManager) DisplayRecord(id string) error {
	record, err := mgr.GetRecord(id)
	if err != nil {
		return err
	}
	fmt.Printf("ID: %s\nTimestamp: %s\nProposalID: %s\nDecision: %s\nVotes For: %d\nVotes Against: %d\nNotes: %s\n",
		record.ID, record.Timestamp, record.ProposalID, record.Decision, record.VotesFor, record.VotesAgainst, record.Notes)
	return nil
}

// SaveRecordsToFile saves all governance records to a file.
func (mgr *GovernanceRecordsManager) SaveRecordsToFile(filename string) error {
	records, err := mgr.GetAllRecords()
	if err != nil {
		return err
	}

	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	for _, record := range records {
		if err := encoder.Encode(record); err != nil {
			return err
		}
	}

	return nil
}

// LoadRecordsFromFile loads governance records from a file.
func (mgr *GovernanceRecordsManager) LoadRecordsFromFile(filename string) error {
	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	for {
		var record GovernanceRecord
		if err := decoder.Decode(&record); err == io.EOF {
			break
		} else if err != nil {
			return err
		}
		mgr.records[record.ID] = record
	}

	return nil
}
