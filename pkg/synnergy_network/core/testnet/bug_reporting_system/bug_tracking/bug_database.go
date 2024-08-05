package bug_tracking

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"
	"github.com/synnergy_network/encryption"
)

// Bug represents the structure of a bug report
type Bug struct {
	ID          string
	Title       string
	Description string
	Reporter    string
	Status      string
	Severity    string
	Timestamp   time.Time
}

// BugDatabase represents a database for storing and managing bugs
type BugDatabase struct {
	bugs map[string]Bug
	mu   sync.Mutex
}

// NewBugDatabase creates a new instance of BugDatabase
func NewBugDatabase() *BugDatabase {
	return &BugDatabase{
		bugs: make(map[string]Bug),
	}
}

// AddBug adds a new bug to the database
func (db *BugDatabase) AddBug(title, description, reporter, severity string) (string, error) {
	db.mu.Lock()
	defer db.mu.Unlock()

	id := generateBugID(title, description)
	if _, exists := db.bugs[id]; exists {
		return "", errors.New("bug with this ID already exists")
	}

	bug := Bug{
		ID:          id,
		Title:       title,
		Description: description,
		Reporter:    reporter,
		Status:      "open",
		Severity:    severity,
		Timestamp:   time.Now(),
	}

	db.bugs[id] = bug
	logBugAction("added", bug)
	return id, nil
}

// UpdateBug updates the details of an existing bug
func (db *BugDatabase) UpdateBug(id, title, description, status, severity string) error {
	db.mu.Lock()
	defer db.mu.Unlock()

	bug, exists := db.bugs[id]
	if !exists {
		return errors.New("bug not found")
	}

	bug.Title = title
	bug.Description = description
	bug.Status = status
	bug.Severity = severity
	db.bugs[id] = bug
	logBugAction("updated", bug)
	return nil
}

// GetBug retrieves the details of a bug by its ID
func (db *BugDatabase) GetBug(id string) (Bug, error) {
	db.mu.Lock()
	defer db.mu.Unlock()

	bug, exists := db.bugs[id]
	if !exists {
		return Bug{}, errors.New("bug not found")
	}
	return bug, nil
}

// ListBugs lists all bugs in the database
func (db *BugDatabase) ListBugs() []Bug {
	db.mu.Lock()
	defer db.mu.Unlock()

	var bugs []Bug
	for _, bug := range db.bugs {
		bugs = append(bugs, bug)
	}
	return bugs
}

// DeleteBug deletes a bug from the database
func (db *BugDatabase) DeleteBug(id string) error {
	db.mu.Lock()
	defer db.mu.Unlock()

	if _, exists := db.bugs[id]; !exists {
		return errors.New("bug not found")
	}

	delete(db.bugs, id)
	log.Printf("Bug %s deleted", id)
	return nil
}

// generateBugID generates a unique ID for a bug based on its title and description
func generateBugID(title, description string) string {
	data := title + description + time.Now().String()
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

// logBugAction logs actions performed on bugs
func logBugAction(action string, bug Bug) {
	log.Printf("Bug %s: %s - %s (Severity: %s, Status: %s)", action, bug.ID, bug.Title, bug.Severity, bug.Status)
}

// EncryptBugDescription encrypts the bug description using AES
func EncryptBugDescription(description string, key []byte) (string, error) {
	encrypted, err := encryption.AESEncrypt([]byte(description), key)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(encrypted), nil
}

// DecryptBugDescription decrypts the bug description using AES
func DecryptBugDescription(description string, key []byte) (string, error) {
	encrypted, err := hex.DecodeString(description)
	if err != nil {
		return "", err
	}
	decrypted, err := encryption.AESDecrypt(encrypted, key)
	if err != nil {
		return "", err
	}
	return string(decrypted), nil
}

// AI-Enhanced Bug Classification
func ClassifyBug(title, description string) string {
	// This function uses an AI model to classify the bug severity
	// Placeholder logic for AI classification
	if len(description) > 100 {
		return "high"
	}
	return "low"
}


