package storage

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"sync"

	"golang.org/x/crypto/scrypt"
)

// Database represents a mock database structure for storing SYN3000 tokens and related data
type Database struct {
	mu            sync.RWMutex
	rentalTokens  map[string]RentalToken
	propertyData  map[string]Property
	transactions  map[string]Transaction
	owners        map[string]Owner
	compliance    map[string]ComplianceRecord
	encryptionKey []byte
}

// RentalToken represents a rental token
type RentalToken struct {
	TokenID       string
	PropertyID    string
	TenantID      string
	LeaseStart    string
	LeaseEnd      string
	MonthlyRent   float64
	Deposit       float64
	IssuedDate    string
	ActiveStatus  bool
	LastUpdate    string
}

// Property represents property details
type Property struct {
	PropertyID   string
	Address      string
	OwnerID      string
	Description  string
	Bedrooms     int
	Bathrooms    int
	SquareFootage int
	Availability bool
}

// Transaction represents a transaction record
type Transaction struct {
	TransactionID   string
	TokenID         string
	Timestamp       string
	TransactionType string
	Details         string
}

// Owner represents an owner record
type Owner struct {
	OwnerID    string
	OwnerName  string
	Properties []string
}

// ComplianceRecord represents a compliance record
type ComplianceRecord struct {
	RecordID    string
	Description string
	Timestamp   string
	Status      string
}

// NewDatabase initializes a new mock database
func NewDatabase(password string) (*Database, error) {
	key, err := generateEncryptionKey(password)
	if err != nil {
		return nil, fmt.Errorf("failed to generate encryption key: %v", err)
	}

	return &Database{
		rentalTokens:  make(map[string]RentalToken),
		propertyData:  make(map[string]Property),
		transactions:  make(map[string]Transaction),
		owners:        make(map[string]Owner),
		compliance:    make(map[string]ComplianceRecord),
		encryptionKey: key,
	}, nil
}

// generateEncryptionKey generates an encryption key using scrypt
func generateEncryptionKey(password string) ([]byte, error) {
	salt := make([]byte, 16)
	_, err := rand.Read(salt)
	if err != nil {
		return nil, err
	}

	key, err := scrypt.Key([]byte(password), salt, 16384, 8, 1, 32)
	if err != nil {
		return nil, err
	}

	return key, nil
}

// encrypt encrypts the given plaintext using AES
func (db *Database) encrypt(plaintext string) (string, error) {
	block, err := aes.NewCipher(db.encryptionKey)
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

	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// decrypt decrypts the given ciphertext using AES
func (db *Database) decrypt(ciphertext string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(db.encryptionKey)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	if len(data) < gcm.NonceSize() {
		return "", errors.New("malformed ciphertext")
	}

	nonce, ciphertext := data[:gcm.NonceSize()], data[gcm.NonceSize():]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

// AddRentalToken adds a rental token to the database
func (db *Database) AddRentalToken(token RentalToken) error {
	db.mu.Lock()
	defer db.mu.Unlock()

	tokenData, err := db.encrypt(fmt.Sprintf("%v", token))
	if err != nil {
		return fmt.Errorf("failed to encrypt rental token: %v", err)
	}

	db.rentalTokens[token.TokenID] = token
	fmt.Printf("Rental token added: %s\n", tokenData)
	return nil
}

// GetRentalToken retrieves a rental token by ID
func (db *Database) GetRentalToken(tokenID string) (RentalToken, error) {
	db.mu.RLock()
	defer db.mu.RUnlock()

	token, exists := db.rentalTokens[tokenID]
	if !exists {
		return RentalToken{}, errors.New("rental token not found")
	}

	return token, nil
}

// UpdateRentalToken updates a rental token in the database
func (db *Database) UpdateRentalToken(token RentalToken) error {
	db.mu.Lock()
	defer db.mu.Unlock()

	_, exists := db.rentalTokens[token.TokenID]
	if !exists {
		return errors.New("rental token not found")
	}

	tokenData, err := db.encrypt(fmt.Sprintf("%v", token))
	if err != nil {
		return fmt.Errorf("failed to encrypt rental token: %v", err)
	}

	db.rentalTokens[token.TokenID] = token
	fmt.Printf("Rental token updated: %s\n", tokenData)
	return nil
}

// AddProperty adds a property to the database
func (db *Database) AddProperty(property Property) error {
	db.mu.Lock()
	defer db.mu.Unlock()

	propertyData, err := db.encrypt(fmt.Sprintf("%v", property))
	if err != nil {
		return fmt.Errorf("failed to encrypt property: %v", err)
	}

	db.propertyData[property.PropertyID] = property
	fmt.Printf("Property added: %s\n", propertyData)
	return nil
}

// GetProperty retrieves a property by ID
func (db *Database) GetProperty(propertyID string) (Property, error) {
	db.mu.RLock()
	defer db.mu.RUnlock()

	property, exists := db.propertyData[propertyID]
	if !exists {
		return Property{}, errors.New("property not found")
	}

	return property, nil
}

// UpdateProperty updates a property in the database
func (db *Database) UpdateProperty(property Property) error {
	db.mu.Lock()
	defer db.mu.Unlock()

	_, exists := db.propertyData[property.PropertyID]
	if !exists {
		return errors.New("property not found")
	}

	propertyData, err := db.encrypt(fmt.Sprintf("%v", property))
	if err != nil {
		return fmt.Errorf("failed to encrypt property: %v", err)
	}

	db.propertyData[property.PropertyID] = property
	fmt.Printf("Property updated: %s\n", propertyData)
	return nil
}

// AddTransaction adds a transaction to the database
func (db *Database) AddTransaction(transaction Transaction) error {
	db.mu.Lock()
	defer db.mu.Unlock()

	transactionData, err := db.encrypt(fmt.Sprintf("%v", transaction))
	if err != nil {
		return fmt.Errorf("failed to encrypt transaction: %v", err)
	}

	db.transactions[transaction.TransactionID] = transaction
	fmt.Printf("Transaction added: %s\n", transactionData)
	return nil
}

// GetTransaction retrieves a transaction by ID
func (db *Database) GetTransaction(transactionID string) (Transaction, error) {
	db.mu.RLock()
	defer db.mu.RUnlock()

	transaction, exists := db.transactions[transactionID]
	if !exists {
		return Transaction{}, errors.New("transaction not found")
	}

	return transaction, nil
}

// AddOwner adds an owner to the database
func (db *Database) AddOwner(owner Owner) error {
	db.mu.Lock()
	defer db.mu.Unlock()

	ownerData, err := db.encrypt(fmt.Sprintf("%v", owner))
	if err != nil {
		return fmt.Errorf("failed to encrypt owner: %v", err)
	}

	db.owners[owner.OwnerID] = owner
	fmt.Printf("Owner added: %s\n", ownerData)
	return nil
}

// GetOwner retrieves an owner by ID
func (db *Database) GetOwner(ownerID string) (Owner, error) {
	db.mu.RLock()
	defer db.mu.RUnlock()

	owner, exists := db.owners[ownerID]
	if !exists {
		return Owner{}, errors.New("owner not found")
	}

	return owner, nil
}

// AddComplianceRecord adds a compliance record to the database
func (db *Database) AddComplianceRecord(record ComplianceRecord) error {
	db.mu.Lock()
	defer db.mu.Unlock()

	complianceData, err := db.encrypt(fmt.Sprintf("%v", record))
	if err != nil {
		return fmt.Errorf("failed to encrypt compliance record: %v", err)
	}

	db.compliance[record.RecordID] = record
	fmt.Printf("Compliance record added: %s\n", complianceData)
	return nil
}

// GetComplianceRecord retrieves a compliance record by ID
func (db *Database) GetComplianceRecord(recordID string) (ComplianceRecord, error) {
	db.mu.RLock()
	defer db.mu.RUnlock()

	record, exists := db.compliance[recordID]
	if !exists {
		return ComplianceRecord{}, errors.New("compliance record not found")
	}

	return record, nil
}
