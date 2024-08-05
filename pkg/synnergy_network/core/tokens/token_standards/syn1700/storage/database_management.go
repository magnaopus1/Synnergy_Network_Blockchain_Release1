package storage

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"io"

	_ "github.com/lib/pq"
	"golang.org/x/crypto/scrypt"
	"log"
	"sync"
)

// DatabaseManager handles all database-related operations
type DatabaseManager struct {
	mu      sync.Mutex
	db      *sql.DB
	aesKey  []byte
	salt    []byte
}

// NewDatabaseManager creates a new instance of DatabaseManager
func NewDatabaseManager(connectionString string, passphrase string) (*DatabaseManager, error) {
	db, err := sql.Open("postgres", connectionString)
	if err != nil {
		return nil, err
	}

	// Derive AES key from passphrase using scrypt
	salt := make([]byte, 16)
	_, err = io.ReadFull(rand.Reader, salt)
	if err != nil {
		return nil, err
	}

	key, err := scrypt.Key([]byte(passphrase), salt, 32768, 8, 1, 32)
	if err != nil {
		return nil, err
	}

	return &DatabaseManager{
		db:     db,
		aesKey: key,
		salt:   salt,
	}, nil
}

// Close closes the database connection
func (dm *DatabaseManager) Close() error {
	dm.mu.Lock()
	defer dm.mu.Unlock()
	return dm.db.Close()
}

// CreateTables creates the necessary tables for the SYN1700 token standard
func (dm *DatabaseManager) CreateTables() error {
	dm.mu.Lock()
	defer dm.mu.Unlock()

	tableCreationQueries := []string{
		`CREATE TABLE IF NOT EXISTS events (
			event_id SERIAL PRIMARY KEY,
			name TEXT,
			description TEXT,
			location TEXT,
			start_time TIMESTAMP,
			end_time TIMESTAMP,
			ticket_supply INT
		)`,
		`CREATE TABLE IF NOT EXISTS tickets (
			ticket_id SERIAL PRIMARY KEY,
			event_id INT REFERENCES events(event_id),
			event_name TEXT,
			date TIMESTAMP,
			price DECIMAL,
			class TEXT,
			type TEXT,
			special_conditions TEXT
		)`,
		`CREATE TABLE IF NOT EXISTS ownership_records (
			record_id SERIAL PRIMARY KEY,
			ticket_id INT REFERENCES tickets(ticket_id),
			owner TEXT,
			transfer_date TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS compliance_records (
			compliance_id SERIAL PRIMARY KEY,
			ticket_id INT REFERENCES tickets(ticket_id),
			compliance_details TEXT
		)`,
	}

	for _, query := range tableCreationQueries {
		if _, err := dm.db.Exec(query); err != nil {
			return err
		}
	}

	return nil
}

// InsertEvent inserts a new event into the events table
func (dm *DatabaseManager) InsertEvent(name, description, location string, startTime, endTime string, ticketSupply int) error {
	dm.mu.Lock()
	defer dm.mu.Unlock()

	_, err := dm.db.Exec(`INSERT INTO events (name, description, location, start_time, end_time, ticket_supply) VALUES ($1, $2, $3, $4, $5, $6)`,
		name, description, location, startTime, endTime, ticketSupply)
	return err
}

// InsertTicket inserts a new ticket into the tickets table
func (dm *DatabaseManager) InsertTicket(eventID int, eventName, date string, price float64, class, ticketType, specialConditions string) error {
	dm.mu.Lock()
	defer dm.mu.Unlock()

	_, err := dm.db.Exec(`INSERT INTO tickets (event_id, event_name, date, price, class, type, special_conditions) VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		eventID, eventName, date, price, class, ticketType, specialConditions)
	return err
}

// InsertOwnershipRecord inserts a new ownership record into the ownership_records table
func (dm *DatabaseManager) InsertOwnershipRecord(ticketID int, owner, transferDate string) error {
	dm.mu.Lock()
	defer dm.mu.Unlock()

	_, err := dm.db.Exec(`INSERT INTO ownership_records (ticket_id, owner, transfer_date) VALUES ($1, $2, $3)`,
		ticketID, owner, transferDate)
	return err
}

// InsertComplianceRecord inserts a new compliance record into the compliance_records table
func (dm *DatabaseManager) InsertComplianceRecord(ticketID int, complianceDetails string) error {
	dm.mu.Lock()
	defer dm.mu.Unlock()

	encryptedDetails, err := dm.encrypt(complianceDetails)
	if err != nil {
		return err
	}

	_, err = dm.db.Exec(`INSERT INTO compliance_records (ticket_id, compliance_details) VALUES ($1, $2)`,
		ticketID, encryptedDetails)
	return err
}

// encrypt encrypts a string using AES-GCM
func (dm *DatabaseManager) encrypt(plaintext string) (string, error) {
	block, err := aes.NewCipher(dm.aesKey)
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

	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// decrypt decrypts a string using AES-GCM
func (dm *DatabaseManager) decrypt(ciphertext string) (string, error) {
	block, err := aes.NewCipher(dm.aesKey)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	data, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}

	if len(data) < gcm.NonceSize() {
		return "", errors.New("ciphertext too short")
	}

	nonce, ciphertext := data[:gcm.NonceSize()], data[gcm.NonceSize():]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

// GetEvent retrieves an event from the database by ID
func (dm *DatabaseManager) GetEvent(eventID int) (map[string]interface{}, error) {
	dm.mu.Lock()
	defer dm.mu.Unlock()

	row := dm.db.QueryRow(`SELECT * FROM events WHERE event_id = $1`, eventID)

	var id int
	var name, description, location, startTime, endTime string
	var ticketSupply int
	err := row.Scan(&id, &name, &description, &location, &startTime, &endTime, &ticketSupply)
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"event_id":     id,
		"name":         name,
		"description":  description,
		"location":     location,
		"start_time":   startTime,
		"end_time":     endTime,
		"ticket_supply": ticketSupply,
	}, nil
}

// GetTicket retrieves a ticket from the database by ID
func (dm *DatabaseManager) GetTicket(ticketID int) (map[string]interface{}, error) {
	dm.mu.Lock()
	defer dm.mu.Unlock()

	row := dm.db.QueryRow(`SELECT * FROM tickets WHERE ticket_id = $1`, ticketID)

	var id, eventID int
	var eventName, date, class, ticketType, specialConditions string
	var price float64
	err := row.Scan(&id, &eventID, &eventName, &date, &price, &class, &ticketType, &specialConditions)
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"ticket_id":       id,
		"event_id":        eventID,
		"event_name":      eventName,
		"date":            date,
		"price":           price,
		"class":           class,
		"type":            ticketType,
		"special_conditions": specialConditions,
	}, nil
}

// GetOwnershipRecords retrieves ownership records for a given ticket ID
func (dm *DatabaseManager) GetOwnershipRecords(ticketID int) ([]map[string]interface{}, error) {
	dm.mu.Lock()
	defer dm.mu.Unlock()

	rows, err := dm.db.Query(`SELECT * FROM ownership_records WHERE ticket_id = $1`, ticketID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var records []map[string]interface{}
	for rows.Next() {
		var id, ticketID int
		var owner, transferDate string
		if err := rows.Scan(&id, &ticketID, &owner, &transferDate); err != nil {
			return nil, err
		}
		records = append(records, map[string]interface{}{
			"record_id":     id,
			"ticket_id":     ticketID,
			"owner":         owner,
			"transfer_date": transferDate,
		})
	}

	return records, nil
}

// GetComplianceRecords retrieves compliance records for a given ticket ID
func (dm *DatabaseManager) GetComplianceRecords(ticketID int) ([]map[string]interface{}, error) {
	dm.mu.Lock()
	defer dm.mu.Unlock()

	rows, err := dm.db.Query(`SELECT * FROM compliance_records WHERE ticket_id = $1`, ticketID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var records []map[string]interface{}
	for rows.Next() {
		var id, ticketID int
		var complianceDetails string
		if err := rows.Scan(&id, &ticketID, &complianceDetails); err != nil {
			return nil, err
		}

		decryptedDetails, err := dm.decrypt(complianceDetails)
		if err != nil {
			return nil, err
		}

		records = append(records, map[string]interface{}{
			"compliance_id":    id,
			"ticket_id":        ticketID,
			"compliance_details": decryptedDetails,
		})
	}

	return records, nil
}
