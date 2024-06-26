package syn200

import (
	"database/sql"
	"fmt"
	"log"
	"time"
)

// Storage handles database operations for carbon credits.
type Storage struct {
	DB *sql.DB
}

// NewStorage initializes a new Storage object with a database connection.
func NewStorage(db *sql.DB) *Storage {
	return &Storage{DB: db}
}

// SaveCarbonCredit stores a new carbon credit record in the database.
func (s *Storage) SaveCarbonCredit(credit *CarbonCredit) error {
	query := `INSERT INTO carbon_credits (id, owner, credits, issued_date, expiration_date, verified)
	          VALUES (?, ?, ?, ?, ?, ?)`
	_, err := s.DB.Exec(query, credit.ID, credit.Owner, credit.Credits, credit.IssuedDate, credit.ExpirationDate, credit.Verified)
	if err != nil {
		log.Printf("Error saving carbon credit: %v", err)
		return fmt.Errorf("error saving carbon credit: %w", err)
	}
	log.Printf("Successfully saved carbon credit: %s", credit.ID)
	return nil
}

// UpdateCarbonCredit updates an existing carbon credit record in the database.
func (s *Storage) UpdateCarbonCredit(credit *CarbonCredit) error {
	query := `UPDATE carbon_credits SET owner=?, credits=?, issued_date=?, expiration_date=?, verified=?
	          WHERE id=?`
	_, err := s.DB.Exec(query, credit.Owner, credit.Credits, credit.IssuedDate, credit.ExpirationDate, credit.Verified, credit.ID)
	if err != nil {
		log.Printf("Error updating carbon credit: %v", err)
		return fmt.Errorf("error updating carbon credit: %w", err)
	}
	log.Printf("Successfully updated carbon credit: %s", credit.ID)
	return nil
}

// DeleteCarbonCredit removes a carbon credit record from the database.
func (s *Storage) DeleteCarbonCredit(creditID string) error {
	query := `DELETE FROM carbon_credits WHERE id=?`
	_, err := s.DB.Exec(query, creditID)
	if err != nil {
		log.Printf("Error deleting carbon credit: %v", err)
		return fmt.Errorf("error deleting carbon credit: %w", err)
	}
	log.Printf("Successfully deleted carbon credit: %s", creditID)
	return nil
}

// GetCarbonCredit retrieves a carbon credit record by its ID.
func (s *Storage) GetCarbonCredit(creditID string) (*CarbonCredit, error) {
	query := `SELECT id, owner, credits, issued_date, expiration_date, verified FROM carbon_credits WHERE id=?`
	row := s.DB.QueryRow(query, creditID)
	var credit CarbonCredit
	err := row.Scan(&credit.ID, &credit.Owner, &credit.Credits, &credit.IssuedDate, &credit.ExpirationDate, &credit.Verified)
	if err != nil {
		log.Printf("Error retrieving carbon credit: %v", err)
		return nil, fmt.Errorf("error retrieving carbon credit: %w", err)
	}
	log.Printf("Successfully retrieved carbon credit: %s", credit.ID)
	return &credit, nil
}
