package syn1900

import (
	"database/sql"
	"fmt"
	"log"
	"time"

	_ "github.com/lib/pq" // PostgreSQL driver
)

const (
	createTableQuery = `CREATE TABLE IF NOT EXISTS education_credits (
		credit_id VARCHAR(255) PRIMARY KEY,
		course_id VARCHAR(255) NOT NULL,
		course_name VARCHAR(255) NOT NULL,
		issuer VARCHAR(255) NOT NULL,
		recipient VARCHAR(255) NOT NULL,
		credit_value FLOAT NOT NULL,
		issue_date TIMESTAMP NOT NULL,
		expiration_date TIMESTAMP,
		metadata TEXT,
		signature TEXT NOT NULL
	);`
)

// DBClient holds the database connection pool.
type DBClient struct {
	DB *sql.DB
}

// NewDBClient creates a new database client.
func NewDBClient(dataSourceName string) *DBClient {
	db, err := sql.Open("postgres", dataSourceName)
	if err != nil {
		log.Fatalf("Could not connect to database: %v", err)
	}
	// Ensure the table exists
	if _, err := db.Exec(createTableQuery); err != nil {
		log.Fatalf("Failed to create education credits table: %v", err)
	}
	return &DBClient{DB: db}
}

// Close terminates the database connection.
func (client *DBClient) Close() {
	client.DB.Close()
}

// SaveCredit stores a new education credit in the database.
func (client *DBClient) SaveCredit(credit EducationCredit) error {
	query := `INSERT INTO education_credits (credit_id, course_id, course_name, issuer, recipient, credit_value, issue_date, expiration_date, metadata, signature) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`
	_, err := client.DB.Exec(query, credit.CreditID, credit.CourseID, credit.CourseName, credit.Issuer, credit.Recipient, credit.CreditValue, credit.IssueDate, credit.ExpirationDate, credit.Metadata, credit.Signature)
	if err != nil {
		return fmt.Errorf("error saving education credit: %v", err)
	}
	return nil
}

// GetCredit retrieves an education credit by its ID from the database.
func (client *DBClient) GetCredit(creditID string) (EducationCredit, error) {
	query := `SELECT credit_id, course_id, course_name, issuer, recipient, credit_value, issue_date, expiration_date, metadata, signature FROM education_credits WHERE credit_id = $1`
	row := client.DB.QueryRow(query, creditID)

	var credit EducationCredit
	err := row.Scan(&credit.CreditID, &credit.CourseID, &credit.CourseName, &credit.Issuer, &credit.Recipient, &credit.CreditValue, &credit.IssueDate, &credit.ExpirationDate, &credit.Metadata, &credit.Signature)
	if err != nil {
		if err == sql.ErrNoRows {
			return EducationCredit{}, fmt.Errorf("no education credit found with ID %s", creditID)
		}
		return EducationCredit{}, fmt.Errorf("error retrieving education credit: %v", err)
	}
	return credit, nil
}

// DeleteCredit deletes an education credit from the database.
func (client *DBClient) DeleteCredit(creditID string) error {
	query := `DELETE FROM education_credits WHERE credit_id = $1`
	_, err := client.DB.Exec(query, creditID)
	if err != nil {
		return fmt.Errorf("error deleting education credit: %v", err)
	}
	return nil
}
