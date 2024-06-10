package syn3200

import (
    "database/sql"
    "encoding/json"
    "fmt"
    "log"
    "time"
    _ "github.com/mattn/go-sqlite3" // Import go-sqlite3 library
)

type Storage struct {
    DB *sql.DB
}

func NewStorage(dataSourceName string) *Storage {
    db, err := sql.Open("sqlite3", dataSourceName)
    if err != nil {
        log.Fatal(err)
    }
    return &Storage{DB: db}
}

func (s *Storage) InitializeDB() error {
    query := `
    CREATE TABLE IF NOT EXISTS bill_tokens (
        token_id TEXT PRIMARY KEY,
        bill_data TEXT NOT NULL,
        issued_date TEXT NOT NULL,
        last_payment_date TEXT, // This could logically belong to the token rather than the bill itself
        total_supply REAL NOT NULL
    );
    `
    _, err := s.DB.Exec(query)
    if err != nil {
        return fmt.Errorf("error creating bill_tokens table: %w", err)
    }
    return nil
}

func (s *Storage) StoreToken(token *BillToken) error {
    billData, err := json.Marshal(token.Bill)
    if err != nil {
        return err
    }
    _, err = s.DB.Exec("INSERT INTO bill_tokens (token_id, bill_data, issued_date, last_payment_date, total_supply) VALUES (?, ?, ?, ?, ?)",
        token.TokenID, string(billData), token.IssuedDate.Format(time.RFC3339), token.LastPaymentDate.Format(time.RFC3339), token.Bill.OriginalAmount)
    if err != nil {
        return fmt.Errorf("error storing new token: %w", err)
    }
    return nil
}

func (s *Storage) UpdateBillToken(tokenID string, lastPaymentDate time.Time) error {
    _, err := s.DB.Exec("UPDATE bill_tokens SET last_payment_date = ? WHERE token_id = ?",
        lastPaymentDate.Format(time.RFC3339), tokenID)
    if err != nil {
        return fmt.Errorf("error updating bill token: %w", err)
    }
    return nil
}

func (s *Storage) RetrieveToken(tokenID string) (*BillToken, error) {
    var billData string
    var issuedDate, lastPaymentDate string
    token := &BillToken{}

    row := s.DB.QueryRow("SELECT token_id, bill_data, issued_date, last_payment_date FROM bill_tokens WHERE token_id = ?", tokenID)
    err := row.Scan(&token.TokenID, &billData, &issuedDate, &lastPaymentDate)
    if err != nil {
        if err == sql.ErrNoRows {
            return nil, fmt.Errorf("no bill token found with ID %s", tokenID)
        }
        return nil, err
    }

    if err := json.Unmarshal([]byte(billData), &token.Bill); err != nil {
        return nil, err
    }
    token.IssuedDate, _ = time.Parse(time.RFC3339, issuedDate)
    token.LastPaymentDate, _ = time.Parse(time.RFC3339, lastPaymentDate)

    return token, nil
}

func (s *Storage) CloseDB() error {
    return s.DB.Close()
}
