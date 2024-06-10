package syn845

import (
    "database/sql"
    "fmt"
    "log"
)

// DebtStorage manages the database operations for debt instruments.
type DebtStorage struct {
    db *sql.DB
}

// NewDebtStorage creates a new instance of DebtStorage.
func NewDebtStorage(db *sql.DB) *DebtStorage {
    return &DebtStorage{db: db}
}

// SaveDebtInstrument stores a new debt instrument or updates an existing one in the database.
func (ds *DebtStorage) SaveDebtInstrument(di *DebtInstrument) error {
    if di == nil {
        return fmt.Errorf("provided debt instrument is nil")
    }

    query := `
        INSERT INTO debt_instruments (id, owner, original_amount, interest_rate, next_payment_date, remaining_amount, status)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ON DUPLICATE KEY UPDATE
        owner=?, original_amount=?, interest_rate=?, next_payment_date=?, remaining_amount=?, status=?;
    `
    _, err := ds.db.Exec(query,
        di.ID, di.Owner, di.OriginalAmount, di.InterestRate, di.NextPaymentDate, di.RemainingAmount, di.Status,
        di.Owner, di.OriginalAmount, di.InterestRate, di.NextPaymentDate, di.RemainingAmount, di.Status,
    )
    if err != nil {
        log.Printf("Failed to save debt instrument %s: %v", di.ID, err)
        return err
    }
    log.Printf("Debt instrument %s saved or updated successfully.", di.ID)
    return nil
}

// LoadDebtInstrument retrieves a debt instrument by its ID.
func (ds *DebtStorage) LoadDebtInstrument(id string) (*DebtInstrument, error) {
    query := `
        SELECT id, owner, original_amount, interest_rate, next_payment_date, remaining_amount, status
        FROM debt_instruments
        WHERE id = ?;
    `
    row := ds.db.QueryRow(query, id)
    di := &DebtInstrument{}
    err := row.Scan(&di.ID, &di.Owner, &di.OriginalAmount, &di.InterestRate, &di.NextPaymentDate, &di.RemainingAmount, &di.Status)
    if err != nil {
        log.Printf("Failed to load debt instrument %s: %v", id, err)
        return nil, err
    }
    log.Printf("Debt instrument %s loaded successfully.", di.ID)
    return di, nil
}

// DeleteDebtInstrument removes a debt instrument from the database.
func (ds *DebtStorage) DeleteDebtInstrument(id string) error {
    query := `DELETE FROM debt_instruments WHERE id = ?;`
    _, err := ds.db.Exec(query, id)
    if err != nil {
        log.Printf("Failed to delete debt instrument %s: %v", id, err)
        return err
    }
    log.Printf("Debt instrument %s deleted successfully.", id)
    return nil
}
