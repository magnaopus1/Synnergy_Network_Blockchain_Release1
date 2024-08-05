// Package ledger provides functionalities to handle the ownership records for SYN3200 tokens.
package ledger

import (
	"encoding/json"
	"errors"

	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/util"
)

// OwnershipRecord represents the ownership details of a bill token.
type OwnershipRecord struct {
	TokenID      string `json:"token_id"`
	OwnerID      string `json:"owner_id"`
	Transferable bool   `json:"transferable"`
}

// OwnershipRecordsLedger manages the ownership records of bill tokens.
type OwnershipRecordsLedger struct {
	DB *leveldb.DB
}

// NewOwnershipRecordsLedger creates a new instance of OwnershipRecordsLedger.
func NewOwnershipRecordsLedger(dbPath string) (*OwnershipRecordsLedger, error) {
	db, err := leveldb.OpenFile(dbPath, nil)
	if err != nil {
		return nil, err
	}
	return &OwnershipRecordsLedger{DB: db}, nil
}

// CloseDB closes the database connection.
func (orl *OwnershipRecordsLedger) CloseDB() error {
	return orl.DB.Close()
}

// AddOwnershipRecord adds a new ownership record to the ledger.
func (orl *OwnershipRecordsLedger) AddOwnershipRecord(record OwnershipRecord) error {
	data, err := json.Marshal(record)
	if err != nil {
		return err
	}
	return orl.DB.Put([]byte("ownership_"+record.TokenID), data, nil)
}

// GetOwnershipRecord retrieves an ownership record by token ID.
func (orl *OwnershipRecordsLedger) GetOwnershipRecord(tokenID string) (*OwnershipRecord, error) {
	data, err := orl.DB.Get([]byte("ownership_"+tokenID), nil)
	if err != nil {
		return nil, err
	}
	var record OwnershipRecord
	if err := json.Unmarshal(data, &record); err != nil {
		return nil, err
	}
	return &record, nil
}

// GetAllOwnershipRecords retrieves all ownership records from the ledger.
func (orl *OwnershipRecordsLedger) GetAllOwnershipRecords() ([]OwnershipRecord, error) {
	var records []OwnershipRecord
	iter := orl.DB.NewIterator(util.BytesPrefix([]byte("ownership_")), nil)
	defer iter.Release()
	for iter.Next() {
		var record OwnershipRecord
		if err := json.Unmarshal(iter.Value(), &record); err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	if iter.Error() != nil {
		return nil, iter.Error()
	}
	return records, nil
}

// UpdateOwnershipRecord updates an existing ownership record in the ledger.
func (orl *OwnershipRecordsLedger) UpdateOwnershipRecord(record OwnershipRecord) error {
	existingRecord, err := orl.GetOwnershipRecord(record.TokenID)
	if err != nil {
		return err
	}
	if existingRecord == nil {
		return errors.New("ownership record not found")
	}
	data, err := json.Marshal(record)
	if err != nil {
		return err
	}
	return orl.DB.Put([]byte("ownership_"+record.TokenID), data, nil)
}

// TransferOwnership transfers the ownership of a bill token to a new owner.
func (orl *OwnershipRecordsLedger) TransferOwnership(tokenID string, newOwnerID string) error {
	record, err := orl.GetOwnershipRecord(tokenID)
	if err != nil {
		return err
	}
	if !record.Transferable {
		return errors.New("token is not transferable")
	}
	record.OwnerID = newOwnerID
	return orl.UpdateOwnershipRecord(*record)
}

// ValidateOwnershipRecord ensures the ownership record is valid before adding it to the ledger.
func (orl *OwnershipRecordsLedger) ValidateOwnershipRecord(record OwnershipRecord) error {
	if record.TokenID == "" {
		return errors.New("token ID must be provided")
	}
	if record.OwnerID == "" {
		return errors.New("owner ID must be provided")
	}
	// Add more validation rules as necessary
	return nil
}

// DeleteOwnershipRecord removes an ownership record from the ledger.
func (orl *OwnershipRecordsLedger) DeleteOwnershipRecord(tokenID string) error {
	return orl.DB.Delete([]byte("ownership_"+tokenID), nil)
}
