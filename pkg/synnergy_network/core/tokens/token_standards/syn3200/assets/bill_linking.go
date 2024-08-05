// Package assets provides functionalities related to bill linking, metadata, and ownership verification for the SYN3200 Token Standard.
package assets

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "crypto/sha256"
    "encoding/hex"
    "errors"
    "io"
    "time"
    
    "golang.org/x/crypto/scrypt"
)

// Bill represents a bill token with metadata.
type Bill struct {
    ID           string
    Issuer       string
    Payer        string
    OriginalAmount float64
    RemainingAmount float64
    DueDate      time.Time
    PaidStatus   bool
    Metadata     string
    Timestamp    time.Time
}

// BillLedger represents an immutable ledger of all bills.
type BillLedger struct {
    bills map[string]Bill
}

// NewBillLedger creates a new BillLedger.
func NewBillLedger() *BillLedger {
    return &BillLedger{
        bills: make(map[string]Bill),
    }
}

// AddBill adds a new bill to the ledger.
func (bl *BillLedger) AddBill(bill Bill) {
    bl.bills[bill.ID] = bill
}

// GetBill retrieves a bill by ID.
func (bl *BillLedger) GetBill(id string) (Bill, error) {
    bill, exists := bl.bills[id]
    if !exists {
        return Bill{}, errors.New("bill not found")
    }
    return bill, nil
}

// UpdateBill updates the details of an existing bill.
func (bl *BillLedger) UpdateBill(bill Bill) error {
    _, exists := bl.bills[bill.ID]
    if !exists {
        return errors.New("bill not found")
    }
    bl.bills[bill.ID] = bill
    return nil
}

// OwnershipVerification handles the verification of bill ownership.
type OwnershipVerification struct {
    ownershipRecords map[string]string
}

// NewOwnershipVerification creates a new OwnershipVerification.
func NewOwnershipVerification() *OwnershipVerification {
    return &OwnershipVerification{
        ownershipRecords: make(map[string]string),
    }
}

// VerifyOwnership verifies the ownership of a bill.
func (ov *OwnershipVerification) VerifyOwnership(billID, owner string) bool {
    actualOwner, exists := ov.ownershipRecords[billID]
    if !exists {
        return false
    }
    return actualOwner == owner
}

// TransferOwnership transfers ownership of a bill to a new owner.
func (ov *OwnershipVerification) TransferOwnership(billID, newOwner string) error {
    _, exists := ov.ownershipRecords[billID]
    if !exists {
        return errors.New("bill not found")
    }
    ov.ownershipRecords[billID] = newOwner
    return nil
}

// Securely hash data using SHA-256 and return the hexadecimal string.
func hashData(data string) string {
    hash := sha256.Sum256([]byte(data))
    return hex.EncodeToString(hash[:])
}

// Encrypt data using AES with a key derived from the password and salt.
func encryptData(password, data string) (string, error) {
    salt := make([]byte, 16)
    if _, err := io.ReadFull(rand.Reader, salt); err != nil {
        return "", err
    }
    key, err := scrypt.Key([]byte(password), salt, 32768, 8, 1, 32)
    if err != nil {
        return "", err
    }

    block, err := aes.NewCipher(key)
    if err != nil {
        return "", err
    }

    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return "", err
    }

    nonce := make([]byte, gcm.NonceSize())
    if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
        return "", err
    }

    ciphertext := gcm.Seal(nonce, nonce, []byte(data), nil)
    return hex.EncodeToString(append(salt, ciphertext...)), nil
}

// Decrypt data using AES with a key derived from the password and salt.
func decryptData(password, encryptedData string) (string, error) {
    data, err := hex.DecodeString(encryptedData)
    if err != nil {
        return "", err
    }

    salt := data[:16]
    ciphertext := data[16:]

    key, err := scrypt.Key([]byte(password), salt, 32768, 8, 1, 32)
    if err != nil {
        return "", err
    }

    block, err := aes.NewCipher(key)
    if err != nil {
        return "", err
    }

    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return "", err
    }

    nonceSize := gcm.NonceSize()
    nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]

    plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
    if err != nil {
        return "", err
    }

    return string(plaintext), nil
}

// BillLinking provides functionality to link bills with their tokens.
type BillLinking struct {
    billLedger           *BillLedger
    ownershipVerification *OwnershipVerification
}

// NewBillLinking creates a new BillLinking.
func NewBillLinking() *BillLinking {
    return &BillLinking{
        billLedger:           NewBillLedger(),
        ownershipVerification: NewOwnershipVerification(),
    }
}

// LinkBill links a bill to its metadata and stores it in the ledger.
func (bl *BillLinking) LinkBill(bill Bill) {
    bl.billLedger.AddBill(bill)
    bl.ownershipVerification.ownershipRecords[bill.ID] = bill.Issuer
}

// VerifyBillOwnership verifies the ownership of a bill.
func (bl *BillLinking) VerifyBillOwnership(billID, owner string) bool {
    return bl.ownershipVerification.VerifyOwnership(billID, owner)
}

// TransferBillOwnership transfers the ownership of a bill to a new owner.
func (bl *BillLinking) TransferBillOwnership(billID, newOwner string) error {
    return bl.ownershipVerification.TransferOwnership(billID, newOwner)
}

// GetBill retrieves a bill by its ID.
func (bl *BillLinking) GetBill(billID string) (Bill, error) {
    return bl.billLedger.GetBill(billID)
}

// UpdateBill updates the details of an existing bill.
func (bl *BillLinking) UpdateBill(bill Bill) error {
    return bl.billLedger.UpdateBill(bill)
}
