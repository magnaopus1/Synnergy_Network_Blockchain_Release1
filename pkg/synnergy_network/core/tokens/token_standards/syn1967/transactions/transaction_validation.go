package transactions

import (
	"errors"
	"time"

	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn1967/assets"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn1967/security"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn1967/storage"
)

// ValidateTransactionInput validates the input fields of a transaction before it is created.
func ValidateTransactionInput(id, tokenID, sender, receiver, signature string, amount float64, timestamp int64) error {
	if id == "" || tokenID == "" || sender == "" || receiver == "" || signature == "" {
		return errors.New("all transaction fields must be provided")
	}
	if amount <= 0 {
		return errors.New("transaction amount must be positive")
	}
	return nil
}

// VerifyTokenExistence checks if the token associated with the transaction exists.
func VerifyTokenExistence(tokenID string) error {
	_, err := storage.GetTokenByID(tokenID)
	if err != nil {
		return errors.New("token not found")
	}
	return nil
}

// VerifySenderBalance ensures the sender has enough balance to perform the transaction.
func VerifySenderBalance(sender string, tokenID string, amount float64) error {
	senderBalance, err := storage.GetUserBalance(sender, tokenID)
	if err != nil {
		return errors.New("sender balance not found")
	}
	if senderBalance < amount {
		return errors.New("insufficient balance")
	}
	return nil
}

// VerifySignature checks the validity of the transaction's signature.
func VerifySignature(sender string, signature string, transactionID string) error {
	if !security.ValidateSignature(sender, signature, transactionID) {
		return errors.New("invalid transaction signature")
	}
	return nil
}

// LogTransaction logs the transaction event in the blockchain.
func LogTransaction(tx *Transaction) error {
	transactionLog := assets.EventLog{
		TokenID:     tx.TokenID,
		Amount:      tx.Amount,
		EventType:   "transfer",
		EventTime:   tx.Timestamp,
		Sender:      tx.Sender,
		Receiver:    tx.Receiver,
	}
	err := assets.LogEvent(transactionLog)
	if err != nil {
		return err
	}
	return nil
}

// ValidateTransaction performs all necessary validation checks for a transaction.
func ValidateTransaction(tx *Transaction) error {
	if err := ValidateTransactionInput(tx.ID, tx.TokenID, tx.Sender, tx.Receiver, tx.Signature, tx.Amount, tx.Timestamp); err != nil {
		return err
	}
	if err := VerifyTokenExistence(tx.TokenID); err != nil {
		return err
	}
	if err := VerifySenderBalance(tx.Sender, tx.TokenID, tx.Amount); err != nil {
		return err
	}
	if err := VerifySignature(tx.Sender, tx.Signature, tx.ID); err != nil {
		return err
	}
	return nil
}

// ProcessTransaction handles the entire transaction process including validation, execution, and logging.
func ProcessTransaction(tx *Transaction) error {
	if err := ValidateTransaction(tx); err != nil {
		return err
	}

	if err := tx.ExecuteTransaction(); err != nil {
		return err
	}

	if err := LogTransaction(tx); err != nil {
		return err
	}

	return nil
}

// ExampleTransactionValidation demonstrates the validation process of a transaction.
func ExampleTransactionValidation() {
	tx, err := NewTransaction("tx123", "token456", 50.0, "Alice", "Bob", "signature789", time.Now().Unix())
	if err != nil {
		fmt.Printf("Transaction creation failed: %s\n", err)
		return
	}

	err = ProcessTransaction(tx)
	if err != nil {
		fmt.Printf("Transaction processing failed: %s\n", err)
		return
	}

	fmt.Println("Transaction processed successfully")
}
