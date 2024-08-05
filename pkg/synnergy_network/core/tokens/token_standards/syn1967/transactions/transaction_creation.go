package transactions

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"

	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn1967/assets"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn1967/security"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn1967/storage"
)

// Transaction represents a generic transaction on the blockchain.
type Transaction struct {
	ID        string
	TokenID   string
	Amount    float64
	Sender    string
	Receiver  string
	Timestamp int64
	Signature string
}

// NewTransaction creates a new transaction instance.
func NewTransaction(id, tokenID string, amount float64, sender, receiver, signature string, timestamp int64) (*Transaction, error) {
	if id == "" || tokenID == "" || sender == "" || receiver == "" || signature == "" {
		return nil, errors.New("all transaction fields must be provided")
	}
	if amount <= 0 {
		return nil, errors.New("transaction amount must be positive")
	}
	return &Transaction{
		ID:        id,
		TokenID:   tokenID,
		Amount:    amount,
		Sender:    sender,
		Receiver:  receiver,
		Timestamp: timestamp,
		Signature: signature,
	}, nil
}

// ValidateTransaction validates the transaction details.
func (tx *Transaction) ValidateTransaction() error {
	// Validate token existence
	token, err := storage.GetTokenByID(tx.TokenID)
	if err != nil {
		return errors.New("token not found")
	}

	// Validate sender balance
	senderBalance, err := storage.GetUserBalance(tx.Sender, tx.TokenID)
	if err != nil {
		return errors.New("sender balance not found")
	}
	if senderBalance < tx.Amount {
		return errors.New("insufficient balance")
	}

	// Validate transaction signature
	if !security.ValidateSignature(tx.Sender, tx.Signature, tx.ID) {
		return errors.New("invalid transaction signature")
	}

	// Additional custom validations can be added here

	return nil
}

// ExecuteTransaction executes the transaction, transferring the token amount.
func (tx *Transaction) ExecuteTransaction() error {
	if err := tx.ValidateTransaction(); err != nil {
		return err
	}

	// Deduct amount from sender's balance
	err := storage.UpdateUserBalance(tx.Sender, tx.TokenID, -tx.Amount)
	if err != nil {
		return err
	}

	// Add amount to receiver's balance
	err = storage.UpdateUserBalance(tx.Receiver, tx.TokenID, tx.Amount)
	if err != nil {
		return err
	}

	// Log the transaction event
	transactionLog := assets.EventLog{
		TokenID:     tx.TokenID,
		Amount:      tx.Amount,
		EventType:   "transfer",
		EventTime:   tx.Timestamp,
		Sender:      tx.Sender,
		Receiver:    tx.Receiver,
	}
	err = assets.LogEvent(transactionLog)
	if err != nil {
		return err
	}

	return nil
}

// EncryptTransaction encrypts transaction details using AES encryption.
func (tx *Transaction) EncryptTransaction(key string) (string, error) {
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return "", err
	}

	plaintext := fmt.Sprintf("%s|%s|%f|%s|%s|%d|%s", tx.ID, tx.TokenID, tx.Amount, tx.Sender, tx.Receiver, tx.Timestamp, tx.Signature)
	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]

	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], []byte(plaintext))

	return hex.EncodeToString(ciphertext), nil
}

// DecryptTransaction decrypts transaction details using AES encryption.
func DecryptTransaction(encrypted string, key string) (*Transaction, error) {
	ciphertext, _ := hex.DecodeString(encrypted)

	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return nil, err
	}

	if len(ciphertext) < aes.BlockSize {
		return nil, errors.New("ciphertext too short")
	}

	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(ciphertext, ciphertext)

	plaintext := string(ciphertext)
	parts := strings.Split(plaintext, "|")
	if len(parts) != 7 {
		return nil, errors.New("invalid transaction format")
	}

	amount, _ := strconv.ParseFloat(parts[2], 64)
	timestamp, _ := strconv.ParseInt(parts[5], 10, 64)

	tx := &Transaction{
		ID:        parts[0],
		TokenID:   parts[1],
		Amount:    amount,
		Sender:    parts[3],
		Receiver:  parts[4],
		Timestamp: timestamp,
		Signature: parts[6],
	}
	return tx, nil
}

// Example usage of transaction creation.
func ExampleTransactionCreation() {
	// Create a new transaction
	tx, err := NewTransaction("tx123", "token456", 50.0, "Alice", "Bob", "signature789", 1623445567)
	if err != nil {
		fmt.Printf("Transaction creation failed: %s\n", err)
		return
	}

	// Encrypt the transaction
	encryptedTx, err := tx.EncryptTransaction("examplekey1234567")
	if err != nil {
		fmt.Printf("Transaction encryption failed: %s\n", err)
		return
	}
	fmt.Printf("Encrypted transaction: %s\n", encryptedTx)

	// Decrypt the transaction
	decryptedTx, err := DecryptTransaction(encryptedTx, "examplekey1234567")
	if err != nil {
		fmt.Printf("Transaction decryption failed: %s\n", err)
		return
	}
	fmt.Printf("Decrypted transaction: %+v\n", decryptedTx)

	// Execute the transaction
	err = decryptedTx.ExecuteTransaction()
	if err != nil {
		fmt.Printf("Transaction execution failed: %s\n", err)
		return
	}
	fmt.Println("Transaction executed successfully")
}
