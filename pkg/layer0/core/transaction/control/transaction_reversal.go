package control

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"sync"

	"github.com/synthron_blockchain/pkg/layer0/core/transaction"
	"github.com/synthron_blockchain/pkg/layer0/core/ledger"
)

type TransactionReversal struct {
	Ledger *ledger.Ledger // Access to the blockchain ledger for transaction validation and reversal
	lock   sync.Mutex     // Mutex to handle concurrency in transaction reversal
}

// NewTransactionReversal creates a new instance of TransactionReversal.
func NewTransactionReversal(ledger *ledger.Ledger) *TransactionReversal {
	return &TransactionReversal{
		Ledger: ledger,
	}
}

// ReverseTransaction attempts to reverse a transaction from the blockchain ledger.
func (tr *TransactionReversal) ReverseTransaction(txID string) error {
	tr.lock.Lock()
	defer tr.lock.Unlock()

	tx, err := tr.Ledger.FetchTransaction(txID)
	if err != nil {
		return fmt.Errorf("failed to fetch transaction: %w", err)
	}

	if !tx.IsReversible {
		return fmt.Errorf("transaction %s is not reversible", txID)
	}

	if err := tr.Ledger.RemoveTransaction(tx); err != nil {
		return fmt.Errorf("failed to remove transaction: %w", err)
	}

	if err := tr.refundFees(tx); err != nil {
		return fmt.Errorf("failed to refund fees: %w", err)
	}

	tr.logReversal(txID)
	return nil
}

// refundFees handles the refund of transaction fees to the appropriate parties.
func (tr *TransactionReversal) refundFees(tx *transaction.Transaction) error {
	// Example: Implement the refund logic here, possibly invoking smart contracts
	return nil
}

// logReversal logs the details of the transaction reversal to the ledger.
func (tr *TransactionReversal) logReversal(txID string) {
	// Logging reversal action; consider using secure logging mechanisms
	fmt.Println("Transaction reversed:", txID)
}

// AES encryption for data security in logging or transmission
func encryptData(data []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	ciphertext := make([]byte, aes.BlockSize+len(data))
	iv := ciphertext[:aes.BlockSize]

	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
        return nil, err
    }

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], data)

	return ciphertext, nil
}

func main() {
	// Example initialization and use of TransactionReversal
	ledger := ledger.NewLedger() // Assume a function to initialize the ledger
	txReversal := NewTransactionReversal(ledger)

	if err := txReversal.ReverseTransaction("1234-abcd"); err != nil {
		fmt.Println("Error reversing transaction:", err)
	}
}
