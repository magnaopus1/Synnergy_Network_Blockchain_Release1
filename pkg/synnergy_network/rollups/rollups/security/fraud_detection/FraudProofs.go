package fraud_detection

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
)

// FraudProofs struct to handle fraud proofs generation and verification
type FraudProofs struct {
	secretKey []byte
}

// NewFraudProofs creates a new instance of FraudProofs
func NewFraudProofs(secret string) (*FraudProofs, error) {
	if len(secret) == 0 {
		return nil, errors.New("secret key cannot be empty")
	}
	hashedKey := sha256.Sum256([]byte(secret))
	return &FraudProofs{
		secretKey: hashedKey[:],
	}, nil
}

// GenerateProof generates a fraud proof for a given transaction
func (fp *FraudProofs) GenerateProof(tx Transaction) (string, error) {
	data := fmt.Sprintf("%s:%s:%f:%s:%s", tx.ID, tx.Sender, tx.Amount, tx.Receiver, tx.Timestamp.String())
	encryptedData, err := fp.encrypt(data)
	if err != nil {
		return "", err
	}
	return encryptedData, nil
}

// VerifyProof verifies a fraud proof against a transaction
func (fp *FraudProofs) VerifyProof(tx Transaction, proof string) (bool, error) {
	data := fmt.Sprintf("%s:%s:%f:%s:%s", tx.ID, tx.Sender, tx.Amount, tx.Receiver, tx.Timestamp.String())
	decryptedData, err := fp.decrypt(proof)
	if err != nil {
		return false, err
	}
	return data == decryptedData, nil
}

// encrypt encrypts the given text with AES
func (fp *FraudProofs) encrypt(text string) (string, error) {
	block, err := aes.NewCipher(fp.secretKey)
	if err != nil {
		return "", err
	}

	plaintext := []byte(text)
	cfb := cipher.NewCFBEncrypter(block, fp.secretKey[:block.BlockSize()])
	ciphertext := make([]byte, len(plaintext))
	cfb.XORKeyStream(ciphertext, plaintext)

	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// decrypt decrypts the given base64 encoded text with AES
func (fp *FraudProofs) decrypt(encryptedText string) (string, error) {
	block, err := aes.NewCipher(fp.secretKey)
	if err != nil {
		return "", err
	}

	ciphertext, err := base64.StdEncoding.DecodeString(encryptedText)
	if err != nil {
		return "", err
	}

	cfb := cipher.NewCFBDecrypter(block, fp.secretKey[:block.BlockSize()])
	plaintext := make([]byte, len(ciphertext))
	cfb.XORKeyStream(plaintext, ciphertext)

	return string(plaintext), nil
}

// Transaction represents a transaction in the blockchain
type Transaction struct {
	ID          string
	Sender      string
	Receiver    string
	Amount      float64
	Description string
	Timestamp   time.Time
}

// GenerateRandomTransactions generates a list of random transactions for testing
func GenerateRandomTransactions(count int) []Transaction {
	var transactions []Transaction
	for i := 0; i < count; i++ {
		transactions = append(transactions, Transaction{
			ID:          generateRandomString(10),
			Sender:      generateRandomString(5),
			Receiver:    generateRandomString(5),
			Amount:      rand.Float64() * 10000,
			Description: generateRandomString(20),
			Timestamp:   time.Now(),
		})
	}
	return transactions
}

// generateRandomString generates a random string of the given length
func generateRandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	var seededRand = rand.New(rand.NewSource(time.Now().UnixNano()))

	b := make([]byte, length)
	for i := range b {
		b[i] = charset[seededRand.Intn(len(charset))]
	}
	return string(b)
}

// handleFraudProofs is a sample function to demonstrate the usage of FraudProofs
func handleFraudProofs() {
	secret := "your-very-secure-secret-key"
	fp, err := NewFraudProofs(secret)
	if err != nil {
		fmt.Println("Error creating FraudProofs:", err)
		return
	}

	txs := GenerateRandomTransactions(5)
	for _, tx := range txs {
		proof, err := fp.GenerateProof(tx)
		if err != nil {
			fmt.Println("Error generating proof:", err)
			continue
		}

		isValid, err := fp.VerifyProof(tx, proof)
		if err != nil {
			fmt.Println("Error verifying proof:", err)
			continue
		}

		if isValid {
			fmt.Printf("Transaction %s is valid with proof: %s\n", tx.ID, proof)
		} else {
			fmt.Printf("Transaction %s is invalid with proof: %s\n", tx.ID, proof)
		}
	}
}
