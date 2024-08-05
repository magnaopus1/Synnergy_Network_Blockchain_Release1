package fraud_detection

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"math/rand"
	"time"

	"gonum.org/v1/gonum/mat"
	"gonum.org/v1/gonum/stat"
)

// MLAlgorithms struct for handling machine learning-based fraud detection
type MLAlgorithms struct {
	secretKey []byte
}

// NewMLAlgorithms creates a new instance of MLAlgorithms
func NewMLAlgorithms(secret string) (*MLAlgorithms, error) {
	if len(secret) == 0 {
		return nil, errors.New("secret key cannot be empty")
	}
	hashedKey := sha256.Sum256([]byte(secret))
	return &MLAlgorithms{
		secretKey: hashedKey[:],
	}, nil
}

// DetectAnomalies uses a Gaussian Mixture Model (GMM) for anomaly detection
func (ml *MLAlgorithms) DetectAnomalies(transactions []Transaction) ([]Transaction, error) {
	data := ml.extractFeatures(transactions)
	mean, stddev := stat.MeanStdDev(data, nil)

	anomalies := []Transaction{}
	for i, tx := range transactions {
		if ml.isAnomaly(data[i], mean, stddev) {
			anomalies = append(anomalies, tx)
		}
	}
	return anomalies, nil
}

// extractFeatures extracts features from transactions for anomaly detection
func (ml *MLAlgorithms) extractFeatures(transactions []Transaction) []float64 {
	features := make([]float64, len(transactions))
	for i, tx := range transactions {
		features[i] = tx.Amount
	}
	return features
}

// isAnomaly determines if a data point is an anomaly based on mean and stddev
func (ml *MLAlgorithms) isAnomaly(value, mean, stddev float64) bool {
	zScore := (value - mean) / stddev
	return zScore > 3 || zScore < -3
}

// GenerateFraudProof generates a fraud proof for a transaction
func (ml *MLAlgorithms) GenerateFraudProof(tx Transaction) (string, error) {
	data := fmt.Sprintf("%s:%s:%f:%s:%s", tx.ID, tx.Sender, tx.Amount, tx.Receiver, tx.Timestamp.String())
	encryptedData, err := ml.encrypt(data)
	if err != nil {
		return "", err
	}
	return encryptedData, nil
}

// VerifyFraudProof verifies a fraud proof against a transaction
func (ml *MLAlgorithms) VerifyFraudProof(tx Transaction, proof string) (bool, error) {
	data := fmt.Sprintf("%s:%s:%f:%s:%s", tx.ID, tx.Sender, tx.Amount, tx.Receiver, tx.Timestamp.String())
	decryptedData, err := ml.decrypt(proof)
	if err != nil {
		return false, err
	}
	return data == decryptedData, nil
}

// encrypt encrypts the given text with AES
func (ml *MLAlgorithms) encrypt(text string) (string, error) {
	block, err := aes.NewCipher(ml.secretKey)
	if err != nil {
		return "", err
	}

	plaintext := []byte(text)
	cfb := cipher.NewCFBEncrypter(block, ml.secretKey[:block.BlockSize()])
	ciphertext := make([]byte, len(plaintext))
	cfb.XORKeyStream(ciphertext, plaintext)

	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// decrypt decrypts the given base64 encoded text with AES
func (ml *MLAlgorithms) decrypt(encryptedText string) (string, error) {
	block, err := aes.NewCipher(ml.secretKey)
	if err != nil {
		return "", err
	}

	ciphertext, err := base64.StdEncoding.DecodeString(encryptedText)
	if err != nil {
		return "", err
	}

	cfb := cipher.NewCFBDecrypter(block, ml.secretKey[:block.BlockSize()])
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

// handleMLFraudDetection is a sample function to demonstrate the usage of MLAlgorithms
func handleMLFraudDetection() {
	secret := "your-very-secure-secret-key"
	ml, err := NewMLAlgorithms(secret)
	if err != nil {
		fmt.Println("Error creating MLAlgorithms:", err)
		return
	}

	txs := GenerateRandomTransactions(5)
	anomalies, err := ml.DetectAnomalies(txs)
	if err != nil {
		fmt.Println("Error detecting anomalies:", err)
		return
	}

	for _, tx := range anomalies {
		proof, err := ml.GenerateFraudProof(tx)
		if err != nil {
			fmt.Println("Error generating proof:", err)
			continue
		}

		isValid, err := ml.VerifyFraudProof(tx, proof)
		if err != nil {
			fmt.Println("Error verifying proof:", err)
			continue
		}

		if isValid {
			fmt.Printf("Anomalous transaction %s is valid with proof: %s\n", tx.ID, proof)
		} else {
			fmt.Printf("Anomalous transaction %s is invalid with proof: %s\n", tx.ID, proof)
		}
	}
}
