package consensus

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/json"
	"log"
	"sync"
	"time"
)

// ConsensusMetrics defines the structure to hold metrics related to consensus operations
type ConsensusMetrics struct {
	mutex                sync.Mutex
	TotalBlocksValidated int
	TotalConsensusTime   time.Duration
	AverageConsensusTime time.Duration
	LastBlockTime        time.Time
}

// NewConsensusMetrics initializes a new instance of consensus metrics
func NewConsensusMetrics() *ConsensusMetrics {
	return &ConsensusMetrics{}
}

// RecordBlockValidation updates metrics after a block is validated
func (cm *ConsensusMetrics) RecordBlockValidation(duration time.Duration) {
	cm.mutex.Lock()
	defer cm.mutex.Unlock()

	cm.TotalBlocksValidated++
	cm.TotalConsensusTime += duration
	cm.AverageConsensusTime = cm.TotalConsensusTime / time.Duration(cm.TotalBlocksValidated)
	cm.LastBlockTime = time.Now()

	log.Printf("Block validated at %v, Total Validations: %d, Average Consensus Time: %v",
		cm.LastBlockTime, cm.TotalBlocksValidated, cm.AverageConsensusTime)
}

// EncryptMetrics encrypts the metrics for secure storage or transmission
func (cm *ConsensusMetrics) EncryptMetrics(key []byte) ([]byte, error) {
	cm.mutex.Lock()
	data, err := json.Marshal(cm)
	cm.mutex.Unlock()
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	encrypted := gcm.Seal(nonce, nonce, data, nil)
	return encrypted, nil
}

// DecryptMetrics decrypts the encrypted metrics data
func DecryptMetrics(encryptedData, key []byte) (*ConsensusMetrics, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(encryptedData) < nonceSize {
		return nil, errors.New("encrypted data too short")
	}

	nonce, ciphertext := encryptedData[:nonceSize], encryptedData[nonceSize:]
	data, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	var metrics ConsensusMetrics
	err = json.Unmarshal(data, &metrics)
	if err != nil {
		return nil, err
	}
	return &metrics, nil
}

// Example usage within consensus system
func main() {
	metrics := NewConsensusMetrics()
	metrics.RecordBlockValidation(time.Millisecond * 450)

	key := []byte("an-example-very-secure-key")
	encryptedMetrics, err := metrics.EncryptMetrics(key)
	if err != nil {
		log.Fatal("Error encrypting metrics:", err)
	}

	// Example of decrypting metrics
	decryptedMetrics, err := DecryptMetrics(encryptedMetrics, key)
	if err != nil {
		log.Fatal("Error decrypting metrics:", err)
	}

	log.Printf("Decrypted Metrics: %+v", decryptedMetrics)
}
