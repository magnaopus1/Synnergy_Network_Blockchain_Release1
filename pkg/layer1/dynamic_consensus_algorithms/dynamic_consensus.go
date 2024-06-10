package dynamicconsensus

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"io"
	"log"
	"sync"
	"time"

	"github.com/pkg/errors"
)

// ConsensusParameters defines dynamic values that can be adjusted.
type ConsensusParameters struct {
	BlockTime         time.Duration `json:"block_time"`
	MinerReward       float64       `json:"miner_reward"`
	TransactionLimit  int           `json:"transaction_limit"`
	AdjustmentFactor  float64       `json:"adjustment_factor"`
	LastAdjustment    time.Time     `json:"last_adjustment"`
	EncryptionKey     []byte        `json:"-"`
}

// ConsensusManager manages the current state of consensus parameters.
type ConsensusManager struct {
	params  ConsensusParameters
	mutex   sync.Mutex
}

// NewConsensusManager creates a new consensus manager with default parameters.
func NewConsensusManager(key []byte) *ConsensusManager {
	return &ConsensusManager{
		params: ConsensusParameters{
			BlockTime:        10 * time.Second,
			MinerReward:      12.5,
			TransactionLimit: 1000,
			AdjustmentFactor: 0.05,
			LastAdjustment:   time.Now(),
			EncryptionKey:    key,
		},
	}
}

// AdjustParameters dynamically adjusts consensus parameters based on network conditions.
func (cm *ConsensusManager) AdjustParameters(newBlockTime time.Duration, newReward float64, newLimit int) error {
	cm.mutex.Lock()
	defer cm.mutex.Unlock()

	cm.params.BlockTime = newBlockTime
	cm.params.MinerReward = newReward
	cm.params.TransactionLimit = newLimit
	cm.params.LastAdjustment = time.Now()

	log.Printf("Consensus parameters adjusted: %+v", cm.params)
	return nil
}

// EncryptParameters encrypts the current consensus parameters.
func (cm *ConsensusManager) EncryptParameters() ([]byte, error) {
	cm.mutex.Lock()
	defer cm.mutex.Unlock()

	data, err := json.Marshal(cm.params)
	if err != nil {
		return nil, errors.Wrap(err, "failed to marshal parameters")
	}

	block, err := aes.NewCipher(cm.params.EncryptionKey)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create cipher block")
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create GCM")
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, errors.Wrap(err, "failed to generate nonce")
	}

	encrypted := gcm.Seal(nonce, nonce, data, nil)
	log.Println("Consensus parameters encrypted")
	return encrypted, nil
}

// DecryptParameters decrypts the consensus parameters data.
func (cm *ConsensusManager) DecryptParameters(data []byte) error {
	cm.mutex.Lock()
	defer cm.mutex.Unlock()

	block, err := aes.NewCipher(cm.params.EncryptionKey)
	if err != nil {
		return errors.Wrap(err, "failed to create cipher block")
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return errors.Wrap(err, "failed to create GCM")
	}

	if len(data) < gcm.NonceSize() {
		return errors.New("encrypted data is too short")
	}

	nonce, ciphertext := data[:gcm.NonceSize()], data[gcm.NonceSize():]
	decrypted, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return errors.Wrap(err, "failed to decrypt data")
	}

	err = json.Unmarshal(decrypted, &cm.params)
	if err != nil {
		return errors.Wrap(err, "failed to unmarshal parameters")
	}
	log.Println("Consensus parameters decrypted and updated")
	return nil
}

// LogParameters logs the current parameters to the console.
func (cm *ConsensusManager) LogParameters() {
	cm.mutex.Lock()
	defer cm.mutex.Unlock()

	log.Printf("Current Consensus Parameters: %+v", cm.params)
}
