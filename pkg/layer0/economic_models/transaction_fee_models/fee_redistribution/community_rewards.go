package fee_redistribution

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"sync"

	"github.com/synthron_blockchain_final/pkg/layer0/core/smart_contract"
	"github.com/synthron_blockchain_final/pkg/layer0/core/transaction"
	"golang.org/x/crypto/scrypt"
)

// CommunityRewards defines the structure for managing community rewards
type CommunityRewards struct {
	sync.Mutex
	rewardsPool   *big.Int
	distribution  map[string]*big.Int
	participants  map[string]bool
	contract      *smart_contract.Contract
}

// NewCommunityRewards creates a new instance of CommunityRewards
func NewCommunityRewards(initialPool *big.Int, contract *smart_contract.Contract) *CommunityRewards {
	return &CommunityRewards{
		rewardsPool:  initialPool,
		distribution: make(map[string]*big.Int),
		participants: make(map[string]bool),
		contract:     contract,
	}
}

// AddParticipant adds a new participant to the rewards system
func (cr *CommunityRewards) AddParticipant(address string) {
	cr.Lock()
	defer cr.Unlock()

	if !cr.participants[address] {
		cr.participants[address] = true
		cr.distribution[address] = big.NewInt(0)
	}
}

// RemoveParticipant removes a participant from the rewards system
func (cr *CommunityRewards) RemoveParticipant(address string) {
	cr.Lock()
	defer cr.Unlock()

	if cr.participants[address] {
		delete(cr.participants, address)
		delete(cr.distribution, address)
	}
}

// DistributeRewards distributes the rewards from the pool to the participants
func (cr *CommunityRewards) DistributeRewards() error {
	cr.Lock()
	defer cr.Unlock()

	if cr.rewardsPool.Cmp(big.NewInt(0)) == 0 {
		return errors.New("rewards pool is empty")
	}

	totalParticipants := len(cr.participants)
	if totalParticipants == 0 {
		return errors.New("no participants to distribute rewards to")
	}

	share := new(big.Int).Div(cr.rewardsPool, big.NewInt(int64(totalParticipants)))
	for address := range cr.participants {
		cr.distribution[address].Add(cr.distribution[address], share)
	}

	cr.rewardsPool.SetInt64(0)
	return nil
}

// GetReward returns the reward for a specific participant
func (cr *CommunityRewards) GetReward(address string) (*big.Int, error) {
	cr.Lock()
	defer cr.Unlock()

	reward, exists := cr.distribution[address]
	if !exists {
		return nil, fmt.Errorf("participant %s not found", address)
	}

	return reward, nil
}

// AddToRewardsPool adds more funds to the rewards pool
func (cr *CommunityRewards) AddToRewardsPool(amount *big.Int) {
	cr.Lock()
	defer cr.Unlock()

	cr.rewardsPool.Add(cr.rewardsPool, amount)
}

// EncryptReward encrypts the reward data using Scrypt and AES
func (cr *CommunityRewards) EncryptReward(address string, passphrase string) (string, error) {
	cr.Lock()
	defer cr.Unlock()

	reward, exists := cr.distribution[address]
	if !exists {
		return "", fmt.Errorf("participant %s not found", address)
	}

	data := []byte(reward.String())
	salt := make([]byte, 16)
	_, err := rand.Read(salt)
	if err != nil {
		return "", err
	}

	key, err := scrypt.Key([]byte(passphrase), salt, 32768, 8, 1, 32)
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
	_, err = rand.Read(nonce)
	if err != nil {
		return "", err
	}

	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return hex.EncodeToString(append(salt, ciphertext...)), nil
}

// DecryptReward decrypts the reward data using Scrypt and AES
func (cr *CommunityRewards) DecryptReward(encryptedData string, passphrase string) (*big.Int, error) {
	data, err := hex.DecodeString(encryptedData)
	if err != nil {
		return nil, err
	}

	if len(data) < 16 {
		return nil, errors.New("invalid encrypted data")
	}

	salt := data[:16]
	ciphertext := data[16:]

	key, err := scrypt.Key([]byte(passphrase), salt, 32768, 8, 1, 32)
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

	if len(ciphertext) < gcm.NonceSize() {
		return nil, errors.New("invalid encrypted data")
	}

	nonce, ciphertext := ciphertext[:gcm.NonceSize()], ciphertext[gcm.NonceSize():]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	reward := new(big.Int)
	reward.SetString(string(plaintext), 10)
	return reward, nil
}
