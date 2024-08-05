package scaling_solutions

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"time"

	"golang.org/x/crypto/scrypt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"
)

// StateChannel represents a state channel in the network
type StateChannel struct {
	Participants   []common.Address
	ChannelBalance map[common.Address]*big.Int
	Nonce          uint64
	IsOpen         bool
	ChannelID      common.Hash
	ChannelLock    sync.Mutex
	Client         *ethclient.Client
}

// NewStateChannel initializes a new state channel
func NewStateChannel(participants []common.Address, clientURL string) (*StateChannel, error) {
	client, err := ethclient.Dial(clientURL)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to Ethereum client: %w", err)
	}

	channelID, err := generateChannelID(participants)
	if err != nil {
		return nil, err
	}

	channelBalance := make(map[common.Address]*big.Int)
	for _, participant := range participants {
		channelBalance[participant] = big.NewInt(0)
	}

	return &StateChannel{
		Participants:   participants,
		ChannelBalance: channelBalance,
		Nonce:          0,
		IsOpen:         true,
		ChannelID:      channelID,
		Client:         client,
	}, nil
}

// Deposit allows participants to deposit funds into the state channel
func (sc *StateChannel) Deposit(participant common.Address, amount *big.Int) error {
	sc.ChannelLock.Lock()
	defer sc.ChannelLock.Unlock()

	if !sc.IsOpen {
		return errors.New("channel is closed")
	}

	balance, exists := sc.ChannelBalance[participant]
	if !exists {
		return errors.New("participant not found in the channel")
	}

	balance.Add(balance, amount)
	return nil
}

// Withdraw allows participants to withdraw funds from the state channel
func (sc *StateChannel) Withdraw(participant common.Address, amount *big.Int) error {
	sc.ChannelLock.Lock()
	defer sc.ChannelLock.Unlock()

	if !sc.IsOpen {
		return errors.New("channel is closed")
	}

	balance, exists := sc.ChannelBalance[participant]
	if !exists {
		return errors.New("participant not found in the channel")
	}

	if balance.Cmp(amount) < 0 {
		return errors.New("insufficient balance")
	}

	balance.Sub(balance, amount)
	return nil
}

// UpdateState updates the state of the channel with a new balance
func (sc *StateChannel) UpdateState(participant common.Address, newBalance *big.Int, nonce uint64) error {
	sc.ChannelLock.Lock()
	defer sc.ChannelLock.Unlock()

	if !sc.IsOpen {
		return errors.New("channel is closed")
	}

	if nonce <= sc.Nonce {
		return errors.New("invalid nonce")
	}

	balance, exists := sc.ChannelBalance[participant]
	if !exists {
		return errors.New("participant not found in the channel")
	}

	balance.Set(newBalance)
	sc.Nonce = nonce
	return nil
}

// CloseChannel closes the state channel and settles balances on-chain
func (sc *StateChannel) CloseChannel() error {
	sc.ChannelLock.Lock()
	defer sc.ChannelLock.Unlock()

	if !sc.IsOpen {
		return errors.New("channel is already closed")
	}

	// Placeholder for on-chain settlement logic
	// TODO: Implement on-chain transaction to settle balances

	sc.IsOpen = false
	return nil
}

// generateChannelID generates a unique channel ID based on participants
func generateChannelID(participants []common.Address) (common.Hash, error) {
	data := []byte{}
	for _, participant := range participants {
		data = append(data, participant.Bytes()...)
	}

	hash := sha256.Sum256(data)
	return common.BytesToHash(hash[:]), nil
}

// scryptKey generates a key using scrypt
func scryptKey(data []byte, keyLen int) ([]byte, error) {
	salt := make([]byte, 16)
	_, err := rand.Read(salt)
	if err != nil {
		return nil, err
	}

	key, err := scrypt.Key(data, salt, 16384, 8, 1, keyLen)
	if err != nil {
		return nil, err
	}

	return key, nil
}

// signState signs the current state of the channel
func (sc *StateChannel) signState(privateKey []byte) ([]byte, error) {
	stateData := fmt.Sprintf("%v:%v:%v", sc.ChannelID.Hex(), sc.ChannelBalance, sc.Nonce)
	stateHash := sha256.Sum256([]byte(stateData))

	key, err := scryptKey(privateKey, 32)
	if err != nil {
		return nil, err
	}

	signature := make([]byte, 32)
	for i := range stateHash {
		signature[i] = stateHash[i] ^ key[i]
	}

	return signature, nil
}

// verifySignature verifies the state signature
func (sc *StateChannel) verifySignature(participant common.Address, signature []byte) (bool, error) {
	stateData := fmt.Sprintf("%v:%v:%v", sc.ChannelID.Hex(), sc.ChannelBalance, sc.Nonce)
	stateHash := sha256.Sum256([]byte(stateData))

	key, err := scryptKey(participant.Bytes(), 32)
	if err != nil {
		return false, err
	}

	for i := range stateHash {
		if signature[i] != (stateHash[i] ^ key[i]) {
			return false, nil
		}
	}

	return true, nil
}

// HandleDispute handles disputes by submitting evidence on-chain
func (sc *StateChannel) HandleDispute(participant common.Address, signature []byte) error {
	isValid, err := sc.verifySignature(participant, signature)
	if err != nil {
		return err
	}

	if !isValid {
		return errors.New("invalid signature")
	}

	// Placeholder for on-chain dispute resolution
	// TODO: Implement on-chain transaction to handle disputes

	return nil
}
