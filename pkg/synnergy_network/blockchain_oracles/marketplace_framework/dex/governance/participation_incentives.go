package governance

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/big"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"
)

// ParticipationIncentives handles the incentives for participation in the governance system.
type ParticipationIncentives struct {
	client       *ethclient.Client
	contractABI  abi.ABI
	contractAddr common.Address
}

// NewParticipationIncentives creates a new instance of ParticipationIncentives.
func NewParticipationIncentives(client *ethclient.Client, contractABI abi.ABI, contractAddr common.Address) *ParticipationIncentives {
	return &ParticipationIncentives{
		client:       client,
		contractABI:  contractABI,
		contractAddr: contractAddr,
	}
}

// Incentive represents a governance incentive.
type Incentive struct {
	ID          string
	Description string
	Reward      *big.Int
	Deadline    time.Time
}

// NewIncentive creates a new governance incentive.
func (pi *ParticipationIncentives) NewIncentive(description string, reward *big.Int, deadline time.Time) (*Incentive, error) {
	// Generate a unique ID for the incentive
	incentiveID := generateUniqueID(description, reward, deadline)

	incentive := &Incentive{
		ID:          incentiveID,
		Description: description,
		Reward:      reward,
		Deadline:    deadline,
	}

	// Serialize the incentive data to JSON
	incentiveData, err := json.Marshal(incentive)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal incentive data: %v", err)
	}

	// Pack the transaction data
	txData, err := pi.contractABI.Pack("createIncentive", incentiveData)
	if err != nil {
		return nil, fmt.Errorf("failed to pack transaction data: %v", err)
	}

	// Send the transaction
	tx, err := pi.sendTransaction(txData)
	if err != nil {
		return nil, fmt.Errorf("failed to send transaction: %v", err)
	}

	log.Printf("Created new incentive with ID: %s, transaction hash: %s\n", incentive.ID, tx.Hash().Hex())
	return incentive, nil
}

// ClaimIncentive claims an incentive for a specific address.
func (pi *ParticipationIncentives) ClaimIncentive(incentiveID, claimerAddress string) (string, error) {
	// Validate the incentive ID
	if incentiveID == "" {
		return "", errors.New("invalid incentive ID")
	}

	// Convert claimer address to common.Address format
	claimerAddr := common.HexToAddress(claimerAddress)

	// Pack the transaction data
	txData, err := pi.contractABI.Pack("claimIncentive", incentiveID, claimerAddr)
	if err != nil {
		return "", fmt.Errorf("failed to pack transaction data: %v", err)
	}

	// Send the transaction
	tx, err := pi.sendTransaction(txData)
	if err != nil {
		return "", fmt.Errorf("failed to send transaction: %v", err)
	}

	log.Printf("Claimed incentive %s for address %s, transaction hash: %s\n", incentiveID, claimerAddress, tx.Hash().Hex())
	return tx.Hash().Hex(), nil
}

// GetIncentive retrieves the details of a specific incentive.
func (pi *ParticipationIncentives) GetIncentive(incentiveID string) (*Incentive, error) {
	// Validate the incentive ID
	if incentiveID == "" {
		return nil, errors.New("invalid incentive ID")
	}

	// Call the smart contract to get the incentive details
	incentiveData, err := pi.contractABI.Pack("getIncentive", incentiveID)
	if err != nil {
		return nil, fmt.Errorf("failed to pack transaction data: %v", err)
	}

	// Send the transaction
	tx, err := pi.sendTransaction(incentiveData)
	if err != nil {
		return nil, fmt.Errorf("failed to send transaction: %v", err)
	}

	// Parse the incentive from the transaction receipt
	incentive := &Incentive{}
	if err := json.Unmarshal(tx.Data(), incentive); err != nil {
		return nil, fmt.Errorf("failed to unmarshal incentive data: %v", err)
	}

	log.Printf("Retrieved incentive %s: %v\n", incentiveID, incentive)
	return incentive, nil
}

// sendTransaction sends a transaction to the blockchain.
func (pi *ParticipationIncentives) sendTransaction(data []byte) (*types.Transaction, error) {
	// TODO: Implement the method to send a transaction using pi.client
	// This method should handle creating and sending a transaction with the provided data.
	return nil, errors.New("sendTransaction method not implemented")
}

// generateUniqueID generates a unique ID for an incentive.
func generateUniqueID(description string, reward *big.Int, deadline time.Time) string {
	// Generate a unique ID using a hash function
	hash := sha256.New()
	hash.Write([]byte(description))
	hash.Write([]byte(reward.String()))
	hash.Write([]byte(deadline.String()))
	return hex.EncodeToString(hash.Sum(nil))
}
