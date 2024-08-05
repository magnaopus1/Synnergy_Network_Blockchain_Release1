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

// VotingProposals handles the proposals and voting system in the governance system.
type VotingProposals struct {
	client       *ethclient.Client
	contractABI  abi.ABI
	contractAddr common.Address
}

// NewVotingProposals creates a new instance of VotingProposals.
func NewVotingProposals(client *ethclient.Client, contractABI abi.ABI, contractAddr common.Address) *VotingProposals {
	return &VotingProposals{
		client:       client,
		contractABI:  contractABI,
		contractAddr: contractAddr,
	}
}

// Proposal represents a governance proposal.
type Proposal struct {
	ID          string
	Title       string
	Description string
	Options     []string
	Deadline    time.Time
	Votes       map[string]*big.Int // Option -> Votes
}

// NewProposal creates a new governance proposal.
func (vp *VotingProposals) NewProposal(title, description string, options []string, deadline time.Time) (*Proposal, error) {
	// Generate a unique ID for the proposal
	proposalID := generateUniqueID(title, description, options, deadline)

	proposal := &Proposal{
		ID:          proposalID,
		Title:       title,
		Description: description,
		Options:     options,
		Deadline:    deadline,
		Votes:       make(map[string]*big.Int),
	}

	for _, option := range options {
		proposal.Votes[option] = big.NewInt(0)
	}

	// Serialize the proposal data to JSON
	proposalData, err := json.Marshal(proposal)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal proposal data: %v", err)
	}

	// Pack the transaction data
	txData, err := vp.contractABI.Pack("createProposal", proposalData)
	if err != nil {
		return nil, fmt.Errorf("failed to pack transaction data: %v", err)
	}

	// Send the transaction
	tx, err := vp.sendTransaction(txData)
	if err != nil {
		return nil, fmt.Errorf("failed to send transaction: %v", err)
	}

	log.Printf("Created new proposal with ID: %s, transaction hash: %s\n", proposal.ID, tx.Hash().Hex())
	return proposal, nil
}

// Vote casts a vote for a specific option in a proposal.
func (vp *VotingProposals) Vote(proposalID, option, voterAddress string) (string, error) {
	// Validate the proposal ID and option
	if proposalID == "" || option == "" {
		return "", errors.New("invalid proposal ID or option")
	}

	// Convert voter address to common.Address format
	voterAddr := common.HexToAddress(voterAddress)

	// Pack the transaction data
	txData, err := vp.contractABI.Pack("vote", proposalID, option, voterAddr)
	if err != nil {
		return "", fmt.Errorf("failed to pack transaction data: %v", err)
	}

	// Send the transaction
	tx, err := vp.sendTransaction(txData)
	if err != nil {
		return "", fmt.Errorf("failed to send transaction: %v", err)
	}

	log.Printf("Voted on proposal %s for option %s by address %s, transaction hash: %s\n", proposalID, option, voterAddress, tx.Hash().Hex())
	return tx.Hash().Hex(), nil
}

// GetProposal retrieves the details of a specific proposal.
func (vp *VotingProposals) GetProposal(proposalID string) (*Proposal, error) {
	// Validate the proposal ID
	if proposalID == "" {
		return nil, errors.New("invalid proposal ID")
	}

	// Call the smart contract to get the proposal details
	proposalData, err := vp.contractABI.Pack("getProposal", proposalID)
	if err != nil {
		return nil, fmt.Errorf("failed to pack transaction data: %v", err)
	}

	// Send the transaction
	tx, err := vp.sendTransaction(proposalData)
	if err != nil {
		return nil, fmt.Errorf("failed to send transaction: %v", err)
	}

	// Parse the proposal from the transaction receipt
	proposal := &Proposal{}
	if err := json.Unmarshal(tx.Data(), proposal); err != nil {
		return nil, fmt.Errorf("failed to unmarshal proposal data: %v", err)
	}

	log.Printf("Retrieved proposal %s: %v\n", proposalID, proposal)
	return proposal, nil
}

// sendTransaction sends a transaction to the blockchain.
func (vp *VotingProposals) sendTransaction(data []byte) (*types.Transaction, error) {
	// TODO: Implement the method to send a transaction using vp.client
	// This method should handle creating and sending a transaction with the provided data.
	return nil, errors.New("sendTransaction method not implemented")
}

// generateUniqueID generates a unique ID for a proposal.
func generateUniqueID(title, description string, options []string, deadline time.Time) string {
	// Generate a unique ID using a hash function
	hash := sha256.New()
	hash.Write([]byte(title))
	hash.Write([]byte(description))
	hash.Write([]byte(strings.Join(options, ",")))
	hash.Write([]byte(deadline.String()))
	return hex.EncodeToString(hash.Sum(nil))
}
