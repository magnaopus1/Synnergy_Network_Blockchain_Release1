package smart_contracts

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/rpc"
)

// IdentityToken represents the structure of the identity token
type IdentityToken struct {
	TokenID     string    `json:"token_id"`
	Owner       string    `json:"owner"`
	FullName    string    `json:"full_name"`
	DateOfBirth time.Time `json:"date_of_birth"`
	Nationality string    `json:"nationality"`
	PhotoHash   string    `json:"photo_hash"`
	Address     string    `json:"address"`
}

// VerificationEvent represents a verification event
type VerificationEvent struct {
	TokenID   string    `json:"token_id"`
	Timestamp time.Time `json:"timestamp"`
	Status    string    `json:"status"`
	Method    string    `json:"method"`
}

// SmartContractIntegration manages interactions with smart contracts
type SmartContractIntegration struct {
	client *rpc.Client
	abi    abi.ABI
	addr   common.Address
}

// NewSmartContractIntegration initializes and returns a new SmartContractIntegration instance
func NewSmartContractIntegration(clientURL, contractABI, contractAddress string) (*SmartContractIntegration, error) {
	client, err := rpc.Dial(clientURL)
	if err != nil {
		return nil, err
	}

	parsedABI, err := abi.JSON(strings.NewReader(contractABI))
	if err != nil {
		return nil, err
	}

	addr := common.HexToAddress(contractAddress)

	return &SmartContractIntegration{
		client: client,
		abi:    parsedABI,
		addr:   addr,
	}, nil
}

// RegisterIdentityToken registers a new identity token on the blockchain
func (s *SmartContractIntegration) RegisterIdentityToken(token IdentityToken) (string, error) {
	data, err := s.abi.Pack("registerIdentityToken", token)
	if err != nil {
		return "", err
	}

	txHash, err := s.sendTransaction(data)
	if err != nil {
		return "", err
	}

	return txHash, nil
}

// VerifyIdentityToken logs a verification event for an identity token
func (s *SmartContractIntegration) VerifyIdentityToken(event VerificationEvent) (string, error) {
	data, err := s.abi.Pack("verifyIdentityToken", event)
	if err != nil {
		return "", err
	}

	txHash, err := s.sendTransaction(data)
	if err != nil {
		return "", err
	}

	return txHash, nil
}

// UpdateIdentityToken updates an existing identity token on the blockchain
func (s *SmartContractIntegration) UpdateIdentityToken(token IdentityToken) (string, error) {
	data, err := s.abi.Pack("updateIdentityToken", token)
	if err != nil {
		return "", err
	}

	txHash, err := s.sendTransaction(data)
	if err != nil {
		return "", err
	}

	return txHash, nil
}

// FetchIdentityToken retrieves an identity token from the blockchain
func (s *SmartContractIntegration) FetchIdentityToken(tokenID string) (*IdentityToken, error) {
	data, err := s.abi.Pack("getIdentityToken", tokenID)
	if err != nil {
		return nil, err
	}

	result, err := s.callContract(data)
	if err != nil {
		return nil, err
	}

	var token IdentityToken
	err = json.Unmarshal(result, &token)
	if err != nil {
		return nil, err
	}

	return &token, nil
}

// sendTransaction sends a transaction to the blockchain
func (s *SmartContractIntegration) sendTransaction(data []byte) (string, error) {
	tx := map[string]interface{}{
		"to":   s.addr.Hex(),
		"data": data,
	}

	var txHash string
	err := s.client.Call(&txHash, "eth_sendTransaction", tx)
	if err != nil {
		return "", err
	}

	return txHash, nil
}

// callContract makes a call to the smart contract
func (s *SmartContractIntegration) callContract(data []byte) ([]byte, error) {
	call := map[string]interface{}{
		"to":   s.addr.Hex(),
		"data": data,
	}

	var result json.RawMessage
	err := s.client.Call(&result, "eth_call", call, "latest")
	if err != nil {
		return nil, err
	}

	return result, nil
}

// DeleteIdentityToken removes an identity token from the blockchain
func (s *SmartContractIntegration) DeleteIdentityToken(tokenID string) (string, error) {
	data, err := s.abi.Pack("deleteIdentityToken", tokenID)
	if err != nil {
		return "", err
	}

	txHash, err := s.sendTransaction(data)
	if err != nil {
		return "", err
	}

	return txHash, nil
}
