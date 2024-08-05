package smart_contracts

import (
	"errors"
	"fmt"
	"log"
	"sync"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rpc"
)

// SmartContractIntegration provides methods to interact with smart contracts
type SmartContractIntegration struct {
	mu             sync.Mutex
	client         *rpc.Client
	auth           *bind.TransactOpts
	contractAddress string
}

// NewSmartContractIntegration creates a new instance of SmartContractIntegration
func NewSmartContractIntegration(rpcURL, privateKey, contractAddress string) (*SmartContractIntegration, error) {
	client, err := rpc.Dial(rpcURL)
	if err != nil {
		return nil, err
	}

	auth, err := bind.NewTransactorWithChainID(crypto.NewKeyedTransactor(privateKey), big.NewInt(1)) // Assuming chain ID is 1, adjust as necessary
	if err != nil {
		return nil, err
	}

	return &SmartContractIntegration{
		client:         client,
		auth:           auth,
		contractAddress: contractAddress,
	}, nil
}

// DeploySmartContract deploys a new instance of the smart contract
func (sci *SmartContractIntegration) DeploySmartContract(contractABI, bytecode string, params ...interface{}) (string, error) {
	sci.mu.Lock()
	defer sci.mu.Unlock()

	address, tx, _, err := bind.DeployContract(sci.auth, bind.NewBoundContract(contractABI, sci.client), common.FromHex(bytecode), sci.client, params...)
	if err != nil {
		return "", err
	}

	fmt.Printf("Contract deployed! Wait for the transaction %s to be mined...\n", tx.Hash().Hex())

	return address.Hex(), nil
}

// CallSmartContractFunction calls a read-only function of the smart contract
func (sci *SmartContractIntegration) CallSmartContractFunction(contractABI, functionName string, result interface{}, params ...interface{}) error {
	sci.mu.Lock()
	defer sci.mu.Unlock()

	contract := bind.NewBoundContract(sci.contractAddress, contractABI, sci.client, sci.client, sci.client)

	callOpts := &bind.CallOpts{
		Pending: false,
		From:    sci.auth.From,
	}

	return contract.Call(callOpts, result, functionName, params...)
}

// TransactSmartContractFunction calls a state-changing function of the smart contract
func (sci *SmartContractIntegration) TransactSmartContractFunction(contractABI, functionName string, params ...interface{}) (string, error) {
	sci.mu.Lock()
	defer sci.mu.Unlock()

	contract := bind.NewBoundContract(sci.contractAddress, contractABI, sci.client, sci.client, sci.client)

	tx, err := contract.Transact(sci.auth, functionName, params...)
	if err != nil {
		return "", err
	}

	fmt.Printf("Transaction sent! Wait for the transaction %s to be mined...\n", tx.Hash().Hex())

	return tx.Hash().Hex(), nil
}

// QuerySmartContractEvent queries a specific event from the smart contract
func (sci *SmartContractIntegration) QuerySmartContractEvent(contractABI, eventName string, startBlock, endBlock uint64, result interface{}) error {
	sci.mu.Lock()
	defer sci.mu.Unlock()

	contract := bind.NewBoundContract(sci.contractAddress, contractABI, sci.client, sci.client, sci.client)

	query := ethereum.FilterQuery{
		FromBlock: big.NewInt(int64(startBlock)),
		ToBlock:   big.NewInt(int64(endBlock)),
		Addresses: []common.Address{common.HexToAddress(sci.contractAddress)},
		Topics:    [][]common.Hash{[]common.Hash{crypto.Keccak256Hash([]byte(eventName))}},
	}

	logs, err := sci.client.FilterLogs(context.Background(), query)
	if err != nil {
		return err
	}

	contract.UnpackLog(result, eventName, logs)
	return nil
}

// VerifySmartContractInteraction verifies if a specific interaction with the smart contract was successful
func (sci *SmartContractIntegration) VerifySmartContractInteraction(txHash string) (bool, error) {
	sci.mu.Lock()
	defer sci.mu.Unlock()

	receipt, err := sci.client.TransactionReceipt(context.Background(), common.HexToHash(txHash))
	if err != nil {
		return false, err
	}

	return receipt.Status == 1, nil
}
