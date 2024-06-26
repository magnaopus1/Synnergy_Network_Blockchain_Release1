package contract_interactions

import (
	"fmt"
	"log"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/rpc"
)

// ContractInteractions is a struct to manage contract interactions.
type ContractInteractions struct {
	client *rpc.Client
}

// NewContractInteractions initializes a new instance of ContractInteractions.
func NewContractInteractions(rpcURL string) (*ContractInteractions, error) {
	client, err := rpc.Dial(rpcURL)
	if err != nil {
		return nil, err
	}
	return &ContractInteractions{client: client}, nil
}

// CallContractConstantMethod calls a constant (read-only) method of a smart contract.
func (c *ContractInteractions) CallContractConstantMethod(contractAddress common.Address, abiJSON string, methodName string, params ...interface{}) (*big.Int, error) {
	parsedABI, err := abi.JSON(strings.NewReader(abiJSON))
	if err != nil {
		return nil, err
	}

	data, err := parsedABI.Pack(methodName, params...)
	if err != nil {
		return nil, err
	}

	msg := ethereum.CallMsg{
		To:   &contractAddress,
		Data: data,
	}

	result, err := c.client.CallContract(context.Background(), msg, nil)
	if err != nil {
		return nil, err
	}

	if len(result) == 0 {
		return nil, errors.New("no result from contract call")
	}

	var resultInt big.Int
	err = parsedABI.Unpack(&resultInt, methodName, result)
	if err != nil {
		return nil, err
	}

	return &resultInt, nil
}

// SendTransaction sends a transaction to a smart contract.
func (c *ContractInteractions) SendTransaction(privateKey *ecdsa.PrivateKey, contractAddress common.Address, abiJSON string, methodName string, value *big.Int, params ...interface{}) (common.Hash, error) {
	// Implement sending a transaction here using private key, contract address, ABI, method name, and parameters.
	// Return the transaction hash.
}

// EventSubscription is a struct to manage event subscriptions.
type EventSubscription struct {
	quit     chan struct{}
	eventCh  chan *types.Log
	contract common.Address
	filter   ethereum.FilterQuery
}

// NewEventSubscription initializes a new instance of EventSubscription.
func (c *ContractInteractions) NewEventSubscription(contractAddress common.Address, abiJSON string, eventName string) (*EventSubscription, error) {
	parsedABI, err := abi.JSON(strings.NewReader(abiJSON))
	if err != nil {
		return nil, err
	}

	event := parsedABI.Events[eventName]
	if event == nil {
		return nil, fmt.Errorf("event %s not found in ABI", eventName)
	}

	filter := ethereum.FilterQuery{
		Addresses: []common.Address{contractAddress},
		Topics:    [][]common.Hash{{event.ID}},
	}

	eventCh := make(chan *types.Log)
	quit := make(chan struct{})

	sub, err := c.client.SubscribeFilterLogs(context.Background(), filter, eventCh)
	if err != nil {
		return nil, err
	}

	go func() {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-eventCh:
				// Handle the event log.
			case <-quit:
				return
			}
		}
	}()

	return &EventSubscription{
		quit:     quit,
		eventCh:  eventCh,
		contract: contractAddress,
		filter:   filter,
	}, nil
}

// Unsubscribe unsubscribes from the event.
func (es *EventSubscription) Unsubscribe() {
	close(es.quit)
}

// Implement other contract interaction functions as needed.
