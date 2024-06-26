package contract_interactions

import (
	"fmt"
	"log"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/ethereum/go-ethereum/rpc/web3"
)

// EventSubscription is a struct to manage event subscriptions.
type EventSubscription struct {
	quit     chan struct{}
	eventCh  chan *web3.Log
	contract common.Address
	filter   web3.FilterQuery
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

	filter := web3.FilterQuery{
		Addresses: []common.Address{contractAddress},
		Topics:    [][]common.Hash{{event.ID}},
	}

	eventCh := make(chan *web3.Log)
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
				c.handleEventLog(log)
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

// handleEventLog is a placeholder function to handle incoming event logs.
func (c *ContractInteractions) handleEventLog(log *web3.Log) {
	// Implement your event handling logic here based on the event log.
	log.Printf("Received event log: %+v\n", log)
	// You can extract data from the log using log.Data and ABI parsing.
}
