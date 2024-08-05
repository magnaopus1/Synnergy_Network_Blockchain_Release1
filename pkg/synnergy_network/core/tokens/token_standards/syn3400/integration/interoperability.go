package integration

import (
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn3400/assets"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn3400/events"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn3400/ledger"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn3400/transactions"
)

type Interoperability struct {
	ConnectedChains map[string]ChainInfo
	mutex           sync.Mutex
	EventLogger     *events.EventLogging
	TransactionLog  *ledger.ForexTransactionLedger
}

type ChainInfo struct {
	ChainID       string `json:"chain_id"`
	ChainName     string `json:"chain_name"`
	Endpoint      string `json:"endpoint"`
	LastConnected time.Time `json:"last_connected"`
}

// InitializeInteroperability initializes the Interoperability structure
func InitializeInteroperability() *Interoperability {
	return &Interoperability{
		ConnectedChains: make(map[string]ChainInfo),
		EventLogger:     events.InitializeEventLogging(),
		TransactionLog:  ledger.InitializeForexTransactionLedger(),
	}
}

// ConnectChain connects a new blockchain to the interoperability system
func (iop *Interoperability) ConnectChain(chainID, chainName, endpoint string) error {
	iop.mutex.Lock()
	defer iop.mutex.Unlock()

	if _, exists := iop.ConnectedChains[chainID]; exists {
		return errors.New("chain already connected")
	}

	iop.ConnectedChains[chainID] = ChainInfo{
		ChainID:       chainID,
		ChainName:     chainName,
		Endpoint:      endpoint,
		LastConnected: time.Now(),
	}

	iop.EventLogger.LogEvent(fmt.Sprintf("chain-connected-%s", chainID), "CHAIN_CONNECTED", fmt.Sprintf("Connected to chain: %s", chainName))

	return nil
}

// DisconnectChain disconnects a blockchain from the interoperability system
func (iop *Interoperability) DisconnectChain(chainID string) error {
	iop.mutex.Lock()
	defer iop.mutex.Unlock()

	if _, exists := iop.ConnectedChains[chainID]; !exists {
		return errors.New("chain not connected")
	}

	delete(iop.ConnectedChains, chainID)

	iop.EventLogger.LogEvent(fmt.Sprintf("chain-disconnected-%s", chainID), "CHAIN_DISCONNECTED", fmt.Sprintf("Disconnected from chain: %s", chainID))

	return nil
}

// GetChainInfo retrieves information about a connected blockchain
func (iop *Interoperability) GetChainInfo(chainID string) (ChainInfo, error) {
	iop.mutex.Lock()
	defer iop.mutex.Unlock()

	chainInfo, exists := iop.ConnectedChains[chainID]
	if !exists {
		return ChainInfo{}, errors.New("chain not connected")
	}

	return chainInfo, nil
}

// RelayTransaction relays a transaction to a connected blockchain
func (iop *Interoperability) RelayTransaction(chainID string, transaction transactions.Transaction) error {
	iop.mutex.Lock()
	defer iop.mutex.Unlock()

	chainInfo, exists := iop.ConnectedChains[chainID]
	if !exists {
		return errors.New("chain not connected")
	}

	// Relay the transaction to the connected blockchain (simulated)
	fmt.Printf("Relaying transaction to chain: %s\n", chainInfo.ChainName)

	// Log the transaction in the local ledger
	err := iop.TransactionLog.LogTransaction(transaction.TransactionID, "RELAY", transaction.PairID, transaction.BaseCurrency, transaction.QuoteCurrency, transaction.Amount)
	if err != nil {
		return err
	}

	iop.EventLogger.LogEvent(fmt.Sprintf("transaction-relayed-%s", transaction.TransactionID), "TRANSACTION_RELAYED", fmt.Sprintf("Transaction relayed to chain: %s", chainInfo.ChainName))

	return nil
}

// SaveChainsToFile saves the connected chains information to a file
func (iop *Interoperability) SaveChainsToFile(filename string) error {
	iop.mutex.Lock()
	defer iop.mutex.Unlock()

	data, err := json.Marshal(iop.ConnectedChains)
	if err != nil {
		return err
	}

	return os.WriteFile(filename, data, 0644)
}

// LoadChainsFromFile loads the connected chains information from a file
func (iop *Interoperability) LoadChainsFromFile(filename string) error {
	iop.mutex.Lock()
	defer iop.mutex.Unlock()

	data, err := os.ReadFile(filename)
	if err != nil {
		return err
	}

	return json.Unmarshal(data, &iop.ConnectedChains)
}

// DisplayChainInfo displays the information of a connected blockchain in a readable format
func (iop *Interoperability) DisplayChainInfo(chainID string) error {
	chainInfo, err := iop.GetChainInfo(chainID)
	if err != nil {
		return err
	}

	fmt.Printf("Chain ID: %s\nChain Name: %s\nEndpoint: %s\nLast Connected: %s\n", chainInfo.ChainID, chainInfo.ChainName, chainInfo.Endpoint, chainInfo.LastConnected)
	return nil
}
