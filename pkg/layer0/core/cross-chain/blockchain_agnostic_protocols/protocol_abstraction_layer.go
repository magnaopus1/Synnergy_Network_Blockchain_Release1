package crosschain

import (
	"errors"
	"sync"
)

// BlockchainProtocol defines a standard interface for interacting with different blockchain technologies.
type BlockchainProtocol interface {
	SendTransaction(data TransactionData) (string, error)
	GetTransactionStatus(txID string) (TransactionStatus, error)
	Connect() error
}

// TransactionData holds the necessary details for blockchain transactions.
type TransactionData struct {
	From    string
	To      string
	Amount  float64
	Payload string
}

// TransactionStatus represents the status of a transaction in the blockchain.
type TransactionStatus struct {
	TxID      string
	Confirmed bool
	FailureReason string
}

// ProtocolAbstractionLayer provides a unified interface to interact with various blockchain protocols.
type ProtocolAbstractionLayer struct {
	protocols map[string]BlockchainProtocol
	mu        sync.RWMutex
}

// NewProtocolAbstractionLayer initializes a new instance of ProtocolAbstractionLayer.
func NewProtocolAbstractionLayer() *ProtocolAbstractionLayer {
	return &ProtocolAbstractionLayer{
		protocols: make(map[string]BlockchainProtocol),
	}
}

// RegisterProtocol adds a new blockchain protocol to the abstraction layer.
func (pal *ProtocolAbstractionLayer) RegisterProtocol(protocolName string, protocol BlockchainProtocol) error {
	pal.mu.Lock()
	defer pal.mu.Unlock()

	if _, exists := pal.protocols[protocolName]; exists {
		return errors.New("protocol already registered")
	}

	pal.protocols[protocolName] = protocol
	return nil
}

// UnregisterProtocol removes a blockchain protocol from the abstraction layer.
func (pal *ProtocolAbstractionLayer) UnregisterProtocol(protocolName string) error {
	pal.mu.Lock()
	defer pal.mu.Unlock()

	if _, exists := pal.protocols[protocolName]; !exists {
		return errors.New("protocol not found")
	}

	delete(pal.protocols, protocolName)
	return nil
}

// SendTransaction abstracts the transaction sending process to any registered blockchain.
func (pal *ProtocolAbstractionLayer) SendTransaction(protocolName string, data TransactionData) (string, error) {
	pal.mu.RLock()
	protocol, exists := pal.protocols[protocolName]
	pal.mu.RUnlock()

	if !exists {
		return "", errors.New("protocol not supported")
	}

	return protocol.SendTransaction(data)
}

// GetTransactionStatus abstracts the process of fetching transaction status from any registered blockchain.
func (pal *ProtocolAbstractionLayer) GetTransactionStatus(protocolName, txID string) (TransactionStatus, error) {
	pal.mu.RLock()
	protocol, exists := pal.protocols[protocolName]
	pal.mu.RUnlock()

	if !exists {
		return TransactionStatus{}, errors.New("protocol not supported")
	}

	return protocol.GetTransactionStatus(txID)
}

// Example of a blockchain protocol implementation
type EthereumProtocol struct {
	// Connection details for Ethereum network
}

func (e *EthereumProtocol) SendTransaction(data TransactionData) (string, error) {
	// Implement sending transaction to Ethereum
	return "eth_tx_id_123", nil
}

func (e *EthereumProtocol) GetTransactionStatus(txID string) (TransactionStatus, error) {
	// Implement checking transaction status on Ethereum
	return TransactionStatus{TxID: txID, Confirmed: true}, nil
}

func (e *EthereumProtocol) Connect() error {
	// Connect to Ethereum network
	return nil
}

func main() {
	pal := NewProtocolAbstractionLayer()
	ethereum := &EthereumProtocol{}
	err := pal.RegisterProtocol("ethereum", ethereum)
	if err != nil {
		panic(err)
	}

	// Example usage
	txData := TransactionData{
		From:   "0xABC",
		To:     "0xDEF",
		Amount: 1.23,
		Payload: "Transfer",
	}
	txID, err := pal.SendTransaction("ethereum", txData)
	if err != nil {
		panic(err)
	}

	status, err := pal.GetTransactionStatus("ethereum", txID)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Transaction %s confirmed: %v\n", status.TxID, status.Confirmed)
}
