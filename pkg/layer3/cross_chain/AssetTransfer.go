package cross_chain

import (
    "errors"
    "fmt"
    "sync"
    "time"
)

// AssetTransfer represents a request to transfer assets between blockchains.
type AssetTransfer struct {
    ID            string
    SourceChain   string
    DestinationChain string
    AssetType     string
    Amount        float64
    Status        string
    CreatedAt     time.Time
    CompletedAt   time.Time
}

// AssetTransferManager manages and processes cross-chain asset transfers.
type AssetTransferManager struct {
    mu            sync.Mutex
    transfers     map[string]*AssetTransfer
    blockchainAPI BlockchainAPI // Interface to interact with blockchain nodes
}

// BlockchainAPI defines the interface required for interacting with blockchain nodes.
type BlockchainAPI interface {
    ValidateTransfer(*AssetTransfer) bool
    ExecuteTransfer(*AssetTransfer) error
    ConfirmTransferCompletion(*AssetTransfer) bool
}

// NewAssetTransferManager creates a new asset transfer manager instance.
func NewAssetTransferManager(api BlockchainAPI) *AssetTransferManager {
    return &AssetTransferManager{
        transfers:     make(map[string]*AssetTransfer),
        blockchainAPI: api,
    }
}

// InitiateTransfer initializes a new asset transfer between blockchains.
func (atm *AssetTransferManager) InitiateTransfer(sourceChain, destinationChain, assetType string, amount float64) (*AssetTransfer, error) {
    atm.mu.Lock()
    defer atm.mu.Unlock()

    transfer := &AssetTransfer{
        ID:              fmt.Sprintf("%d", time.Now().UnixNano()), // Generate a unique ID
        SourceChain:     sourceChain,
        DestinationChain: destinationChain,
        AssetType:       assetType,
        Amount:          amount,
        Status:          "Initiated",
        CreatedAt:       time.Now(),
    }

    if !atm.blockchainAPI.ValidateTransfer(transfer) {
        return nil, errors.New("transfer validation failed")
    }

    atm.transfers[transfer.ID] = transfer
    return transfer, nil
}

// ProcessTransfer processes and completes the asset transfer.
func (atm *AssetTransferManager) ProcessTransfer(transferID string) error {
    atm.mu.Lock()
    defer atm.mu.Unlock()

    transfer, exists := atm.transfers[transferID]
    if !exists {
        return errors.New("transfer not found")
    }

    err := atm.blockchainAPI.ExecuteTransfer(transfer)
    if err != nil {
        transfer.Status = "Failed"
        return fmt.Errorf("failed to execute transfer: %v", err)
    }

    // Confirm the transfer has been completed successfully
    if atm.blockchainAPI.ConfirmTransferCompletion(transfer) {
        transfer.Status = "Completed"
        transfer.CompletedAt = time.Now()
    } else {
        transfer.Status = "Confirmation Failed"
        return errors.New("failed to confirm transfer completion")
    }

    return nil
}

// GetTransferDetails provides details of a specific asset transfer.
func (atm *AssetTransferManager) GetTransferDetails(transferID string) (*AssetTransfer, error) {
    atm.mu.Lock()
    defer atm.mu.Unlock()

    transfer, exists := atm.transfers[transferID]
    if !exists {
        return nil, errors.New("transfer not found")
    }
    return transfer, nil
}
