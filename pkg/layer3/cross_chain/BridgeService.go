package cross_chain

import (
    "errors"
    "sync"
    "fmt"
    "time"
)

// Bridge represents a connection between two blockchains that allows for asset transfers.
type Bridge struct {
    SourceChain      string
    DestinationChain string
    Active           bool
}

// BridgeService manages the bridges between different blockchain networks.
type BridgeService struct {
    mu       sync.Mutex
    bridges  map[string]*Bridge // Bridges are identified by a concatenation of source and destination chain names
}

// NewBridgeService creates a new bridge service instance.
func NewBridgeService() *BridgeService {
    return &BridgeService{
        bridges: make(map[string]*Bridge),
    }
}

// CreateBridge establishes a new bridge between two blockchains.
func (bs *BridgeService) CreateBridge(sourceChain, destinationChain string) error {
    bs.mu.Lock()
    defer bs.mu.Unlock()

    bridgeID := sourceChain + "-" + destinationChain
    if _, exists := bs.bridges[bridgeID]; exists {
        return fmt.Errorf("bridge already exists between %s and %s", sourceChain, destinationChain)
    }

    bs.bridges[bridgeID] = &Bridge{
        SourceChain:      sourceChain,
        DestinationChain: destinationChain,
        Active:           true,
    }

    fmt.Printf("New bridge created between %s and %s\n", sourceChain, destinationChain)
    return nil
}

// ActivateBridge activates a bridge for use.
func (bs *BridgeService) ActivateBridge(sourceChain, destinationChain string) error {
    bs.mu.Lock()
    defer bs.mu.Unlock()

    bridgeID := sourceChain + "-" + destinationChain
    bridge, exists := bs.bridges[bridgeID]
    if !exists {
        return errors.New("bridge does not exist")
    }

    bridge.Active = true
    fmt.Printf("Bridge activated between %s and %s\n", sourceChain, destinationChain)
    return nil
}

// DeactivateBridge deactivates a bridge, halting all transfers.
func (bs *BridgeService) DeactivateBridge(sourceChain, destinationChain string) error {
    bs.mu.Lock()
    defer bs.mu.Unlock()

    bridgeID := sourceChain + "-" + destinationChain
    bridge, exists := bs.bridges[bridgeID]
    if !exists {
        return errors.New("bridge does not exist")
    }

    bridge.Active = false
    fmt.Printf("Bridge deactivated between %s and %s\n", sourceChain, destinationChain)
    return nil
}

// GetBridgeStatus returns the active status of a bridge.
func (bs *BridgeService) GetBridgeStatus(sourceChain, destinationChain string) (bool, error) {
    bs.mu.Lock()
    defer bs.mu.Unlock()

    bridgeID := sourceChain + "-" + destinationChain
    bridge, exists := bs.bridges[bridgeID]
    if !exists {
        return false, errors.New("bridge does not exist")
    }

    return bridge.Active, nil
}

// ListBridges lists all existing bridges and their statuses.
func (bs *BridgeService) ListBridges() []string {
    bs.mu.Lock()
    defer bs.mu.Unlock()

    var bridgeList []string
    for id, bridge := range bs.bridges {
        status := "inactive"
        if bridge.Active {
            status = "active"
        }
        bridgeList = append(bridgeList, fmt.Sprintf("%s: %s", id, status))
    }
    return bridgeList
}
