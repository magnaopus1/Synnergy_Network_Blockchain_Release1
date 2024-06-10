package syn2369

import (
    "crypto/sha256"
    "encoding/hex"
    "fmt"
    "sync"
    "time"
)

// VirtualItem represents any type of virtual item or property in the virtual world.
type VirtualItem struct {
    ItemID      string                 `json:"itemId"`      // Unique identifier for the virtual item
    Name        string                 `json:"name"`        // Name of the item
    Description string                 `json:"description"` // Description of the item
    Type        string                 `json:"type"`        // Type of item (e.g., weapon, costume, real estate)
    Attributes  map[string]interface{} `json:"attributes"`  // Detailed attributes (color, size, power, etc.)
    Owner       string                 `json:"owner"`       // Current owner's identifier
    Creator     string                 `json:"creator"`     // Creator's identifier for original content tracking
    CreatedAt   time.Time              `json:"createdAt"`   // Creation date of the item
    UpdatedAt   time.Time              `json:"updatedAt"`   // Last update date
    Metadata    map[string]string      `json:"metadata"`    // Additional metadata for external integrations
}

// ItemLedger stores all virtual items and provides methods to interact with them.
type ItemLedger struct {
    Items map[string]VirtualItem
    mutex sync.RWMutex // ensures thread-safe access
}

// NewItemLedger initializes a new ledger to manage virtual items.
func NewItemLedger() *ItemLedger {
    return &ItemLedger{
        Items: make(map[string]VirtualItem),
    }
}

// CreateItem adds a new virtual item to the ledger.
func (il *ItemLedger) CreateItem(item VirtualItem) error {
    il.mutex.Lock()
    defer il.mutex.Unlock()

    if _, exists := il.Items[item.ItemID]; exists {
        return fmt.Errorf("item with ID %s already exists", item.ItemID)
    }

    item.ItemID = generateItemID(item.Name, item.Creator) // Generate a unique ID based on item details
    item.CreatedAt = time.Now()
    item.UpdatedAt = time.Now()
    il.Items[item.ItemID] = item
    return nil
}

// UpdateItem modifies details of an existing virtual item.
func (il *ItemLedger) UpdateItem(itemID string, updates map[string]interface{}) error {
    il.mutex.Lock()
    defer il.mutex.Unlock()

    item, exists := il.Items[itemID]
    if !exists {
        return fmt.Errorf("item with ID %s not found", itemID)
    }

    for key, value := range updates {
        item.Attributes[key] = value
    }
    item.UpdatedAt = time.Now()
    il.Items[itemID] = item
    return nil
}

// TransferOwnership changes the owner of a virtual item.
func (il *ItemLedger) TransferOwnership(itemID, newOwner string) error {
    il.mutex.Lock()
    defer il.mutex.Unlock()

    item, exists := il.Items[itemID]
    if !exists {
        return fmt.Errorf("item with ID %s not found", itemID)
    }

    item.Owner = newOwner
    item.UpdatedAt = time.Now()
    il.Items[itemID] = item
    return nil
}

// GetItem retrieves a virtual item by its ID.
func (il *ItemLedger) GetItem(itemID string) (VirtualItem, error) {
    il.mutex.RLock()
    defer il.mutex.RUnlock()

    item, exists := il.Items[itemID]
    if !exists {
        return VirtualItem{}, fmt.Errorf("item with ID %s not found", itemID)
    }
    return item, nil
}

// DeleteItem removes an item from the ledger.
func (il *ItemLedger) DeleteItem(itemID string) error {
    il.mutex.Lock()
    defer il.mutex.Unlock()

    if _, exists := il.Items[itemID]; !exists {
        return fmt.Errorf("item with ID %s not found", itemID)
    }
    delete(il.Items, itemID)
    return nil
}

// generateItemID creates a unique ID for each item based on its name and creator.
func generateItemID(name, creator string) string {
    hasher := sha256.New()
    hasher.Write([]byte(name + creator + time.Now().String()))
    return hex.EncodeToString(hasher.Sum(nil))
}
