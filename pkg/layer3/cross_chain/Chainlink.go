package cross_chain

import (
    "fmt"
    "sync"
    "errors"
)

// ChainLink represents a link between two blockchains, facilitating data and asset transfer.
type ChainLink struct {
    SourceChain      string
    DestinationChain string
    Active           bool
}

// ChainLinkManager manages the connections (links) between different blockchain networks.
type ChainLinkManager struct {
    mu       sync.Mutex
    links    map[string]*ChainLink // Map of links identified by concatenated chain names
}

// NewChainLinkManager creates a new ChainLink manager instance.
func NewChainLinkManager() *ChainLinkManager {
    return &ChainLinkManager{
        links: make(map[string]*ChainLink),
    }
}

// CreateLink establishes a new link between two blockchain networks.
func (clm *ChainLinkManager) CreateLink(sourceChain, destinationChain string) error {
    clm.mu.Lock()
    defer clm.mu.Unlock()

    linkID := fmt.Sprintf("%s-%s", sourceChain, destinationChain)
    if _, exists := clm.links[linkID]; exists {
        return fmt.Errorf("link already exists between %s and %s", sourceChain, destinationChain)
    }

    clm.links[linkID] = &ChainLink{
        SourceChain:      sourceChain,
        DestinationChain: destinationChain,
        Active:           true,
    }

    fmt.Printf("New link created between %s and %s\n", sourceChain, destinationChain)
    return nil
}

// ActivateLink activates an existing link for operations.
func (clm *ChainLinkManager) ActivateLink(sourceChain, destinationChain string) error {
    clm.mu.Lock()
    defer clm.mu.Unlock()

    linkID := fmt.Sprintf("%s-%s", sourceChain, destinationChain)
    link, exists := clm.links[linkID]
    if !exists {
        return errors.New("link does not exist")
    }

    link.Active = true
    fmt.Printf("Link activated between %s and %s\n", sourceChain, destinationChain)
    return nil
}

// DeactivateLink deactivates a link to stop operations.
func (clm *ChainLinkManager) DeactivateLink(sourceChain, destinationChain string) error {
    clm.mu.Lock()
    defer clm.mu.Unlock()

    linkID := fmt.Sprintf("%s-%s", sourceChain, destinationChain)
    link, exists := clm.links[linkID]
    if !exists {
        return errors.New("link does not exist")
    }

    link.Active = false
    fmt.Printf("Link deactivated between %s and %s\n", sourceChain, destinationChain)
    return nil
}

// GetLinkStatus checks the active status of a link between two chains.
func (clm *ChainLinkManager) GetLinkStatus(sourceChain, destinationChain string) (bool, error) {
    clm.mu.Lock()
    defer clm.mu.Unlock()

    linkID := fmt.Sprintf("%s-%s", sourceChain, destinationChain)
    link, exists := clm.links[linkID]
    if !exists {
        return false, errors.New("link does not exist")
    }

    return link.Active, nil
}

// ListLinks returns a list of all existing links and their statuses.
func (clm *ChainLinkManager) ListLinks() []string {
    clm.mu.Lock()
    defer clm.mu.Unlock()

    var linkList []string
    for id, link := range clm.links {
        status := "inactive"
        if link.Active {
            status = "active"
        }
        linkList = append(linkList, fmt.Sprintf("%s: %s", id, status))
    }
    return linkList
}
