package assets

import (
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"
)

type PairLinking struct {
	PairLinks map[string]PairLink
	mutex     sync.Mutex
}

type PairLink struct {
	TokenID        string    `json:"token_id"`
	ForexPairID    string    `json:"forex_pair_id"`
	Linked         bool      `json:"linked"`
	LastLinkedTime time.Time `json:"last_linked_time"`
}

// InitializePairLinking initializes the PairLinking structure
func InitializePairLinking() *PairLinking {
	return &PairLinking{
		PairLinks: make(map[string]PairLink),
	}
}

// LinkPair links a Forex token to a specific Forex pair
func (pl *PairLinking) LinkPair(tokenID, forexPairID string) error {
	pl.mutex.Lock()
	defer pl.mutex.Unlock()

	if _, exists := pl.PairLinks[tokenID]; exists {
		return errors.New("token already linked to a pair")
	}

	pl.PairLinks[tokenID] = PairLink{
		TokenID:        tokenID,
		ForexPairID:    forexPairID,
		Linked:         true,
		LastLinkedTime: time.Now(),
	}

	return nil
}

// UnlinkPair unlinks a Forex token from its Forex pair
func (pl *PairLinking) UnlinkPair(tokenID string) error {
	pl.mutex.Lock()
	defer pl.mutex.Unlock()

	link, exists := pl.PairLinks[tokenID]
	if !exists {
		return errors.New("token not linked to any pair")
	}

	link.Linked = false
	link.LastLinkedTime = time.Now()
	pl.PairLinks[tokenID] = link

	return nil
}

// GetPairLink retrieves the link details of a Forex token
func (pl *PairLinking) GetPairLink(tokenID string) (PairLink, error) {
	pl.mutex.Lock()
	defer pl.mutex.Unlock()

	link, exists := pl.PairLinks[tokenID]
	if !exists {
		return PairLink{}, errors.New("token not linked to any pair")
	}

	return link, nil
}

// IsLinked checks if a Forex token is currently linked to a Forex pair
func (pl *PairLinking) IsLinked(tokenID string) (bool, error) {
	pl.mutex.Lock()
	defer pl.mutex.Unlock()

	link, exists := pl.PairLinks[tokenID]
	if !exists {
		return false, errors.New("token not linked to any pair")
	}

	return link.Linked, nil
}

// SaveToFile saves the pair links to a file
func (pl *PairLinking) SaveToFile(filename string) error {
	pl.mutex.Lock()
	defer pl.mutex.Unlock()

	data, err := json.Marshal(pl.PairLinks)
	if err != nil {
		return err
	}

	return ioutil.WriteFile(filename, data, 0644)
}

// LoadFromFile loads the pair links from a file
func (pl *PairLinking) LoadFromFile(filename string) error {
	pl.mutex.Lock()
	defer pl.mutex.Unlock()

	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return err
	}

	return json.Unmarshal(data, &pl.PairLinks)
}

// DisplayPairLink displays the link details of a token in a readable format
func (pl *PairLinking) DisplayPairLink(tokenID string) error {
	link, err := pl.GetPairLink(tokenID)
	if err != nil {
		return err
	}

	fmt.Printf("Token ID: %s\nForex Pair ID: %s\nLinked: %t\nLast Linked Time: %s\n", link.TokenID, link.ForexPairID, link.Linked, link.LastLinkedTime)
	return nil
}
