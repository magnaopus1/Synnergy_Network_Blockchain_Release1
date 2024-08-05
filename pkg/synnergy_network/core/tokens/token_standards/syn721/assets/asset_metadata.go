package assets

import (
	"fmt"
	"sync"
	"time"
)

// Metadata represents the metadata of a SYN721 token
type Metadata struct {
	ID             string
	Name           string
	Description    string
	ImageURI       string
	MusicURI       string
	AnimationURI   string
	ModelURI       string
	SpriteURI      string
	Domain         string
	Attributes     map[string]string
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// MetadataHistory records changes to metadata over time
type MetadataHistory struct {
	ID        string
	Changes   []MetadataChange
	mutex     sync.Mutex
}

// MetadataChange represents a change to the metadata
type MetadataChange struct {
	Timestamp time.Time
	OldValue  Metadata
	NewValue  Metadata
}

// MetadataManager manages metadata for SYN721 tokens
type MetadataManager struct {
	metadataStore map[string]Metadata
	historyStore  map[string]MetadataHistory
	mutex         sync.Mutex
}

// NewMetadataManager initializes a new MetadataManager
func NewMetadataManager() *MetadataManager {
	return &MetadataManager{
		metadataStore: make(map[string]Metadata),
		historyStore:  make(map[string]MetadataHistory),
	}
}

// AddMetadata adds new metadata for a SYN721 token
func (m *MetadataManager) AddMetadata(id, name, description, imageURI, musicURI, animationURI, modelURI, spriteURI, domain string, attributes map[string]string) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if _, exists := m.metadataStore[id]; exists {
		return fmt.Errorf("metadata with ID %s already exists", id)
	}

	metadata := Metadata{
		ID:             id,
		Name:           name,
		Description:    description,
		ImageURI:       imageURI,
		MusicURI:       musicURI,
		AnimationURI:   animationURI,
		ModelURI:       modelURI,
		SpriteURI:      spriteURI,
		Domain:         domain,
		Attributes:     attributes,
		CreatedAt:      time.Now(),
		UpdatedAt:      time.Now(),
	}

	m.metadataStore[id] = metadata
	m.historyStore[id] = MetadataHistory{
		ID: id,
		Changes: []MetadataChange{
			{
				Timestamp: time.Now(),
				OldValue:  Metadata{},
				NewValue:  metadata,
			},
		},
	}

	return nil
}

// UpdateMetadata updates existing metadata for a SYN721 token
func (m *MetadataManager) UpdateMetadata(id, name, description, imageURI, musicURI, animationURI, modelURI, spriteURI, domain string, attributes map[string]string) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	metadata, exists := m.metadataStore[id]
	if !exists {
		return fmt.Errorf("metadata with ID %s not found", id)
	}

	oldMetadata := metadata

	metadata.Name = name
	metadata.Description = description
	metadata.ImageURI = imageURI
	metadata.MusicURI = musicURI
	metadata.AnimationURI = animationURI
	metadata.ModelURI = modelURI
	metadata.SpriteURI = spriteURI
	metadata.Domain = domain
	metadata.Attributes = attributes
	metadata.UpdatedAt = time.Now()

	m.metadataStore[id] = metadata
	m.recordChange(id, oldMetadata, metadata)

	return nil
}

// GetMetadata retrieves metadata for a SYN721 token by ID
func (m *MetadataManager) GetMetadata(id string) (Metadata, error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	metadata, exists := m.metadataStore[id]
	if !exists {
		return Metadata{}, fmt.Errorf("metadata with ID %s not found", id)
	}

	return metadata, nil
}

// GetMetadataHistory retrieves the metadata change history for a SYN721 token by ID
func (m *MetadataManager) GetMetadataHistory(id string) (MetadataHistory, error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	history, exists := m.historyStore[id]
	if !exists {
		return MetadataHistory{}, fmt.Errorf("metadata history with ID %s not found", id)
	}

	return history, nil
}

// recordChange records a metadata change in the history
func (m *MetadataManager) recordChange(id string, oldMetadata, newMetadata Metadata) {
	history, exists := m.historyStore[id]
	if !exists {
		history = MetadataHistory{
			ID:      id,
			Changes: []MetadataChange{},
		}
	}

	change := MetadataChange{
		Timestamp: time.Now(),
		OldValue:  oldMetadata,
		NewValue:  newMetadata,
	}

	history.mutex.Lock()
	history.Changes = append(history.Changes, change)
	history.mutex.Unlock()

	m.historyStore[id] = history
}
