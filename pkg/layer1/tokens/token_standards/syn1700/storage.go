package syn1700

import (
	"sync"
	"fmt"
)

// Storage interface defines the methods to interact with the data layer for events and tickets.
type Storage interface {
	SaveEvent(event Event) error
	GetEvent(eventID string) (Event, error)
	UpdateEvent(event Event) error
	ListEvents() ([]Event, error)
}

// InMemoryStorage implements Storage interface using an in-memory map.
type InMemoryStorage struct {
	sync.RWMutex
	events map[string]Event
}

// NewInMemoryStorage initializes a new instance of InMemoryStorage.
func NewInMemoryStorage() *InMemoryStorage {
	return &InMemoryStorage{
		events: make(map[string]Event),
	}
}

// SaveEvent stores an event in the memory.
func (s *InMemoryStorage) SaveEvent(event Event) error {
	s.Lock()
	defer s.Unlock()

	if _, exists := s.events[event.ID]; exists {
		return fmt.Errorf("event with ID %s already exists", event.ID)
	}

	s.events[event.ID] = event
	return nil
}

// GetEvent retrieves an event by its ID.
func (s *InMemoryStorage) GetEvent(eventID string) (Event, error) {
	s.RLock()
	defer s.RUnlock()

	event, exists := s.events[eventID]
	if !exists {
		return Event{}, fmt.Errorf("no event found with ID %s", eventID)
	}
	return event, nil
}

// UpdateEvent updates an existing event.
func (s *InMemoryStorage) UpdateEvent(event Event) error {
	s.Lock()
	defer s.Unlock()

	if _, exists := s.events[event.ID]; !exists {
		return fmt.Errorf("no event found with ID %s to update", event.ID)
	}

	s.events[event.ID] = event
	return nil
}

// ListEvents returns a list of all events.
func (s *InMemoryStorage) ListEvents() ([]Event, error) {
	s.RLock()
	defer s.RUnlock()

	eventsList := make([]Event, 0, len(s.events))
	for _, event := range s.events {
		eventsList = append(eventsList, event)
	}
	return eventsList, nil
}
