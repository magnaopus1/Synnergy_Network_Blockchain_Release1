package allocation

import (
	"sync"
	"errors"
)

// Priority levels defined for various blockchain operations.
const (
	LowPriority    = 1
	MediumPriority = 2
	HighPriority   = 3
	CriticalPriority = 4
)

// Priority defines the structure for resource allocation priorities.
type Priority struct {
	mutex     sync.Mutex
	priorities map[string]int
}

// NewPriority creates a new Priority manager instance.
func NewPriority() *Priority {
	return &Priority{
		priorities: make(map[string]int),
	}
}

// SetPriority sets the priority level for a specific transaction or operation.
func (p *Priority) SetPriority(key string, level int) error {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	if level < LowPriority || level > CriticalPriority {
		return errors.New("invalid priority level")
	}

	p.priorities[key] = level
	return nil
}

// GetPriority retrieves the priority level for a given key.
func (p *Priority) GetPriority(key string) (int, error) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	level, exists := p.priorities[key]
	if !exists {
		return 0, errors.New("priority not found")
	}

	return level, nil
}

// RemovePriority removes the priority setting for a given key.
func (p *Priority) RemovePriority(key string) error {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	_, exists := p.priorities[key]
	if !exists {
		return errors.New("priority not found")
	}

	delete(p.priorities, key)
	return nil
}

// UpdatePriority adjusts the priority of an existing key.
func (p *Priority) UpdatePriority(key string, level int) error {
	return p.SetPriority(key, level)
}

// ListPriorities lists all current priority settings.
func (p *Priority) ListPriorities() map[string]int {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	// Return a copy to prevent modification.
	copied := make(map[string]int)
	for key, value := range p.priorities {
		copied[key] = value
	}
	return copied
}

// ClearAllPriorities clears all priority settings.
func (p *Priority) ClearAllPriorities() {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	p.priorities = make(map[string]int)
}

