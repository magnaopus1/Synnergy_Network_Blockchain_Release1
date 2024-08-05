package data_channels

import (
	"errors"
	"fmt"
	"sync"
	"time"
)

// UseCase represents a specific use case for a data channel
type UseCase struct {
	ChannelID string
	UseCaseID string
	Data      []byte
	Timestamp time.Time
	Status    string
	lock      sync.RWMutex
}

const (
	UseCaseActive   = "ACTIVE"
	UseCaseInactive = "INACTIVE"
	UseCaseClosed   = "CLOSED"
)

// NewUseCase initializes a new use case for a data channel
func NewUseCase(channelID, useCaseID string, data []byte) *UseCase {
	return &UseCase{
		ChannelID: channelID,
		UseCaseID: useCaseID,
		Data:      data,
		Timestamp: time.Now(),
		Status:    UseCaseActive,
	}
}

// UpdateUseCaseData updates the data of the use case
func (uc *UseCase) UpdateUseCaseData(newData []byte) error {
	uc.lock.Lock()
	defer uc.lock.Unlock()

	if uc.Status != UseCaseActive {
		return errors.New("cannot update data of an inactive or closed use case")
	}

	uc.Data = newData
	uc.Timestamp = time.Now()
	return nil
}

// CloseUseCase closes the use case
func (uc *UseCase) CloseUseCase() error {
	uc.lock.Lock()
	defer uc.lock.Unlock()

	if uc.Status != UseCaseActive {
		return errors.New("use case is not active")
	}

	uc.Status = UseCaseClosed
	uc.Timestamp = time.Now()
	return nil
}

// ValidateUseCase performs validation on the use case data
func (uc *UseCase) ValidateUseCase() error {
	uc.lock.RLock()
	defer uc.lock.RUnlock()

	if len(uc.Data) == 0 {
		return errors.New("use case data cannot be empty")
	}

	return nil
}

func (uc *UseCase) String() string {
	return fmt.Sprintf("ChannelID: %s, UseCaseID: %s, Status: %s, Timestamp: %s", uc.ChannelID, uc.UseCaseID, uc.Status, uc.Timestamp)
}

// IsActive checks if the use case is active
func (uc *UseCase) IsActive() bool {
	uc.lock.RLock()
	defer uc.lock.RUnlock()
	return uc.Status == UseCaseActive
}

// IsClosed checks if the use case is closed
func (uc *UseCase) IsClosed() bool {
	uc.lock.RLock()
	defer uc.lock.RUnlock()
	return uc.Status == UseCaseClosed
}

// GetData returns the data of the use case
func (uc *UseCase) GetData() []byte {
	uc.lock.RLock()
	defer uc.lock.RUnlock()
	return uc.Data
}

// GetStatus returns the status of the use case
func (uc *UseCase) GetStatus() string {
	uc.lock.RLock()
	defer uc.lock.RUnlock()
	return uc.Status
}

// UpdateTimestamp updates the timestamp of the use case
func (uc *UseCase) UpdateTimestamp() {
	uc.lock.Lock()
	defer uc.lock.Unlock()
	uc.Timestamp = time.Now()
}

// GetTimestamp returns the timestamp of the use case
func (uc *UseCase) GetTimestamp() time.Time {
	uc.lock.RLock()
	defer uc.lock.RUnlock()
	return uc.Timestamp
}

// AddUseCaseNote adds a note to the use case
func (uc *UseCase) AddUseCaseNote(note string) {
	uc.lock.Lock()
	defer uc.lock.Unlock()
	uc.Data = append(uc.Data, []byte(note)...)
	uc.Timestamp = time.Now()
}

// RemoveUseCaseNote removes a note from the use case
func (uc *UseCase) RemoveUseCaseNote(note string) error {
	uc.lock.Lock()
	defer uc.lock.Unlock()
	noteBytes := []byte(note)
	noteIndex := -1
	for i := 0; i < len(uc.Data)-len(noteBytes); i++ {
		if string(uc.Data[i:i+len(noteBytes)]) == note {
			noteIndex = i
			break
		}
	}
	if noteIndex == -1 {
		return errors.New("note not found")
	}
	uc.Data = append(uc.Data[:noteIndex], uc.Data[noteIndex+len(noteBytes):]...)
	uc.Timestamp = time.Now()
	return nil
}

// ListUseCaseNotes lists all notes in the use case
func (uc *UseCase) ListUseCaseNotes() []string {
	uc.lock.RLock()
	defer uc.lock.RUnlock()
	notes := []string{}
	note := ""
	for _, b := range uc.Data {
		if b == '\n' {
			notes = append(notes, note)
			note = ""
		} else {
			note += string(b)
		}
	}
	if note != "" {
		notes = append(notes, note)
	}
	return notes
}
