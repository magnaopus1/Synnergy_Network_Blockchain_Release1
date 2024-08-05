package management

import (
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/synnergy_network/core/tokens/token_standards/syn131/events"
	"github.com/synnergy_network/core/tokens/token_standards/syn131/security"
	"github.com/synnergy_network/core/tokens/token_standards/syn131/storage"
)

type Stakeholder struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Email       string    `json:"email"`
	JoinedAt    time.Time `json:"joined_at"`
	Role        string    `json:"role"`
	LastActive  time.Time `json:"last_active"`
}

type StakeholderEngagement struct {
	Storage         storage.Storage
	EventDispatcher events.EventDispatcher
	mutex           sync.Mutex
	stakeholders    map[string]Stakeholder
}

func NewStakeholderEngagement(storage storage.Storage, eventDispatcher events.EventDispatcher) *StakeholderEngagement {
	return &StakeholderEngagement{
		Storage:         storage,
		EventDispatcher: eventDispatcher,
		stakeholders:    make(map[string]Stakeholder),
	}
}

// RegisterStakeholder registers a new stakeholder
func (se *StakeholderEngagement) RegisterStakeholder(name, email, role string) (string, error) {
	se.mutex.Lock()
	defer se.mutex.Unlock()

	stakeholderID := fmt.Sprintf("stakeholder_%d", len(se.stakeholders)+1)
	stakeholder := Stakeholder{
		ID:         stakeholderID,
		Name:       name,
		Email:      email,
		JoinedAt:   time.Now(),
		Role:       role,
		LastActive: time.Now(),
	}

	se.stakeholders[stakeholderID] = stakeholder

	event := events.Event{
		Type:    events.StakeholderRegistered,
		Payload: map[string]interface{}{"stakeholderID": stakeholderID},
	}
	if err := se.EventDispatcher.Dispatch(event); err != nil {
		return "", fmt.Errorf("failed to dispatch stakeholder registered event: %w", err)
	}

	return stakeholderID, nil
}

// GetStakeholder retrieves a stakeholder by ID
func (se *StakeholderEngagement) GetStakeholder(stakeholderID string) (Stakeholder, error) {
	se.mutex.Lock()
	defer se.mutex.Unlock()

	stakeholder, exists := se.stakeholders[stakeholderID]
	if !exists {
		return Stakeholder{}, errors.New("stakeholder not found")
	}

	return stakeholder, nil
}

// ListStakeholders lists all registered stakeholders
func (se *StakeholderEngagement) ListStakeholders() ([]Stakeholder, error) {
	se.mutex.Lock()
	defer se.mutex.Unlock()

	var stakeholdersList []Stakeholder
	for _, stakeholder := range se.stakeholders {
		stakeholdersList = append(stakeholdersList, stakeholder)
	}

	return stakeholdersList, nil
}

// UpdateStakeholderActivity updates the last active timestamp of a stakeholder
func (se *StakeholderEngagement) UpdateStakeholderActivity(stakeholderID string) error {
	se.mutex.Lock()
	defer se.mutex.Unlock()

	stakeholder, exists := se.stakeholders[stakeholderID]
	if !exists {
		return errors.New("stakeholder not found")
	}

	stakeholder.LastActive = time.Now()
	se.stakeholders[stakeholderID] = stakeholder

	event := events.Event{
		Type:    events.StakeholderActivityUpdated,
		Payload: map[string]interface{}{"stakeholderID": stakeholderID, "lastActive": stakeholder.LastActive},
	}
	if err := se.EventDispatcher.Dispatch(event); err != nil {
		return fmt.Errorf("failed to dispatch stakeholder activity updated event: %w", err)
	}

	return nil
}

// EncryptAndStoreStakeholderData encrypts and stores sensitive stakeholder information
func (se *StakeholderEngagement) EncryptAndStoreStakeholderData(stakeholderID string, stakeholderData []byte, passphrase string) error {
	salt, err := security.GenerateSalt()
	if err != nil {
		return fmt.Errorf("failed to generate salt: %w", err)
	}

	encryptedData, err := security.Encrypt(stakeholderData, passphrase, salt)
	if err != nil {
		return fmt.Errorf("failed to encrypt stakeholder data: %w", err)
	}

	storeData := append(salt, encryptedData...)
	if err := se.Storage.Save(fmt.Sprintf("encrypted_stakeholder_%s", stakeholderID), storeData); err != nil {
		return fmt.Errorf("failed to save encrypted stakeholder data: %w", err)
	}

	return nil
}

// DecryptAndRetrieveStakeholderData decrypts and retrieves sensitive stakeholder information
func (se *StakeholderEngagement) DecryptAndRetrieveStakeholderData(stakeholderID string, passphrase string) ([]byte, error) {
	storeData, err := se.Storage.Load(fmt.Sprintf("encrypted_stakeholder_%s", stakeholderID))
	if err != nil {
		return nil, fmt.Errorf("failed to load encrypted stakeholder data: %w", err)
	}

	salt := storeData[:security.SaltSize]
	encryptedData := storeData[security.SaltSize:]

	data, err := security.Decrypt(encryptedData, passphrase, salt)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt stakeholder data: %w", err)
	}

	return data, nil
}

// GenerateStakeholderReport generates a comprehensive report of all stakeholders and their activities
func (se *StakeholderEngagement) GenerateStakeholderReport() (map[string]interface{}, error) {
	stakeholders, err := se.ListStakeholders()
	if err != nil {
		return nil, fmt.Errorf("failed to list stakeholders: %w", err)
	}

	report := make(map[string]interface{})
	for _, stakeholder := range stakeholders {
		report[stakeholder.ID] = map[string]interface{}{
			"stakeholder": stakeholder,
			"name":        stakeholder.Name,
			"email":       stakeholder.Email,
			"role":        stakeholder.Role,
			"joined_at":   stakeholder.JoinedAt,
			"last_active": stakeholder.LastActive,
		}
	}

	return report, nil
}

// RemoveStakeholder removes a stakeholder by ID
func (se *StakeholderEngagement) RemoveStakeholder(stakeholderID string) error {
	se.mutex.Lock()
	defer se.mutex.Unlock()

	if _, exists := se.stakeholders[stakeholderID]; !exists {
		return errors.New("stakeholder not found")
	}

	delete(se.stakeholders, stakeholderID)

	event := events.Event{
		Type:    events.StakeholderRemoved,
		Payload: map[string]interface{}{"stakeholderID": stakeholderID},
	}
	if err := se.EventDispatcher.Dispatch(event); err != nil {
		return fmt.Errorf("failed to dispatch stakeholder removed event: %w", err)
	}

	return nil
}
