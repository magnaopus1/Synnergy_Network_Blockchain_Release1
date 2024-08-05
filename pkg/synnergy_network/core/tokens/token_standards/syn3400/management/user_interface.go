package management

import (
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"
)

// UserInterface represents the interface for managing and interacting with Forex tokens
type UserInterface struct {
	Users          map[string]User
	ForexContracts *ForexSmartContractManager
	mutex          sync.Mutex
}

// User represents a user in the system
type User struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Email     string    `json:"email"`
	CreatedAt time.Time `json:"created_at"`
}

// NewUserInterface initializes the UserInterface structure
func NewUserInterface() *UserInterface {
	return &UserInterface{
		Users:          make(map[string]User),
		ForexContracts: NewForexSmartContractManager(),
	}
}

// RegisterUser registers a new user
func (ui *UserInterface) RegisterUser(id, name, email string) error {
	ui.mutex.Lock()
	defer ui.mutex.Unlock()

	if _, exists := ui.Users[id]; exists {
		return errors.New("user already exists")
	}

	user := User{
		ID:        id,
		Name:      name,
		Email:     email,
		CreatedAt: time.Now(),
	}

	ui.Users[id] = user

	// Log user registration
	ui.logUserEvent(user, "USER_REGISTERED")

	return nil
}

// GetUser retrieves a user by ID
func (ui *UserInterface) GetUser(id string) (User, error) {
	ui.mutex.Lock()
	defer ui.mutex.Unlock()

	user, exists := ui.Users[id]
	if !exists {
		return User{}, errors.New("user not found")
	}

	return user, nil
}

// ListUsers lists all registered users
func (ui *UserInterface) ListUsers() []User {
	ui.mutex.Lock()
	defer ui.mutex.Unlock()

	users := make([]User, 0, len(ui.Users))
	for _, user := range ui.Users {
		users = append(users, user)
	}
	return users
}

// CreateForexContract creates a new Forex smart contract
func (ui *UserInterface) CreateForexContract(userID, contractID, code string) error {
	ui.mutex.Lock()
	defer ui.mutex.Unlock()

	if _, exists := ui.Users[userID]; !exists {
		return errors.New("user not found")
	}

	contract := ForexSmartContract{
		ContractID:       contractID,
		Owner:            userID,
		Code:             code,
		DeploymentDate:   time.Now(),
		LastUpdatedDate:  time.Now(),
		ActivationStatus: false,
	}

	err := ui.ForexContracts.AddContract(contract)
	if err != nil {
		return err
	}

	// Log contract creation
	ui.logContractEvent(contract, "CONTRACT_CREATED")

	return nil
}

// UpdateForexContract updates an existing Forex smart contract
func (ui *UserInterface) UpdateForexContract(userID, contractID, code string) error {
	ui.mutex.Lock()
	defer ui.mutex.Unlock()

	if _, exists := ui.Users[userID]; !exists {
		return errors.New("user not found")
	}

	contract, err := ui.ForexContracts.GetContract(contractID)
	if err != nil {
		return err
	}

	if contract.Owner != userID {
		return errors.New("user is not the owner of the contract")
	}

	contract.Code = code
	contract.LastUpdatedDate = time.Now()

	err = ui.ForexContracts.UpdateContract(contract)
	if err != nil {
		return err
	}

	// Log contract update
	ui.logContractEvent(contract, "CONTRACT_UPDATED")

	return nil
}

// ActivateForexContract activates a Forex smart contract
func (ui *UserInterface) ActivateForexContract(userID, contractID string) error {
	ui.mutex.Lock()
	defer ui.mutex.Unlock()

	if _, exists := ui.Users[userID]; !exists {
		return errors.New("user not found")
	}

	contract, err := ui.ForexContracts.GetContract(contractID)
	if err != nil {
		return err
	}

	if contract.Owner != userID {
		return errors.New("user is not the owner of the contract")
	}

	err = ui.ForexContracts.ActivateContract(contractID)
	if err != nil {
		return err
	}

	// Log contract activation
	ui.logContractEvent(contract, "CONTRACT_ACTIVATED")

	return nil
}

// DeactivateForexContract deactivates a Forex smart contract
func (ui *UserInterface) DeactivateForexContract(userID, contractID string) error {
	ui.mutex.Lock()
	defer ui.mutex.Unlock()

	if _, exists := ui.Users[userID]; !exists {
		return errors.New("user not found")
	}

	contract, err := ui.ForexContracts.GetContract(contractID)
	if err != nil {
		return err
	}

	if contract.Owner != userID {
		return errors.New("user is not the owner of the contract")
	}

	err = ui.ForexContracts.DeactivateContract(contractID)
	if err != nil {
		return err
	}

	// Log contract deactivation
	ui.logContractEvent(contract, "CONTRACT_DEACTIVATED")

	return nil
}

// ListUserContracts lists all Forex smart contracts owned by a user
func (ui *UserInterface) ListUserContracts(userID string) ([]ForexSmartContract, error) {
	ui.mutex.Lock()
	defer ui.mutex.Unlock()

	if _, exists := ui.Users[userID]; !exists {
		return nil, errors.New("user not found")
	}

	contracts := ui.ForexContracts.ListContracts()
	userContracts := make([]ForexSmartContract, 0)
	for _, contract := range contracts {
		if contract.Owner == userID {
			userContracts = append(userContracts, contract)
		}
	}
	return userContracts, nil
}

// logUserEvent logs events related to user actions
func (ui *UserInterface) logUserEvent(user User, eventType string) {
	event := map[string]interface{}{
		"event_type": eventType,
		"user_id":    user.ID,
		"timestamp":  time.Now().UTC(),
	}
	eventData, _ := json.Marshal(event)
	fmt.Println(string(eventData))
}

// logContractEvent logs events related to smart contracts
func (ui *UserInterface) logContractEvent(contract ForexSmartContract, eventType string) {
	event := map[string]interface{}{
		"event_type":      eventType,
		"contract_id":     contract.ContractID,
		"owner":           contract.Owner,
		"timestamp":       time.Now().UTC(),
		"activation_status": contract.ActivationStatus,
	}
	eventData, _ := json.Marshal(event)
	fmt.Println(string(eventData))
}
