package management

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/synnergy_network/core/tokens/token_standards/syn131/events"
	"github.com/synnergy_network/core/tokens/token_standards/syn131/ledger"
	"github.com/synnergy_network/core/tokens/token_standards/syn131/security"
	"github.com/synnergy_network/core/tokens/token_standards/syn131/storage"
)

type UserInterface struct {
	Storage         storage.Storage
	EventDispatcher events.EventDispatcher
	OwnershipLedger *ledger.OwnershipLedger
	mutex           sync.Mutex
	users           map[string]User
}

type User struct {
	ID           string    `json:"id"`
	Username     string    `json:"username"`
	Email        string    `json:"email"`
	RegisteredAt time.Time `json:"registered_at"`
	LastActive   time.Time `json:"last_active"`
	Role         string    `json:"role"`
}

func NewUserInterface(storage storage.Storage, eventDispatcher events.EventDispatcher, ownershipLedger *ledger.OwnershipLedger) *UserInterface {
	return &UserInterface{
		Storage:         storage,
		EventDispatcher: eventDispatcher,
		OwnershipLedger: ownershipLedger,
		users:           make(map[string]User),
	}
}

// RegisterUser registers a new user
func (ui *UserInterface) RegisterUser(username, email, role string) (string, error) {
	ui.mutex.Lock()
	defer ui.mutex.Unlock()

	userID := fmt.Sprintf("user_%d", len(ui.users)+1)
	user := User{
		ID:           userID,
		Username:     username,
		Email:        email,
		RegisteredAt: time.Now(),
		LastActive:   time.Now(),
		Role:         role,
	}

	ui.users[userID] = user

	event := events.Event{
		Type:    events.UserRegistered,
		Payload: map[string]interface{}{"userID": userID},
	}
	if err := ui.EventDispatcher.Dispatch(event); err != nil {
		return "", fmt.Errorf("failed to dispatch user registered event: %w", err)
	}

	return userID, nil
}

// GetUser retrieves a user by ID
func (ui *UserInterface) GetUser(userID string) (User, error) {
	ui.mutex.Lock()
	defer ui.mutex.Unlock()

	user, exists := ui.users[userID]
	if !exists {
		return User{}, fmt.Errorf("user not found")
	}

	return user, nil
}

// ListUsers lists all registered users
func (ui *UserInterface) ListUsers() ([]User, error) {
	ui.mutex.Lock()
	defer ui.mutex.Unlock()

	var userList []User
	for _, user := range ui.users {
		userList = append(userList, user)
	}

	return userList, nil
}

// UpdateUserActivity updates the last active timestamp of a user
func (ui *UserInterface) UpdateUserActivity(userID string) error {
	ui.mutex.Lock()
	defer ui.mutex.Unlock()

	user, exists := ui.users[userID]
	if !exists {
		return fmt.Errorf("user not found")
	}

	user.LastActive = time.Now()
	ui.users[userID] = user

	event := events.Event{
		Type:    events.UserActivityUpdated,
		Payload: map[string]interface{}{"userID": userID, "lastActive": user.LastActive},
	}
	if err := ui.EventDispatcher.Dispatch(event); err != nil {
		return fmt.Errorf("failed to dispatch user activity updated event: %w", err)
	}

	return nil
}

// EncryptAndStoreUserData encrypts and stores sensitive user information
func (ui *UserInterface) EncryptAndStoreUserData(userID string, userData []byte, passphrase string) error {
	salt, err := security.GenerateSalt()
	if err != nil {
		return fmt.Errorf("failed to generate salt: %w", err)
	}

	encryptedData, err := security.Encrypt(userData, passphrase, salt)
	if err != nil {
		return fmt.Errorf("failed to encrypt user data: %w", err)
	}

	storeData := append(salt, encryptedData...)
	if err := ui.Storage.Save(fmt.Sprintf("encrypted_user_%s", userID), storeData); err != nil {
		return fmt.Errorf("failed to save encrypted user data: %w", err)
	}

	return nil
}

// DecryptAndRetrieveUserData decrypts and retrieves sensitive user information
func (ui *UserInterface) DecryptAndRetrieveUserData(userID string, passphrase string) ([]byte, error) {
	storeData, err := ui.Storage.Load(fmt.Sprintf("encrypted_user_%s", userID))
	if err != nil {
		return nil, fmt.Errorf("failed to load encrypted user data: %w", err)
	}

	salt := storeData[:security.SaltSize]
	encryptedData := storeData[security.SaltSize:]

	data, err := security.Decrypt(encryptedData, passphrase, salt)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt user data: %w", err)
	}

	return data, nil
}

// GenerateUserReport generates a comprehensive report of all users and their activities
func (ui *UserInterface) GenerateUserReport() (map[string]interface{}, error) {
	users, err := ui.ListUsers()
	if err != nil {
		return nil, fmt.Errorf("failed to list users: %w", err)
	}

	report := make(map[string]interface{})
	for _, user := range users {
		report[user.ID] = map[string]interface{}{
			"user":         user,
			"username":     user.Username,
			"email":        user.Email,
			"role":         user.Role,
			"registered_at": user.RegisteredAt,
			"last_active":  user.LastActive,
		}
	}

	return report, nil
}

// RemoveUser removes a user by ID
func (ui *UserInterface) RemoveUser(userID string) error {
	ui.mutex.Lock()
	defer ui.mutex.Unlock()

	if _, exists := ui.users[userID]; !exists {
		return fmt.Errorf("user not found")
	}

	delete(ui.users, userID)

	event := events.Event{
		Type:    events.UserRemoved,
		Payload: map[string]interface{}{"userID": userID},
	}
	if err := ui.EventDispatcher.Dispatch(event); err != nil {
		return fmt.Errorf("failed to dispatch user removed event: %w", err)
	}

	return nil
}

// ServeHTTP implements the HTTP handler interface for user-related endpoints
func (ui *UserInterface) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		ui.handlePost(w, r)
	case http.MethodGet:
		ui.handleGet(w, r)
	case http.MethodPut:
		ui.handlePut(w, r)
	case http.MethodDelete:
		ui.handleDelete(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (ui *UserInterface) handlePost(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Email    string `json:"email"`
		Role     string `json:"role"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	userID, err := ui.RegisterUser(req.Username, req.Email, req.Role)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	resp := map[string]string{"userID": userID}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (ui *UserInterface) handleGet(w http.ResponseWriter, r *http.Request) {
	userID := r.URL.Query().Get("userID")
	if userID == "" {
		users, err := ui.ListUsers()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(users)
	} else {
		user, err := ui.GetUser(userID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(user)
	}
}

func (ui *UserInterface) handlePut(w http.ResponseWriter, r *http.Request) {
	var req struct {
		UserID string `json:"userID"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if err := ui.UpdateUserActivity(req.UserID); err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (ui *UserInterface) handleDelete(w http.ResponseWriter, r *http.Request) {
	var req struct {
		UserID string `json:"userID"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if err := ui.RemoveUser(req.UserID); err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
