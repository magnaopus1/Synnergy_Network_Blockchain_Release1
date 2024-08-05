package interoperability

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"
)

// ComposableContract represents a smart contract that can interact with other contracts
type ComposableContract struct {
	ID          string
	Code        string
	Dependencies []string
	State       map[string]interface{}
	Mutex       sync.Mutex
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// NewComposableContract creates a new instance of ComposableContract
func NewComposableContract(id, code string, dependencies []string) *ComposableContract {
	return &ComposableContract{
		ID:          id,
		Code:        code,
		Dependencies: dependencies,
		State:       make(map[string]interface{}),
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}
}

// Execute runs the contract code with the given inputs
func (cc *ComposableContract) Execute(inputs map[string]interface{}) (map[string]interface{}, error) {
	cc.Mutex.Lock()
	defer cc.Mutex.Unlock()

	// Update the state with the inputs
	for k, v := range inputs {
		cc.State[k] = v
	}

	// Simulate executing the contract code
	// In a real-world scenario, this would involve more complex logic
	result := make(map[string]interface{})
	result["status"] = "success"
	result["updatedState"] = cc.State

	cc.UpdatedAt = time.Now()

	return result, nil
}

// AddDependency adds a new dependency to the contract
func (cc *ComposableContract) AddDependency(dependency string) {
	cc.Mutex.Lock()
	defer cc.Mutex.Unlock()

	cc.Dependencies = append(cc.Dependencies, dependency)
	cc.UpdatedAt = time.Now()
}

// RemoveDependency removes a dependency from the contract
func (cc *ComposableContract) RemoveDependency(dependency string) error {
	cc.Mutex.Lock()
	defer cc.Mutex.Unlock()

	for i, d := range cc.Dependencies {
		if d == dependency {
			cc.Dependencies = append(cc.Dependencies[:i], cc.Dependencies[i+1:]...)
			cc.UpdatedAt = time.Now()
			return nil
		}
	}

	return fmt.Errorf("dependency %s not found", dependency)
}

// EncryptState encrypts the contract state using AES
func (cc *ComposableContract) EncryptState(secret string) (string, error) {
	cc.Mutex.Lock()
	defer cc.Mutex.Unlock()

	hashedKey := sha256.Sum256([]byte(secret))
	block, err := aes.NewCipher(hashedKey[:])
	if err != nil {
		return "", err
	}

	stateBytes, err := json.Marshal(cc.State)
	if err != nil {
		return "", err
	}

	ciphertext := make([]byte, aes.BlockSize+len(stateBytes))
	iv := ciphertext[:aes.BlockSize]

	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], stateBytes)

	return base64.URLEncoding.EncodeToString(ciphertext), nil
}

// DecryptState decrypts the contract state using AES
func (cc *ComposableContract) DecryptState(secret, encryptedState string) error {
	cc.Mutex.Lock()
	defer cc.Mutex.Unlock()

	hashedKey := sha256.Sum256([]byte(secret))
	block, err := aes.NewCipher(hashedKey[:])
	if err != nil {
		return err
	}

	ciphertext, err := base64.URLEncoding.DecodeString(encryptedState)
	if err != nil {
		return err
	}

	if len(ciphertext) < aes.BlockSize {
		return errors.New("ciphertext too short")
	}

	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(ciphertext, ciphertext)

	if err := json.Unmarshal(ciphertext, &cc.State); err != nil {
		return err
	}

	return nil
}

// CallDependency calls a dependency contract and updates the state
func (cc *ComposableContract) CallDependency(dependencyID string, inputs map[string]interface{}) (map[string]interface{}, error) {
	cc.Mutex.Lock()
	defer cc.Mutex.Unlock()

	// Simulate calling the dependency contract
	// In a real-world scenario, this would involve more complex logic, possibly involving cross-chain communication
	if dependencyID == "" {
		return nil, errors.New("dependency ID cannot be empty")
	}

	result := make(map[string]interface{})
	for k, v := range inputs {
		result[k] = v
	}

	cc.State[dependencyID] = result
	cc.UpdatedAt = time.Now()

	return result, nil
}

// GetState returns the current state of the contract
func (cc *ComposableContract) GetState() map[string]interface{} {
	cc.Mutex.Lock()
	defer cc.Mutex.Unlock()

	return cc.State
}

// UpdateState updates the state of the contract with the given inputs
func (cc *ComposableContract) UpdateState(inputs map[string]interface{}) {
	cc.Mutex.Lock()
	defer cc.Mutex.Unlock()

	for k, v := range inputs {
		cc.State[k] = v
	}

	cc.UpdatedAt = time.Now()
}
