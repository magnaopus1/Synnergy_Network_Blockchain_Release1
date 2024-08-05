package upgrades

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"
)

// ModularDesign provides methods for managing modular design upgrades in the blockchain network
type ModularDesign struct {
	Modules  map[string]Module
	APIKey   string
	SecretKey string
	Mutex    sync.Mutex
}

// Module represents a module in the blockchain network
type Module struct {
	Name        string
	Version     string
	Enabled     bool
	Dependencies []string
}

// NewModularDesign creates a new instance of ModularDesign
func NewModularDesign(apiKey, secretKey string) *ModularDesign {
	return &ModularDesign{
		Modules:   make(map[string]Module),
		APIKey:    apiKey,
		SecretKey: secretKey,
	}
}

// AddModule adds a new module to the blockchain network
func (md *ModularDesign) AddModule(name, version string, dependencies []string) error {
	md.Mutex.Lock()
	defer md.Mutex.Unlock()

	if _, exists := md.Modules[name]; exists {
		return fmt.Errorf("module %s already exists", name)
	}

	md.Modules[name] = Module{
		Name:        name,
		Version:     version,
		Enabled:     false,
		Dependencies: dependencies,
	}

	md.logModuleActivity("add", name)
	return nil
}

// RemoveModule removes a module from the blockchain network
func (md *ModularDesign) RemoveModule(name string) error {
	md.Mutex.Lock()
	defer md.Mutex.Unlock()

	if _, exists := md.Modules[name]; !exists {
		return fmt.Errorf("module %s does not exist", name)
	}

	delete(md.Modules, name)
	md.logModuleActivity("remove", name)
	return nil
}

// EnableModule enables a module in the blockchain network
func (md *ModularDesign) EnableModule(name string) error {
	md.Mutex.Lock()
	defer md.Mutex.Unlock()

	module, exists := md.Modules[name]
	if !exists {
		return fmt.Errorf("module %s does not exist", name)
	}

	// Check dependencies
	for _, dep := range module.Dependencies {
		if depModule, depExists := md.Modules[dep]; !depExists || !depModule.Enabled {
			return fmt.Errorf("dependency %s for module %s is not enabled", dep, name)
		}
	}

	module.Enabled = true
	md.Modules[name] = module

	md.logModuleActivity("enable", name)
	return nil
}

// DisableModule disables a module in the blockchain network
func (md *ModularDesign) DisableModule(name string) error {
	md.Mutex.Lock()
	defer md.Mutex.Unlock()

	module, exists := md.Modules[name]
	if !exists {
		return fmt.Errorf("module %s does not exist", name)
	}

	// Check if any other modules depend on this module
	for _, mod := range md.Modules {
		for _, dep := range mod.Dependencies {
			if dep == name && mod.Enabled {
				return fmt.Errorf("module %s cannot be disabled as it is a dependency for enabled module %s", name, mod.Name)
			}
		}
	}

	module.Enabled = false
	md.Modules[name] = module

	md.logModuleActivity("disable", name)
	return nil
}

// IsModuleEnabled checks if a module is enabled in the blockchain network
func (md *ModularDesign) IsModuleEnabled(name string) bool {
	md.Mutex.Lock()
	defer md.Mutex.Unlock()

	module, exists := md.Modules[name]
	return exists && module.Enabled
}

// logModuleActivity logs the activity related to module management
func (md *ModularDesign) logModuleActivity(action, moduleName string) {
	logEntry := map[string]interface{}{
		"action":    action,
		"module":    moduleName,
		"timestamp": time.Now(),
	}

	// In a real-world scenario, this would be logged to a file, database, or monitoring system
	fmt.Printf("Module Log: %v\n", logEntry)
}

// EncryptData encrypts data using AES
func (md *ModularDesign) EncryptData(data map[string]interface{}) (string, error) {
	md.Mutex.Lock()
	defer md.Mutex.Unlock()

	hashedKey := sha256.Sum256([]byte(md.SecretKey))
	block, err := aes.NewCipher(hashedKey[:])
	if err != nil {
		return "", err
	}

	dataBytes, err := json.Marshal(data)
	if err != nil {
		return "", err
	}

	ciphertext := make([]byte, aes.BlockSize+len(dataBytes))
	iv := ciphertext[:aes.BlockSize]

	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], dataBytes)

	return base64.URLEncoding.EncodeToString(ciphertext), nil
}

// DecryptData decrypts data using AES
func (md *ModularDesign) DecryptData(encryptedData string) (map[string]interface{}, error) {
	md.Mutex.Lock()
	defer md.Mutex.Unlock()

	hashedKey := sha256.Sum256([]byte(md.SecretKey))
	block, err := aes.NewCipher(hashedKey[:])
	if err != nil {
		return nil, err
	}

	ciphertext, err := base64.URLEncoding.DecodeString(encryptedData)
	if err != nil {
		return nil, err
	}

	if len(ciphertext) < aes.BlockSize {
		return nil, errors.New("ciphertext too short")
	}

	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(ciphertext, ciphertext)

	var data map[string]interface{}
	if err := json.Unmarshal(ciphertext, &data); err != nil {
		return nil, err
	}

	return data, nil
}

// HandleModuleRequest handles requests for enabling or disabling modules
func (md *ModularDesign) HandleModuleRequest(request map[string]interface{}) (map[string]interface{}, error) {
	action, ok := request["action"].(string)
	if !ok {
		return nil, errors.New("invalid request: missing action")
	}

	moduleName, ok := request["moduleName"].(string)
	if !ok {
		return nil, errors.New("invalid request: missing moduleName")
	}

	var response map[string]interface{}
	var err error

	switch action {
	case "enable":
		err = md.EnableModule(moduleName)
		response = map[string]interface{}{
			"status":  "success",
			"message": fmt.Sprintf("module %s enabled", moduleName),
		}
	case "disable":
		err = md.DisableModule(moduleName)
		response = map[string]interface{}{
			"status":  "success",
			"message": fmt.Sprintf("module %s disabled", moduleName),
		}
	default:
		err = errors.New("invalid action")
		response = map[string]interface{}{
			"status":  "error",
			"message": "invalid action",
		}
	}

	if err != nil {
		return map[string]interface{}{
			"status":  "error",
			"message": err.Error(),
		}, err
	}

	return response, nil
}

// AddAdditionalSecurityHeaders adds additional security headers to the API request
func (md *ModularDesign) AddAdditionalSecurityHeaders(req *http.Request) {
	req.Header.Set("X-Request-ID", generateRequestID())
	req.Header.Set("X-Timestamp", fmt.Sprintf("%d", time.Now().Unix()))
}

// generateRequestID generates a unique request ID for tracking purposes
func generateRequestID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return fmt.Sprintf("%x", b)
}
