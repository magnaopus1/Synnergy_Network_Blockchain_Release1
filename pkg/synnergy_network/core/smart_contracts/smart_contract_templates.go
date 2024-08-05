package smart_contract_templates

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"
)

// NewAIEnhancedTemplate creates a new AI-enhanced smart contract template
func NewAIEnhancedTemplate(name, description, version string, parameters map[string]interface{}) (*AIEnhancedTemplate, error) {
	id, err := generateTemplateID(name, description, version)
	if err != nil {
		return nil, err
	}
	return &AIEnhancedTemplate{
		ID:          id,
		Name:        name,
		Description: description,
		Version:     version,
		Parameters:  parameters,
		LastUpdated: time.Now(),
	}, nil
}

// generateTemplateID generates a unique ID for the AI-enhanced template
func generateTemplateID(name, description, version string) (string, error) {
	data := fmt.Sprintf("%s:%s:%s:%d", name, description, version, time.Now().UnixNano())
	id, err := argon2Key([]byte(data), nil)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", id), nil
}

// argon2Key generates a key using the Argon2id key derivation function
func argon2Key(password, salt []byte) ([]byte, error) {
	if salt == nil {
		salt = make([]byte, 16)
		if _, err := rand.Read(salt); err != nil {
			return nil, err
		}
	}
	return argon2.IDKey(password, salt, 1, 64*1024, 4, 32), nil
}

// UpdateTemplate updates the template's parameters and AI model
func (t *AIEnhancedTemplate) UpdateTemplate(parameters map[string]interface{}, aiModel []byte) error {
	t.mutex.Lock()
	defer t.mutex.Unlock()

	t.Parameters = parameters
	t.AIModel = aiModel
	t.LastUpdated = time.Now()
	return nil
}

// EncryptAIModel encrypts the AI model using AES
func (t *AIEnhancedTemplate) EncryptAIModel(key []byte) error {
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return err
	}
	t.AIModel = gcm.Seal(nonce, nonce, t.AIModel, nil)
	return nil
}

// DecryptAIModel decrypts the AI model using AES
func (t *AIEnhancedTemplate) DecryptAIModel(key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	if len(t.AIModel) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}
	nonce, ciphertext := t.AIModel[:nonceSize], t.AIModel[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

// ValidateTemplate validates the template parameters using AI model
func (t *AIEnhancedTemplate) ValidateTemplate(input map[string]interface{}) (bool, error) {
	// Placeholder for AI validation logic
	// For example, run input through a trained AI model to validate parameters
	return true, nil
}

// SerializeTemplate serializes the template to JSON
func (t *AIEnhancedTemplate) SerializeTemplate() ([]byte, error) {
	t.mutex.Lock()
	defer t.mutex.Unlock()

	return json.Marshal(t)
}

// DeserializeTemplate deserializes the JSON data to an AIEnhancedTemplate
func DeserializeTemplate(data []byte) (*AIEnhancedTemplate, error) {
	var template AIEnhancedTemplate
	if err := json.Unmarshal(data, &template); err != nil {
		return nil, err
	}
	return &template, nil
}

// StoreTemplate securely stores the template in a storage system
func (t *AIEnhancedTemplate) StoreTemplate(storage Storage) error {
	t.mutex.Lock()
	defer t.mutex.Unlock()

	data, err := t.SerializeTemplate()
	if err != nil {
		return err
	}
	return storage.Store(t.ID, data)
}

// LoadTemplate loads the template from a storage system
func LoadTemplate(storage Storage, id string) (*AIEnhancedTemplate, error) {
	data, err := storage.Load(id)
	if err != nil {
		return nil, err
	}
	return DeserializeTemplate(data)
}

// Storage interface defines methods for storing and loading templates
type Storage interface {
	Store(id string, data []byte) error
	Load(id string) ([]byte, error)
	Delete(id string) error
}

// Example of a simple in-memory storage
type InMemoryStorage struct {
	data map[string][]byte
	mu   sync.Mutex
}

func NewInMemoryStorage() *InMemoryStorage {
	return &InMemoryStorage{data: make(map[string][]byte)}
}

func (s *InMemoryStorage) Store(id string, data []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data[id] = data
	return nil
}

func (s *InMemoryStorage) Load(id string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, exists := s.data[id]
	if !exists {
		return nil, errors.New("template not found")
	}
	return data, nil
}

func (s *InMemoryStorage) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.data, id)
	return nil
}

// NewCrossChainTemplate creates a new cross-chain template
func NewCrossChainTemplate(name, description, version string, parameters map[string]interface{}, chains []string) (*CrossChainTemplate, error) {
	id, err := generateTemplateID(name, description, version)
	if err != nil {
		return nil, err
	}
	return &CrossChainTemplate{
		ID:          id,
		Name:        name,
		Description: description,
		Version:     version,
		Parameters:  parameters,
		Chains:      chains,
		LastUpdated: time.Now(),
	}, nil
}

// generateTemplateID generates a unique ID for the cross-chain template
func generateTemplateID(name, description, version string) (string, error) {
	data := fmt.Sprintf("%s:%s:%s:%d", name, description, version, time.Now().UnixNano())
	id, err := argon2Key([]byte(data), nil)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", id), nil
}

// argon2Key generates a key using the Argon2id key derivation function
func argon2Key(password, salt []byte) ([]byte, error) {
	if salt == nil {
		salt = make([]byte, 16)
		if _, err := rand.Read(salt); err != nil {
			return nil, err
		}
	}
	return argon2.IDKey(password, salt, 1, 64*1024, 4, 32), nil
}

// UpdateTemplate updates the template's parameters
func (t *CrossChainTemplate) UpdateTemplate(parameters map[string]interface{}, chains []string) error {
	t.mutex.Lock()
	defer t.mutex.Unlock()

	t.Parameters = parameters
	t.Chains = chains
	t.LastUpdated = time.Now()
	return nil
}

// EncryptTemplateData encrypts the template data using AES
func (t *CrossChainTemplate) EncryptTemplateData(key []byte) error {
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return err
	}
	encryptedData := gcm.Seal(nonce, nonce, t.SerializeTemplate(), nil)
	t.Parameters["encryptedData"] = hex.EncodeToString(encryptedData)
	return nil
}

// DecryptTemplateData decrypts the template data using AES
func (t *CrossChainTemplate) DecryptTemplateData(key []byte) ([]byte, error) {
	encryptedData, ok := t.Parameters["encryptedData"].(string)
	if !ok {
		return nil, errors.New("encrypted data not found in parameters")
	}
	data, err := hex.DecodeString(encryptedData)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

// ValidateTemplate validates the template parameters
func (t *CrossChainTemplate) ValidateTemplate() (bool, error) {
	// Placeholder for validation logic
	// For example, check required fields, types, and cross-chain compatibility
	return true, nil
}

// SerializeTemplate serializes the template to JSON
func (t *CrossChainTemplate) SerializeTemplate() []byte {
	t.mutex.Lock()
	defer t.mutex.Unlock()

	data, _ := json.Marshal(t)
	return data
}

// DeserializeTemplate deserializes the JSON data to a CrossChainTemplate
func DeserializeTemplate(data []byte) (*CrossChainTemplate, error) {
	var template CrossChainTemplate
	if err := json.Unmarshal(data, &template); err != nil {
		return nil, err
	}
	return &template, nil
}

// DeployTemplate deploys the template to the specified chains
func (t *CrossChainTemplate) DeployTemplate() error {
	t.mutex.Lock()
	defer t.mutex.Unlock()

	for _, chain := range t.Chains {
		// Placeholder for deployment logic to each specified chain
		// This could involve interacting with different blockchain APIs
		fmt.Printf("Deploying template %s to chain %s\n", t.Name, chain)
	}
	t.LastUpdated = time.Now()
	return nil
}

// StoreTemplate securely stores the template in a storage system
func (t *CrossChainTemplate) StoreTemplate(storage Storage) error {
	t.mutex.Lock()
	defer t.mutex.Unlock()

	data := t.SerializeTemplate()
	return storage.Store(t.ID, data)
}

// LoadTemplate loads the template from a storage system
func LoadTemplate(storage Storage, id string) (*CrossChainTemplate, error) {
	data, err := storage.Load(id)
	if err != nil {
		return nil, err
	}
	return DeserializeTemplate(data)
}

// Storage interface defines methods for storing and loading templates
type Storage interface {
	Store(id string, data []byte) error
	Load(id string) ([]byte, error)
	Delete(id string) error
}

// Example of a simple in-memory storage
type InMemoryStorage struct {
	data map[string][]byte
	mu   sync.Mutex
}

func NewInMemoryStorage() *InMemoryStorage {
	return &InMemoryStorage{data: make(map[string][]byte)}
}

func (s *InMemoryStorage) Store(id string, data []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data[id] = data
	return nil
}

func (s *InMemoryStorage) Load(id string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, exists := s.data[id]
	if !exists {
		return nil, errors.New("template not found")
	}
	return data, nil
}

func (s *InMemoryStorage) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.data, id)
	return nil
}


// NewIndustrySpecificTemplate creates a new industry-specific template
func NewIndustrySpecificTemplate(name, industry, description, version string, parameters map[string]interface{}) (*IndustrySpecificTemplate, error) {
	id, err := generateTemplateID(name, industry, version)
	if err != nil {
		return nil, err
	}
	return &IndustrySpecificTemplate{
		ID:          id,
		Name:        name,
		Industry:    industry,
		Description: description,
		Version:     version,
		Parameters:  parameters,
		LastUpdated: time.Now(),
	}, nil
}

// generateTemplateID generates a unique ID for the industry-specific template
func generateTemplateID(name, industry, version string) (string, error) {
	data := fmt.Sprintf("%s:%s:%s:%d", name, industry, version, time.Now().UnixNano())
	id, err := argon2Key([]byte(data), nil)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", id), nil
}

// argon2Key generates a key using the Argon2id key derivation function
func argon2Key(password, salt []byte) ([]byte, error) {
	if salt == nil {
		salt = make([]byte, 16)
		if _, err := rand.Read(salt); err != nil {
			return nil, err
		}
	}
	return argon2.IDKey(password, salt, 1, 64*1024, 4, 32), nil
}

// UpdateTemplate updates the template's parameters and AI model
func (t *IndustrySpecificTemplate) UpdateTemplate(parameters map[string]interface{}, aiModel []byte) error {
	t.mutex.Lock()
	defer t.mutex.Unlock()

	t.Parameters = parameters
	t.AIModel = aiModel
	t.LastUpdated = time.Now()
	return nil
}

// EncryptAIModel encrypts the AI model using AES
func (t *IndustrySpecificTemplate) EncryptAIModel(key []byte) error {
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return err
	}
	t.AIModel = gcm.Seal(nonce, nonce, t.AIModel, nil)
	return nil
}

// DecryptAIModel decrypts the AI model using AES
func (t *IndustrySpecificTemplate) DecryptAIModel(key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	if len(t.AIModel) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}
	nonce, ciphertext := t.AIModel[:nonceSize], t.AIModel[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

// ValidateTemplate validates the template parameters using AI model
func (t *IndustrySpecificTemplate) ValidateTemplate(input map[string]interface{}) (bool, error) {
	// Placeholder for AI validation logic
	// For example, run input through a trained AI model to validate parameters
	return true, nil
}

// SerializeTemplate serializes the template to JSON
func (t *IndustrySpecificTemplate) SerializeTemplate() ([]byte, error) {
	t.mutex.Lock()
	defer t.mutex.Unlock()

	return json.Marshal(t)
}

// DeserializeTemplate deserializes the JSON data to an IndustrySpecificTemplate
func DeserializeTemplate(data []byte) (*IndustrySpecificTemplate, error) {
	var template IndustrySpecificTemplate
	if err := json.Unmarshal(data, &template); err != nil {
		return nil, err
	}
	return &template, nil
}

// StoreTemplate securely stores the template in a storage system
func (t *IndustrySpecificTemplate) StoreTemplate(storage Storage) error {
	t.mutex.Lock()
	defer t.mutex.Unlock()

	data, err := t.SerializeTemplate()
	if err != nil {
		return err
	}
	return storage.Store(t.ID, data)
}

// LoadTemplate loads the template from a storage system
func LoadTemplate(storage Storage, id string) (*IndustrySpecificTemplate, error) {
	data, err := storage.Load(id)
	if err != nil {
		return nil, err
	}
	return DeserializeTemplate(data)
}

// Storage interface defines methods for storing and loading templates
type Storage interface {
	Store(id string, data []byte) error
	Load(id string) ([]byte, error)
	Delete(id string) error
}

// Example of a simple in-memory storage
type InMemoryStorage struct {
	data map[string][]byte
	mu   sync.Mutex
}

func NewInMemoryStorage() *InMemoryStorage {
	return &InMemoryStorage{data: make(map[string][]byte)}
}

func (s *InMemoryStorage) Store(id string, data []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data[id] = data
	return nil
}

func (s *InMemoryStorage) Load(id string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, exists := s.data[id]
	if !exists {
		return nil, errors.New("template not found")
	}
	return data, nil
}

func (s *InMemoryStorage) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.data, id)
	return nil
}

// IndustrySpecificTemplateManager manages industry-specific templates
type IndustrySpecificTemplateManager struct {
	Templates map[string]*IndustrySpecificTemplate
	mutex     sync.Mutex
}

// NewIndustrySpecificTemplateManager creates a new template manager
func NewIndustrySpecificTemplateManager() *IndustrySpecificTemplateManager {
	return &IndustrySpecificTemplateManager{
		Templates: make(map[string]*IndustrySpecificTemplate),
	}
}

// AddTemplate adds a new template to the manager
func (tm *IndustrySpecificTemplateManager) AddTemplate(template *IndustrySpecificTemplate) {
	tm.mutex.Lock()
	defer tm.mutex.Unlock()
	tm.Templates[template.ID] = template
}

// GetTemplate retrieves a template by its ID
func (tm *IndustrySpecificTemplateManager) GetTemplate(id string) (*IndustrySpecificTemplate, error) {
	tm.mutex.Lock()
	defer tm.mutex.Unlock()

	template, exists := tm.Templates[id]
	if !exists {
		return nil, errors.New("template not found")
	}
	return template, nil
}

// UpdateTemplate updates an existing template
func (tm *IndustrySpecificTemplateManager) UpdateTemplate(id string, parameters map[string]interface{}, aiModel []byte) error {
	tm.mutex.Lock()
	defer tm.mutex.Unlock()

	template, exists := tm.Templates[id]
	if !exists {
		return errors.New("template not found")
	}

	return template.UpdateTemplate(parameters, aiModel)
}

// DeleteTemplate deletes a template by its ID
func (tm *IndustrySpecificTemplateManager) DeleteTemplate(id string) error {
	tm.mutex.Lock()
	defer tm.mutex.Unlock()

	if _, exists := tm.Templates[id]; !exists {
		return errors.New("template not found")
	}

	delete(tm.Templates, id)
	return nil
}

// ListTemplates lists all templates managed by the manager
func (tm *IndustrySpecificTemplateManager) ListTemplates() []*IndustrySpecificTemplate {
	tm.mutex.Lock()
	defer tm.mutex.Unlock()

	templates := make([]*IndustrySpecificTemplate, 0, len(tm.Templates))
	for _, template := range tm.Templates {
		templates = append(templates, template)
	}
	return templates
}

// ApplyTemplate applies a template to a given set of parameters and returns the result
func (tm *IndustrySpecificTemplateManager) ApplyTemplate(id string, input map[string]interface{}) (map[string]interface{}, error) {
	template, err := tm.GetTemplate(id)
	if err != nil {
		return nil, err
	}

	valid, err := template.ValidateTemplate(input)
	if err != nil || !valid {
		return nil, errors.New("validation failed")
	}

	// Placeholder for applying the template logic
	// This could involve running the AI model with the input parameters
	result := make(map[string]interface{})
	for k, v := range input {
		result[k] = v
	}

	return result, nil
}


// NewParameterizedTemplate creates a new parameterized template
func NewParameterizedTemplate(name, description, version string, parameters map[string]interface{}) (*ParameterizedTemplate, error) {
	id, err := generateTemplateID(name, version)
	if err != nil {
		return nil, err
	}
	return &ParameterizedTemplate{
		ID:          id,
		Name:        name,
		Description: description,
		Version:     version,
		Parameters:  parameters,
		LastUpdated: time.Now(),
	}, nil
}

// generateTemplateID generates a unique ID for the parameterized template
func generateTemplateID(name, version string) (string, error) {
	data := fmt.Sprintf("%s:%s:%d", name, version, time.Now().UnixNano())
	hash := sha256.Sum256([]byte(data))
	return fmt.Sprintf("%x", hash[:]), nil
}

// UpdateTemplate updates the template's parameters
func (t *ParameterizedTemplate) UpdateTemplate(parameters map[string]interface{}) error {
	t.mutex.Lock()
	defer t.mutex.Unlock()

	t.Parameters = parameters
	t.LastUpdated = time.Now()
	return nil
}

// EncryptParameters encrypts the template's parameters using AES
func (t *ParameterizedTemplate) EncryptParameters(key []byte) error {
	if t.Encrypted {
		return errors.New("parameters are already encrypted")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return err
	}
	parametersJSON, err := json.Marshal(t.Parameters)
	if err != nil {
		return err
	}
	t.Parameters = map[string]interface{}{
		"data": gcm.Seal(nonce, nonce, parametersJSON, nil),
	}
	t.Encrypted = true
	return nil
}

// DecryptParameters decrypts the template's parameters using AES
func (t *ParameterizedTemplate) DecryptParameters(key []byte) error {
	if !t.Encrypted {
		return errors.New("parameters are not encrypted")
	}
	data, ok := t.Parameters["data"].([]byte)
	if !ok {
		return errors.New("invalid encrypted data")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return errors.New("ciphertext too short")
	}
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	parametersJSON, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return err
	}
	parameters := make(map[string]interface{})
	if err := json.Unmarshal(parametersJSON, &parameters); err != nil {
		return err
	}
	t.Parameters = parameters
	t.Encrypted = false
	return nil
}

// SerializeTemplate serializes the template to JSON
func (t *ParameterizedTemplate) SerializeTemplate() ([]byte, error) {
	t.mutex.Lock()
	defer t.mutex.Unlock()

	return json.Marshal(t)
}

// DeserializeTemplate deserializes the JSON data to a ParameterizedTemplate
func DeserializeTemplate(data []byte) (*ParameterizedTemplate, error) {
	var template ParameterizedTemplate
	if err := json.Unmarshal(data, &template); err != nil {
		return nil, err
	}
	return &template, nil
}

// StoreTemplate securely stores the template in a storage system
func (t *ParameterizedTemplate) StoreTemplate(storage Storage) error {
	t.mutex.Lock()
	defer t.mutex.Unlock()

	data, err := t.SerializeTemplate()
	if err != nil {
		return err
	}
	return storage.Store(t.ID, data)
}

// LoadTemplate loads the template from a storage system
func LoadTemplate(storage Storage, id string) (*ParameterizedTemplate, error) {
	data, err := storage.Load(id)
	if err != nil {
		return nil, err
	}
	return DeserializeTemplate(data)
}



func NewInMemoryStorage() *InMemoryStorage {
	return &InMemoryStorage{data: make(map[string][]byte)}
}

func (s *InMemoryStorage) Store(id string, data []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data[id] = data
	return nil
}

func (s *InMemoryStorage) Load(id string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, exists := s.data[id]
	if !exists {
		return nil, errors.New("template not found")
	}
	return data, nil
}

func (s *InMemoryStorage) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.data, id)
	return nil
}


// NewParameterizedTemplateManager creates a new template manager
func NewParameterizedTemplateManager() *ParameterizedTemplateManager {
	return &ParameterizedTemplateManager{
		Templates: make(map[string]*ParameterizedTemplate),
	}
}

// AddTemplate adds a new template to the manager
func (tm *ParameterizedTemplateManager) AddTemplate(template *ParameterizedTemplate) {
	tm.mutex.Lock()
	defer tm.mutex.Unlock()
	tm.Templates[template.ID] = template
}

// GetTemplate retrieves a template by its ID
func (tm *ParameterizedTemplateManager) GetTemplate(id string) (*ParameterizedTemplate, error) {
	tm.mutex.Lock()
	defer tm.mutex.Unlock()

	template, exists := tm.Templates[id]
	if !exists {
		return nil, errors.New("template not found")
	}
	return template, nil
}

// UpdateTemplate updates an existing template
func (tm *ParameterizedTemplateManager) UpdateTemplate(id string, parameters map[string]interface{}) error {
	tm.mutex.Lock()
	defer tm.mutex.Unlock()

	template, exists := tm.Templates[id]
	if !exists {
		return errors.New("template not found")
	}

	return template.UpdateTemplate(parameters)
}

// DeleteTemplate deletes a template by its ID
func (tm *ParameterizedTemplateManager) DeleteTemplate(id string) error {
	tm.mutex.Lock()
	defer tm.mutex.Unlock()

	if _, exists := tm.Templates[id]; !exists {
		return errors.New("template not found")
	}

	delete(tm.Templates, id)
	return nil
}

// ListTemplates lists all templates managed by the manager
func (tm *ParameterizedTemplateManager) ListTemplates() []*ParameterizedTemplate {
	tm.mutex.Lock()
	defer tm.mutex.Unlock()

	templates := make([]*ParameterizedTemplate, 0, len(tm.Templates))
	for _, template := range tm.Templates {
		templates = append(templates, template)
	}
	return templates
}

// NewRealTimeTemplate creates a new real-time updateable template
func NewRealTimeTemplate(name, description, version string, parameters map[string]interface{}) (*RealTimeTemplate, error) {
	id, err := generateTemplateID(name, version)
	if err != nil {
		return nil, err
	}
	return &RealTimeTemplate{
		ID:          id,
		Name:        name,
		Description: description,
		Version:     version,
		Parameters:  parameters,
		LastUpdated: time.Now(),
	}, nil
}

// generateTemplateID generates a unique ID for the real-time template
func generateTemplateID(name, version string) (string, error) {
	data := fmt.Sprintf("%s:%s:%d", name, version, time.Now().UnixNano())
	hash := sha256.Sum256([]byte(data))
	return fmt.Sprintf("%x", hash[:]), nil
}

// UpdateTemplate updates the template's parameters in real-time
func (t *RealTimeTemplate) UpdateTemplate(parameters map[string]interface{}) error {
	t.mutex.Lock()
	defer t.mutex.Unlock()

	t.Parameters = parameters
	t.LastUpdated = time.Now()
	return nil
}

// EncryptParameters encrypts the template's parameters using AES
func (t *RealTimeTemplate) EncryptParameters(key []byte) error {
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return err
	}
	parametersJSON, err := json.Marshal(t.Parameters)
	if err != nil {
		return err
	}
	t.Parameters = map[string]interface{}{
		"data": gcm.Seal(nonce, nonce, parametersJSON, nil),
	}
	return nil
}

// DecryptParameters decrypts the template's parameters using AES
func (t *RealTimeTemplate) DecryptParameters(key []byte) error {
	data, ok := t.Parameters["data"].([]byte)
	if !ok {
		return errors.New("invalid encrypted data")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return errors.New("ciphertext too short")
	}
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	parametersJSON, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return err
	}
	parameters := make(map[string]interface{})
	if err := json.Unmarshal(parametersJSON, &parameters); err != nil {
		return err
	}
	t.Parameters = parameters
	return nil
}

// SerializeTemplate serializes the template to JSON
func (t *RealTimeTemplate) SerializeTemplate() ([]byte, error) {
	t.mutex.Lock()
	defer t.mutex.Unlock()

	return json.Marshal(t)
}

// DeserializeTemplate deserializes the JSON data to a RealTimeTemplate
func DeserializeTemplate(data []byte) (*RealTimeTemplate, error) {
	var template RealTimeTemplate
	if err := json.Unmarshal(data, &template); err != nil {
		return nil, err
	}
	return &template, nil
}

// StoreTemplate securely stores the template in a storage system
func (t *RealTimeTemplate) StoreTemplate(storage Storage) error {
	t.mutex.Lock()
	defer t.mutex.Unlock()

	data, err := t.SerializeTemplate()
	if err != nil {
		return err
	}
	return storage.Store(t.ID, data)
}

// LoadTemplate loads the template from a storage system
func LoadTemplate(storage Storage, id string) (*RealTimeTemplate, error) {
	data, err := storage.Load(id)
	if err != nil {
		return nil, err
	}
	return DeserializeTemplate(data)
}

func NewInMemoryStorage() *InMemoryStorage {
	return &InMemoryStorage{data: make(map[string][]byte)}
}

func (s *InMemoryStorage) Store(id string, data []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data[id] = data
	return nil
}

func (s *InMemoryStorage) Load(id string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, exists := s.data[id]
	if !exists {
		return nil, errors.New("template not found")
	}
	return data, nil
}

func (s *InMemoryStorage) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.data, id)
	return nil
}

// NewRealTimeTemplateManager creates a new template manager
func NewRealTimeTemplateManager() *RealTimeTemplateManager {
	return &RealTimeTemplateManager{
		Templates: make(map[string]*RealTimeTemplate),
	}
}

// AddTemplate adds a new template to the manager
func (tm *RealTimeTemplateManager) AddTemplate(template *RealTimeTemplate) {
	tm.mutex.Lock()
	defer tm.mutex.Unlock()
	tm.Templates[template.ID] = template
}

// GetTemplate retrieves a template by its ID
func (tm *RealTimeTemplateManager) GetTemplate(id string) (*RealTimeTemplate, error) {
	tm.mutex.Lock()
	defer tm.mutex.Unlock()

	template, exists := tm.Templates[id]
	if !exists {
		return nil, errors.New("template not found")
	}
	return template, nil
}

// UpdateTemplate updates an existing template
func (tm *RealTimeTemplateManager) UpdateTemplate(id string, parameters map[string]interface{}) error {
	tm.mutex.Lock()
	defer tm.mutex.Unlock()

	template, exists := tm.Templates[id]
	if !exists {
		return errors.New("template not found")
	}

	return template.UpdateTemplate(parameters)
}

// DeleteTemplate deletes a template by its ID
func (tm *RealTimeTemplateManager) DeleteTemplate(id string) error {
	tm.mutex.Lock()
	defer tm.mutex.Unlock()

	if _, exists := tm.Templates[id]; !exists {
		return errors.New("template not found")
	}

	delete(tm.Templates, id)
	return nil
}

// ListTemplates lists all templates managed by the manager
func (tm *RealTimeTemplateManager) ListTemplates() []*RealTimeTemplate {
	tm.mutex.Lock()
	defer tm.mutex.Unlock()

	templates := make([]*RealTimeTemplate, 0, len(tm.Templates))
	for _, template := range tm.Templates {
		templates = append(templates, template)
	}
	return templates
}


// NewSmartTemplate creates a new smart template
func NewSmartTemplate(name, description, version, author string, parameters map[string]interface{}) (*SmartTemplate, error) {
	id, err := generateTemplateID(name, version)
	if err != nil {
		return nil, err
	}
	return &SmartTemplate{
		ID:          id,
		Name:        name,
		Description: description,
		Version:     version,
		Author:      author,
		Parameters:  parameters,
		LastUpdated: time.Now(),
	}, nil
}

// generateTemplateID generates a unique ID for the smart template
func generateTemplateID(name, version string) (string, error) {
	data := fmt.Sprintf("%s:%s:%d", name, version, time.Now().UnixNano())
	hash := sha256.Sum256([]byte(data))
	return fmt.Sprintf("%x", hash[:]), nil
}

// UpdateTemplate updates the template's parameters
func (t *SmartTemplate) UpdateTemplate(parameters map[string]interface{}) error {
	t.mutex.Lock()
	defer t.mutex.Unlock()

	t.Parameters = parameters
	t.LastUpdated = time.Now()
	return nil
}

// EncryptParameters encrypts the template's parameters using AES
func (t *SmartTemplate) EncryptParameters(key []byte) error {
	if t.Encrypted {
		return errors.New("parameters are already encrypted")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return err
	}
	parametersJSON, err := json.Marshal(t.Parameters)
	if err != nil {
		return err
	}
	t.Parameters = map[string]interface{}{
		"data": gcm.Seal(nonce, nonce, parametersJSON, nil),
	}
	t.Encrypted = true
	return nil
}

// DecryptParameters decrypts the template's parameters using AES
func (t *SmartTemplate) DecryptParameters(key []byte) error {
	if !t.Encrypted {
		return errors.New("parameters are not encrypted")
	}
	data, ok := t.Parameters["data"].([]byte)
	if !ok {
		return errors.New("invalid encrypted data")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return errors.New("ciphertext too short")
	}
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	parametersJSON, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return err
	}
	parameters := make(map[string]interface{})
	if err := json.Unmarshal(parametersJSON, &parameters); err != nil {
		return err
	}
	t.Parameters = parameters
	t.Encrypted = false
	return nil
}

// SerializeTemplate serializes the template to JSON
func (t *SmartTemplate) SerializeTemplate() ([]byte, error) {
	t.mutex.Lock()
	defer t.mutex.Unlock()

	return json.Marshal(t)
}

// DeserializeTemplate deserializes the JSON data to a SmartTemplate
func DeserializeTemplate(data []byte) (*SmartTemplate, error) {
	var template SmartTemplate
	if err := json.Unmarshal(data, &template); err != nil {
		return nil, err
	}
	return &template, nil
}

// StoreTemplate securely stores the template in a storage system
func (t *SmartTemplate) StoreTemplate(storage Storage) error {
	t.mutex.Lock()
	defer t.mutex.Unlock()

	data, err := t.SerializeTemplate()
	if err != nil {
		return err
	}
	return storage.Store(t.ID, data)
}

// LoadTemplate loads the template from a storage system
func LoadTemplate(storage Storage, id string) (*SmartTemplate, error) {
	data, err := storage.Load(id)
	if err != nil {
		return nil, err
	}
	return DeserializeTemplate(data)
}

// Storage interface defines methods for storing and loading templates
type Storage interface {
	Store(id string, data []byte) error
	Load(id string) ([]byte, error)
	Delete(id string) error
}

// Example of a simple in-memory storage
type InMemoryStorage struct {
	data map[string][]byte
	mu   sync.Mutex
}

func NewInMemoryStorage() *InMemoryStorage {
	return &InMemoryStorage{data: make(map[string][]byte)}
}

func (s *InMemoryStorage) Store(id string, data []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data[id] = data
	return nil
}

func (s *InMemoryStorage) Load(id string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, exists := s.data[id]
	if !exists {
		return nil, errors.New("template not found")
	}
	return data, nil
}

func (s *InMemoryStorage) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.data, id)
	return nil
}

// SmartTemplateMarketplace manages the marketplace for smart templates
type SmartTemplateMarketplace struct {
	Templates map[string]*SmartTemplate
	mutex     sync.Mutex
	storage   Storage
}

// NewSmartTemplateMarketplace creates a new template marketplace
func NewSmartTemplateMarketplace(storage Storage) *SmartTemplateMarketplace {
	return &SmartTemplateMarketplace{
		Templates: make(map[string]*SmartTemplate),
		storage:   storage,
	}
}

// AddTemplate adds a new template to the marketplace
func (m *SmartTemplateMarketplace) AddTemplate(template *SmartTemplate) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	if _, exists := m.Templates[template.ID]; exists {
		return errors.New("template already exists")
	}
	m.Templates[template.ID] = template
	return template.StoreTemplate(m.storage)
}

// GetTemplate retrieves a template by its ID
func (m *SmartTemplateMarketplace) GetTemplate(id string) (*SmartTemplate, error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	template, exists := m.Templates[id]
	if !exists {
		var err error
		template, err = LoadTemplate(m.storage, id)
		if err != nil {
			return nil, err
		}
		m.Templates[id] = template
	}
	return template, nil
}

// UpdateTemplate updates an existing template in the marketplace
func (m *SmartTemplateMarketplace) UpdateTemplate(id string, parameters map[string]interface{}) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	template, exists := m.Templates[id]
	if !exists {
		return errors.New("template not found")
	}
	err := template.UpdateTemplate(parameters)
	if err != nil {
		return err
	}
	return template.StoreTemplate(m.storage)
}

// DeleteTemplate deletes a template from the marketplace
func (m *SmartTemplateMarketplace) DeleteTemplate(id string) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if _, exists := m.Templates[id]; !exists {
		return errors.New("template not found")
	}
	delete(m.Templates, id)
	return m.storage.Delete(id)
}

// ListTemplates lists all templates in the marketplace
func (m *SmartTemplateMarketplace) ListTemplates() []*SmartTemplate {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	templates := make([]*SmartTemplate, 0, len(m.Templates))
	for _, template := range m.Templates {
		templates = append(templates, template)
	}
	return templates
}

// NewTemplateAnalytics creates a new TemplateAnalytics instance
func NewTemplateAnalytics(id, name, version string) *TemplateAnalytics {
	return &TemplateAnalytics{
		ID:                 id,
		Name:               name,
		Version:            version,
		PerformanceMetrics: make(map[string]float64),
	}
}

// UpdateDeployment updates the deployment count and last deployed time
func (ta *TemplateAnalytics) UpdateDeployment() {
	ta.mutex.Lock()
	defer ta.mutex.Unlock()

	ta.DeploymentCount++
	ta.LastDeployed = time.Now()
}

// UpdateExecution updates the execution count, last execution time, and average gas used
func (ta *TemplateAnalytics) UpdateExecution(gasUsed float64, success bool) {
	ta.mutex.Lock()
	defer ta.mutex.Unlock()

	ta.ExecutionCount++
	ta.LastExecution = time.Now()
	ta.AverageGasUsed = ((ta.AverageGasUsed * float64(ta.ExecutionCount-1)) + gasUsed) / float64(ta.ExecutionCount)
	if success {
		ta.SuccessRate = ((ta.SuccessRate * float64(ta.ExecutionCount-1)) + 1) / float64(ta.ExecutionCount)
	} else {
		ta.SuccessRate = ((ta.SuccessRate * float64(ta.ExecutionCount-1)) + 0) / float64(ta.ExecutionCount)
	}
}

// AddPerformanceMetric adds or updates a performance metric for the template
func (ta *TemplateAnalytics) AddPerformanceMetric(metricName string, value float64) {
	ta.mutex.Lock()
	defer ta.mutex.Unlock()

	ta.PerformanceMetrics[metricName] = value
}

// Serialize serializes the TemplateAnalytics to JSON
func (ta *TemplateAnalytics) Serialize() ([]byte, error) {
	ta.mutex.Lock()
	defer ta.mutex.Unlock()

	return json.Marshal(ta)
}

// DeserializeTemplateAnalytics deserializes JSON data to a TemplateAnalytics instance
func DeserializeTemplateAnalytics(data []byte) (*TemplateAnalytics, error) {
	var ta TemplateAnalytics
	if err := json.Unmarshal(data, &ta); err != nil {
		return nil, err
	}
	return &ta, nil
}

// AnalyticsStorage interface defines methods for storing and loading analytics data
type AnalyticsStorage interface {
	Store(id string, data []byte) error
	Load(id string) ([]byte, error)
	Delete(id string) error
}

// NewInMemoryAnalyticsStorage creates a new instance of InMemoryAnalyticsStorage
func NewInMemoryAnalyticsStorage() *InMemoryAnalyticsStorage {
	return &InMemoryAnalyticsStorage{data: make(map[string][]byte)}
}

func (s *InMemoryAnalyticsStorage) Store(id string, data []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data[id] = data
	return nil
}

func (s *InMemoryAnalyticsStorage) Load(id string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, exists := s.data[id]
	if !exists {
		return nil, errors.New("analytics data not found")
	}
	return data, nil
}

func (s *InMemoryAnalyticsStorage) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.data, id)
	return nil
}

// TemplateAnalyticsManager manages the analytics data for smart contract templates
type TemplateAnalyticsManager struct {
	analytics map[string]*TemplateAnalytics
	mutex     sync.Mutex
	storage   AnalyticsStorage
}

// NewTemplateAnalyticsManager creates a new instance of TemplateAnalyticsManager
func NewTemplateAnalyticsManager(storage AnalyticsStorage) *TemplateAnalyticsManager {
	return &TemplateAnalyticsManager{
		analytics: make(map[string]*TemplateAnalytics),
		storage:   storage,
	}
}

// AddAnalytics adds a new analytics instance to the manager
func (m *TemplateAnalyticsManager) AddAnalytics(analytics *TemplateAnalytics) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	if _, exists := m.analytics[analytics.ID]; exists {
		return errors.New("analytics already exists")
	}
	m.analytics[analytics.ID] = analytics
	return m.storeAnalytics(analytics)
}

// GetAnalytics retrieves an analytics instance by ID
func (m *TemplateAnalyticsManager) GetAnalytics(id string) (*TemplateAnalytics, error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	analytics, exists := m.analytics[id]
	if !exists {
		var err error
		analytics, err = m.loadAnalytics(id)
		if err != nil {
			return nil, err
		}
		m.analytics[id] = analytics
	}
	return analytics, nil
}

// UpdateAnalytics updates an existing analytics instance
func (m *TemplateAnalyticsManager) UpdateAnalytics(id string, updateFunc func(*TemplateAnalytics)) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	analytics, exists := m.analytics[id]
	if !exists {
		var err error
		analytics, err = m.loadAnalytics(id)
		if err != nil {
			return err
		}
		m.analytics[id] = analytics
	}
	updateFunc(analytics)
	return m.storeAnalytics(analytics)
}

// DeleteAnalytics deletes an analytics instance by ID
func (m *TemplateAnalyticsManager) DeleteAnalytics(id string) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if _, exists := m.analytics[id]; !exists {
		return errors.New("analytics not found")
	}
	delete(m.analytics, id)
	return m.storage.Delete(id)
}

// ListAnalytics lists all analytics instances
func (m *TemplateAnalyticsManager) ListAnalytics() []*TemplateAnalytics {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	analyticsList := make([]*TemplateAnalytics, 0, len(m.analytics))
	for _, analytics := range m.analytics {
		analyticsList = append(analyticsList, analytics)
	}
	return analyticsList
}

// storeAnalytics stores an analytics instance in the storage
func (m *TemplateAnalyticsManager) storeAnalytics(analytics *TemplateAnalytics) error {
	data, err := analytics.Serialize()
	if err != nil {
		return err
	}
	return m.storage.Store(analytics.ID, data)
}

// loadAnalytics loads an analytics instance from the storage
func (m *TemplateAnalyticsManager) loadAnalytics(id string) (*TemplateAnalytics, error) {
	data, err := m.storage.Load(id)
	if err != nil {
		return nil, err
	}
	return DeserializeTemplateAnalytics(data)
}

// NewTemplateCollaboration creates a new TemplateCollaboration instance
func NewTemplateCollaboration(id, name, version string) *TemplateCollaboration {
    return &TemplateCollaboration{
        ID:             id,
        Name:           name,
        Version:        version,
        Contributors:   []string{},
        Comments:       []Comment{},
    }
}

// AddContributor adds a new contributor to the collaboration
func (tc *TemplateCollaboration) AddContributor(contributor string) {
    tc.mutex.Lock()
    defer tc.mutex.Unlock()

    for _, existingContributor := range tc.Contributors {
        if existingContributor == contributor {
            return // Contributor already exists
        }
    }
    tc.Contributors = append(tc.Contributors, contributor)
}

// AddComment adds a new comment to the collaboration
func (tc *TemplateCollaboration) AddComment(author, message string) {
    tc.mutex.Lock()
    defer tc.mutex.Unlock()

    tc.Comments = append(tc.Comments, Comment{
        Author:    author,
        Timestamp: time.Now(),
        Message:   message,
    })
    tc.Collaborations++
    tc.LastCollab = time.Now()
}

// Serialize serializes the TemplateCollaboration to JSON
func (tc *TemplateCollaboration) Serialize() ([]byte, error) {
    tc.mutex.Lock()
    defer tc.mutex.Unlock()

    return json.Marshal(tc)
}

// DeserializeTemplateCollaboration deserializes JSON data to a TemplateCollaboration instance
func DeserializeTemplateCollaboration(data []byte) (*TemplateCollaboration, error) {
    var tc TemplateCollaboration
    if err := json.Unmarshal(data, &tc); err != nil {
        return nil, err
    }
    return &tc, nil
}

// CollaborationStorage interface defines methods for storing and loading collaboration data
type CollaborationStorage interface {
    Store(id string, data []byte) error
    Load(id string) ([]byte, error)
    Delete(id string) error
}

// InMemoryCollaborationStorage provides a simple in-memory storage for collaboration data
type InMemoryCollaborationStorage struct {
    data map[string][]byte
    mu   sync.Mutex
}

// NewInMemoryCollaborationStorage creates a new instance of InMemoryCollaborationStorage
func NewInMemoryCollaborationStorage() *InMemoryCollaborationStorage {
    return &InMemoryCollaborationStorage{data: make(map[string][]byte)}
}

func (s *InMemoryCollaborationStorage) Store(id string, data []byte) error {
    s.mu.Lock()
    defer s.mu.Unlock()
    s.data[id] = data
    return nil
}

func (s *InMemoryCollaborationStorage) Load(id string) ([]byte, error) {
    s.mu.Lock()
    defer s.mu.Unlock()
    data, exists := s.data[id]
    if !exists {
        return nil, errors.New("collaboration data not found")
    }
    return data, nil
}

func (s *InMemoryCollaborationStorage) Delete(id string) error {
    s.mu.Lock()
    defer s.mu.Unlock()
    delete(s.data, id)
    return nil
}

// TemplateCollaborationManager manages the collaboration data for smart contract templates
type TemplateCollaborationManager struct {
    collaborations map[string]*TemplateCollaboration
    mutex          sync.Mutex
    storage        CollaborationStorage
}

// NewTemplateCollaborationManager creates a new instance of TemplateCollaborationManager
func NewTemplateCollaborationManager(storage CollaborationStorage) *TemplateCollaborationManager {
    return &TemplateCollaborationManager{
        collaborations: make(map[string]*TemplateCollaboration),
        storage:        storage,
    }
}

// AddCollaboration adds a new collaboration instance to the manager
func (m *TemplateCollaborationManager) AddCollaboration(collaboration *TemplateCollaboration) error {
    m.mutex.Lock()
    defer m.mutex.Unlock()
    if _, exists := m.collaborations[collaboration.ID]; exists {
        return errors.New("collaboration already exists")
    }
    m.collaborations[collaboration.ID] = collaboration
    return m.storeCollaboration(collaboration)
}

// GetCollaboration retrieves a collaboration instance by ID
func (m *TemplateCollaborationManager) GetCollaboration(id string) (*TemplateCollaboration, error) {
    m.mutex.Lock()
    defer m.mutex.Unlock()

    collaboration, exists := m.collaborations[id]
    if !exists {
        var err error
        collaboration, err = m.loadCollaboration(id)
        if err != nil {
            return nil, err
        }
        m.collaborations[id] = collaboration
    }
    return collaboration, nil
}

// UpdateCollaboration updates an existing collaboration instance
func (m *TemplateCollaborationManager) UpdateCollaboration(id string, updateFunc func(*TemplateCollaboration)) error {
    m.mutex.Lock()
    defer m.mutex.Unlock()

    collaboration, exists := m.collaborations[id]
    if !exists {
        var err error
        collaboration, err = m.loadCollaboration(id)
        if err != nil {
            return err
        }
        m.collaborations[id] = collaboration
    }
    updateFunc(collaboration)
    return m.storeCollaboration(collaboration)
}

// DeleteCollaboration deletes a collaboration instance by ID
func (m *TemplateCollaborationManager) DeleteCollaboration(id string) error {
    m.mutex.Lock()
    defer m.mutex.Unlock()

    if _, exists := m.collaborations[id]; !exists {
        return errors.New("collaboration not found")
    }
    delete(m.collaborations, id)
    return m.storage.Delete(id)
}

// ListCollaborations lists all collaboration instances
func (m *TemplateCollaborationManager) ListCollaborations() []*TemplateCollaboration {
    m.mutex.Lock()
    defer m.mutex.Unlock()

    collaborationList := make([]*TemplateCollaboration, 0, len(m.collaborations))
    for _, collaboration := range m.collaborations {
        collaborationList = append(collaborationList, collaboration)
    }
    return collaborationList
}

// storeCollaboration stores a collaboration instance in the storage
func (m *TemplateCollaborationManager) storeCollaboration(collaboration *TemplateCollaboration) error {
    data, err := collaboration.Serialize()
    if err != nil {
        return err
    }
    return m.storage.Store(collaboration.ID, data)
}

// loadCollaboration loads a collaboration instance from the storage
func (m *TemplateCollaborationManager) loadCollaboration(id string) (*TemplateCollaboration, error) {
    data, err := m.storage.Load(id)
    if err != nil {
        return nil, err
    }
    return DeserializeTemplateCollaboration(data)
}

// NewTemplateCustomization creates a new TemplateCustomization instance
func NewTemplateCustomization(id, name, version, author string, customFields map[string]interface{}, customLogic string) *TemplateCustomization {
    return &TemplateCustomization{
        ID:           id,
        Name:         name,
        Version:      version,
        Author:       author,
        Timestamp:    time.Now(),
        CustomFields: customFields,
        CustomLogic:  customLogic,
    }
}

// AddCustomField adds a custom field to the template customization
func (tc *TemplateCustomization) AddCustomField(fieldName string, value interface{}) {
    tc.mutex.Lock()
    defer tc.mutex.Unlock()
    tc.CustomFields[fieldName] = value
}

// UpdateCustomLogic updates the custom logic of the template customization
func (tc *TemplateCustomization) UpdateCustomLogic(logic string) {
    tc.mutex.Lock()
    defer tc.mutex.Unlock()
    tc.CustomLogic = logic
}

// Serialize serializes the TemplateCustomization to JSON
func (tc *TemplateCustomization) Serialize() ([]byte, error) {
    tc.mutex.Lock()
    defer tc.mutex.Unlock()

    return json.Marshal(tc)
}

// DeserializeTemplateCustomization deserializes JSON data to a TemplateCustomization instance
func DeserializeTemplateCustomization(data []byte) (*TemplateCustomization, error) {
    var tc TemplateCustomization
    if err := json.Unmarshal(data, &tc); err != nil {
        return nil, err
    }
    return &tc, nil
}

// EncryptData encrypts the template customization data using AES encryption
func (tc *TemplateCustomization) EncryptData(passphrase string) error {
    tc.mutex.Lock()
    defer tc.mutex.Unlock()

    data, err := tc.Serialize()
    if err != nil {
        return err
    }

    block, err := aes.NewCipher([]byte(hash(passphrase)))
    if err != nil {
        return err
    }

    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return err
    }

    nonce := make([]byte, gcm.NonceSize())
    if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
        return err
    }

    tc.EncryptedData = gcm.Seal(nonce, nonce, data, nil)
    return nil
}

// DecryptData decrypts the template customization data using AES encryption
func (tc *TemplateCustomization) DecryptData(passphrase string) error {
    tc.mutex.Lock()
    defer tc.mutex.Unlock()

    block, err := aes.NewCipher([]byte(hash(passphrase)))
    if err != nil {
        return err
    }

    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return err
    }

    nonceSize := gcm.NonceSize()
    if len(tc.EncryptedData) < nonceSize {
        return errors.New("ciphertext too short")
    }

    nonce, ciphertext := tc.EncryptedData[:nonceSize], tc.EncryptedData[nonceSize:]
    data, err := gcm.Open(nil, nonce, ciphertext, nil)
    if err != nil {
        return err
    }

    return json.Unmarshal(data, tc)
}

func hash(passphrase string) string {
    h := sha256.New()
    h.Write([]byte(passphrase))
    return fmt.Sprintf("%x", h.Sum(nil))
}


// NewInMemoryTemplateCustomizationStorage creates a new instance of InMemoryTemplateCustomizationStorage
func NewInMemoryTemplateCustomizationStorage() *InMemoryTemplateCustomizationStorage {
    return &InMemoryTemplateCustomizationStorage{data: make(map[string][]byte)}
}

func (s *InMemoryTemplateCustomizationStorage) Store(id string, data []byte) error {
    s.mu.Lock()
    defer s.mu.Unlock()
    s.data[id] = data
    return nil
}

func (s *InMemoryTemplateCustomizationStorage) Load(id string) ([]byte, error) {
    s.mu.Lock()
    defer s.mu.Unlock()
    data, exists := s.data[id]
    if !exists {
        return nil, errors.New("customization data not found")
    }
    return data, nil
}

func (s *InMemoryTemplateCustomizationStorage) Delete(id string) error {
    s.mu.Lock()
    defer s.mu.Unlock()
    delete(s.data, id)
    return nil
}

// NewTemplateCustomizationManager creates a new instance of TemplateCustomizationManager
func NewTemplateCustomizationManager(storage TemplateCustomizationStorage) *TemplateCustomizationManager {
    return &TemplateCustomizationManager{
        customizations: make(map[string]*TemplateCustomization),
        storage:        storage,
    }
}

// AddCustomization adds a new customization instance to the manager
func (m *TemplateCustomizationManager) AddCustomization(customization *TemplateCustomization) error {
    m.mutex.Lock()
    defer m.mutex.Unlock()
    if _, exists := m.customizations[customization.ID]; exists {
        return errors.New("customization already exists")
    }
    m.customizations[customization.ID] = customization
    return m.storeCustomization(customization)
}

// GetCustomization retrieves a customization instance by ID
func (m *TemplateCustomizationManager) GetCustomization(id string) (*TemplateCustomization, error) {
    m.mutex.Lock()
    defer m.mutex.Unlock()

    customization, exists := m.customizations[id]
    if !exists {
        var err error
        customization, err = m.loadCustomization(id)
        if err != nil {
            return nil, err
        }
        m.customizations[id] = customization
    }
    return customization, nil
}

// UpdateCustomization updates an existing customization instance
func (m *TemplateCustomizationManager) UpdateCustomization(id string, updateFunc func(*TemplateCustomization)) error {
    m.mutex.Lock()
    defer m.mutex.Unlock()

    customization, exists := m.customizations[id]
    if !exists {
        var err error
        customization, err = m.loadCustomization(id)
        if err != nil {
            return err
        }
        m.customizations[id] = customization
    }
    updateFunc(customization)
    return m.storeCustomization(customization)
}

// DeleteCustomization deletes a customization instance by ID
func (m *TemplateCustomizationManager) DeleteCustomization(id string) error {
    m.mutex.Lock()
    defer m.mutex.Unlock()

    if _, exists := m.customizations[id]; !exists {
        return errors.New("customization not found")
    }
    delete(m.customizations, id)
    return m.storage.Delete(id)
}

// ListCustomizations lists all customization instances
func (m *TemplateCustomizationManager) ListCustomizations() []*TemplateCustomization {
    m.mutex.Lock()
    defer m.mutex.Unlock()

    customizationList := make([]*TemplateCustomization, 0, len(m.customizations))
    for _, customization := range m.customizations {
        customizationList = append(customizationList, customization)
    }
    return customizationList
}

// storeCustomization stores a customization instance in the storage
func (m *TemplateCustomizationManager) storeCustomization(customization *TemplateCustomization) error {
    data, err := customization.Serialize()
    if err != nil {
        return err
    }
    return m.storage.Store(customization.ID, data)
}

// loadCustomization loads a customization instance from the storage
func (m *TemplateCustomizationManager) loadCustomization(id string) (*TemplateCustomization, error) {
    data, err := m.storage.Load(id)
    if err != nil {
        return nil, err
    }
    return DeserializeTemplateCustomization(data)
}


// NewDeploymentManager creates a new instance of DeploymentManager.
func NewDeploymentManager(client blockchain.Client, storage storage.Service, key string) *DeploymentManager {
    return &DeploymentManager{
        blockchainClient: client,
        storageService:   storage,
        encryptionKey:    key,
    }
}

// DeployTemplate deploys a smart contract template to the blockchain.
func (dm *DeploymentManager) DeployTemplate(template *ContractTemplate) error {
    if template.Deployed {
        return errors.New("template is already deployed")
    }

    // Encrypt the template code if needed
    if template.Encrypted {
        encryptedCode, err := dm.encryptCode(template.Code)
        if err != nil {
            return fmt.Errorf("failed to encrypt template code: %v", err)
        }
        template.Code = encryptedCode
    }

    // Deploy the contract to the blockchain
    contractAddress, err := dm.blockchainClient.DeployContract(template.Code)
    if err != nil {
        return fmt.Errorf("failed to deploy contract: %v", err)
    }

    // Update the template status
    template.Deployed = true

    // Store the template metadata in the storage service
    err = dm.storageService.Save(template.ID, template)
    if err != nil {
        return fmt.Errorf("failed to save template metadata: %v", err)
    }

    log.Printf("Template deployed successfully. Contract address: %s", contractAddress)
    return nil
}

// UpdateTemplate updates an existing deployed smart contract template.
func (dm *DeploymentManager) UpdateTemplate(template *ContractTemplate) error {
    if !template.Deployed {
        return errors.New("template is not deployed")
    }

    // Encrypt the template code if needed
    if template.Encrypted {
        encryptedCode, err := dm.encryptCode(template.Code)
        if err != nil {
            return fmt.Errorf("failed to encrypt template code: %v", err)
        }
        template.Code = encryptedCode
    }

    // Update the contract on the blockchain
    err := dm.blockchainClient.UpdateContract(template.Code)
    if err != nil {
        return fmt.Errorf("failed to update contract: %v", err)
    }

    // Store the updated template metadata in the storage service
    err = dm.storageService.Save(template.ID, template)
    if err != nil {
        return fmt.Errorf("failed to save updated template metadata: %v", err)
    }

    log.Printf("Template updated successfully.")
    return nil
}

// encryptCode encrypts the contract code using AES encryption.
func (dm *DeploymentManager) encryptCode(code string) (string, error) {
    block, err := aes.NewCipher([]byte(dm.encryptionKey))
    if err != nil {
        return "", fmt.Errorf("failed to create cipher block: %v", err)
    }

    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return "", fmt.Errorf("failed to create GCM: %v", err)
    }

    nonce := make([]byte, gcm.NonceSize())
    if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
        return "", fmt.Errorf("failed to generate nonce: %v", err)
    }

    ciphertext := gcm.Seal(nonce, nonce, []byte(code), nil)
    return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// decryptCode decrypts the contract code using AES decryption.
func (dm *DeploymentManager) decryptCode(encryptedCode string) (string, error) {
    block, err := aes.NewCipher([]byte(dm.encryptionKey))
    if err != nil {
        return "", fmt.Errorf("failed to create cipher block: %v", err)
    }

    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return "", fmt.Errorf("failed to create GCM: %v", err)
    }

    decodedCiphertext, err := base64.StdEncoding.DecodeString(encryptedCode)
    if err != nil {
        return "", fmt.Errorf("failed to decode ciphertext: %v", err)
    }

    nonceSize := gcm.NonceSize()
    if len(decodedCiphertext) < nonceSize {
        return "", errors.New("ciphertext too short")
    }

    nonce, ciphertext := decodedCiphertext[:nonceSize], decodedCiphertext[nonceSize:]
    plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
    if err != nil {
        return "", fmt.Errorf("failed to decrypt code: %v", err)
    }

    return string(plaintext), nil
}

// NewTemplateDeploymentService creates a new instance of TemplateDeploymentService.
func NewTemplateDeploymentService(ledger *ledger.Ledger, stateManager *state.StateManager, txPool *transaction.TransactionPool) *TemplateDeploymentService {
	return &TemplateDeploymentService{
		ledger:            ledger,
		stateManager:      stateManager,
		transactionPool:   txPool,
		deploymentHistory: make(map[string][]DeploymentRecord),
	}
}

// DeployTemplate handles the deployment of a smart contract template.
func (s *TemplateDeploymentService) DeployTemplate(templateID, version, deployedBy string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Validate input parameters
	if templateID == "" || version == "" || deployedBy == "" {
		return "", errors.New("templateID, version, and deployedBy are required")
	}

	// Create a new deployment transaction
	tx, err := s.createDeploymentTransaction(templateID, version, deployedBy)
	if err != nil {
		return "", fmt.Errorf("failed to create deployment transaction: %v", err)
	}

	// Add the transaction to the pool
	err = s.transactionPool.AddTransaction(tx)
	if err != nil {
		return "", fmt.Errorf("failed to add deployment transaction to the pool: %v", err)
	}

	// Record the deployment
	record := DeploymentRecord{
		TemplateID:      templateID,
		Version:         version,
		DeploymentTime:  time.Now(),
		DeployedBy:      deployedBy,
		TransactionHash: tx.Hash(),
		Status:          "Pending",
	}
	s.deploymentHistory[templateID] = append(s.deploymentHistory[templateID], record)

	// Broadcast the transaction
	err = s.broadcastDeploymentTransaction(tx)
	if err != nil {
		return "", fmt.Errorf("failed to broadcast deployment transaction: %v", err)
	}

	return tx.Hash(), nil
}

// createDeploymentTransaction creates a new transaction for deploying a template.
func (s *TemplateDeploymentService) createDeploymentTransaction(templateID, version, deployedBy string) (*transaction.Transaction, error) {
	// Generate transaction data
	data := fmt.Sprintf("Deploying template %s version %s by %s", templateID, version, deployedBy)

	// Create a new transaction
	tx := transaction.NewTransaction(templateID, data)

	// Sign the transaction
	err := tx.Sign(deployedBy)
	if err != nil {
		return nil, fmt.Errorf("failed to sign deployment transaction: %v", err)
	}

	return tx, nil
}

// broadcastDeploymentTransaction broadcasts a deployment transaction to the network.
func (s *TemplateDeploymentService) broadcastDeploymentTransaction(tx *transaction.Transaction) error {
	// Simulate broadcasting the transaction
	log.Printf("Broadcasting deployment transaction %s", tx.Hash())
	// In real implementation, this would involve network calls to broadcast the transaction
	return nil
}

// GetDeploymentHistory retrieves the deployment history for a specific template.
func (s *TemplateDeploymentService) GetDeploymentHistory(templateID string) ([]DeploymentRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	history, exists := s.deploymentHistory[templateID]
	if !exists {
		return nil, errors.New("no deployment history found for the specified template ID")
	}
	return history, nil
}

// ValidateTemplateDeployment ensures the template deployment adheres to the required standards.
func (s *TemplateDeploymentService) ValidateTemplateDeployment(templateID, version string) error {
	// Placeholder for actual validation logic
	log.Printf("Validating deployment for template %s version %s", templateID, version)
	// Implement comprehensive validation logic here
	return nil
}

// RollbackDeployment rolls back a deployment in case of failures or errors.
func (s *TemplateDeploymentService) RollbackDeployment(templateID, version string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Find the deployment record
	var record *DeploymentRecord
	for i, r := range s.deploymentHistory[templateID] {
		if r.Version == version && r.Status == "Pending" {
			record = &s.deploymentHistory[templateID][i]
			break
		}
	}
	if record == nil {
		return errors.New("no pending deployment found for the specified template ID and version")
	}

	// Perform rollback actions
	record.Status = "RolledBack"
	log.Printf("Rolled back deployment for template %s version %s", templateID, version)
	// Add rollback logic here

	return nil
}

// finalizeDeployment marks a deployment as complete.
func (s *TemplateDeploymentService) finalizeDeployment(templateID, version, txHash string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for i, record := range s.deploymentHistory[templateID] {
		if record.Version == version && record.TransactionHash == txHash {
			s.deploymentHistory[templateID][i].Status = "Completed"
			break
		}
	}
	log.Printf("Deployment for template %s version %s has been finalized", templateID, version)
}

// MonitorDeployments monitors the status of ongoing deployments and finalizes them upon completion.
func (s *TemplateDeploymentService) MonitorDeployments() {
	for {
		time.Sleep(30 * time.Second)
		s.mu.Lock()
		for templateID, records := range s.deploymentHistory {
			for _, record := range records {
				if record.Status == "Pending" {
					// Simulate checking the deployment status
					if s.checkDeploymentStatus(record.TransactionHash) {
						s.finalizeDeployment(templateID, record.Version, record.TransactionHash)
					}
				}
			}
		}
		s.mu.Unlock()
	}
}

// checkDeploymentStatus simulates checking the status of a deployment transaction.
func (s *TemplateDeploymentService) checkDeploymentStatus(txHash string) bool {
	// Simulate checking the transaction status
	// In a real implementation, this would involve checking the blockchain or transaction pool
	return true
}

// NewTemplateLibrary initializes a new TemplateLibrary.
func NewTemplateLibrary() *TemplateLibrary {
	return &TemplateLibrary{
		templates: make(map[string]ContractTemplate),
	}
}

// AddTemplate adds a new contract template to the library.
func (lib *TemplateLibrary) AddTemplate(template ContractTemplate) error {
	if _, exists := lib.templates[template.ID]; exists {
		return errors.New("template already exists")
	}
	template.CreatedAt = time.Now()
	template.UpdatedAt = time.Now()
	lib.templates[template.ID] = template
	return nil
}

// UpdateTemplate updates an existing contract template.
func (lib *TemplateLibrary) UpdateTemplate(template ContractTemplate) error {
	if _, exists := lib.templates[template.ID]; !exists {
		return errors.New("template not found")
	}
	template.UpdatedAt = time.Now()
	lib.templates[template.ID] = template
	return nil
}

// GetTemplate retrieves a contract template by its ID.
func (lib *TemplateLibrary) GetTemplate(id string) (ContractTemplate, error) {
	template, exists := lib.templates[id]
	if !exists {
		return ContractTemplate{}, errors.New("template not found")
	}
	return template, nil
}

// DeleteTemplate removes a contract template from the library.
func (lib *TemplateLibrary) DeleteTemplate(id string) error {
	if _, exists := lib.templates[id]; !exists {
		return errors.New("template not found")
	}
	delete(lib.templates, id)
	return nil
}

// ListTemplates returns all contract templates in the library.
func (lib *TemplateLibrary) ListTemplates() []ContractTemplate {
	templates := make([]ContractTemplate, 0, len(lib.templates))
	for _, template := range lib.templates {
		templates = append(templates, template)
	}
	return templates
}

// ExportTemplates exports all templates to a JSON file.
func (lib *TemplateLibrary) ExportTemplates(filename string) error {
	data, err := json.Marshal(lib.templates)
	if err != nil {
		return err
	}
	return utils.SaveToFile(filename, data)
}

// ImportTemplates imports templates from a JSON file.
func (lib *TemplateLibrary) ImportTemplates(filename string) error {
	data, err := utils.LoadFromFile(filename)
	if err != nil {
		return err
	}
	templates := make(map[string]ContractTemplate)
	if err := json.Unmarshal(data, &templates); err != nil {
		return err
	}
	for id, template := range templates {
		template.CreatedAt = time.Now()
		template.UpdatedAt = time.Now()
		lib.templates[id] = template
	}
	return nil
}

// ValidateTemplate ensures the template code is syntactically correct.
func (lib *TemplateLibrary) ValidateTemplate(code string) error {
	// TODO: Add code validation logic based on specific language (e.g., Solidity, Yul, Rust)
	return nil
}

// EncryptTemplate encrypts the contract template code for secure storage.
func (lib *TemplateLibrary) EncryptTemplate(templateID, passphrase string) error {
	template, err := lib.GetTemplate(templateID)
	if err != nil {
		return err
	}
	encryptedCode, err := utils.Encrypt(template.Code, passphrase)
	if err != nil {
		return err
	}
	template.Code = encryptedCode
	lib.templates[templateID] = template
	return nil
}

// DecryptTemplate decrypts the contract template code for viewing or editing.
func (lib *TemplateLibrary) DecryptTemplate(templateID, passphrase string) (string, error) {
	template, err := lib.GetTemplate(templateID)
	if err != nil {
		return "", err
	}
	decryptedCode, err := utils.Decrypt(template.Code, passphrase)
	if err != nil {
		return "", err
	}
	return decryptedCode, nil
}

// VersionControl manages multiple versions of a contract template.
func (lib *TemplateLibrary) VersionControl(templateID string, newVersion string) error {
	template, err := lib.GetTemplate(templateID)
	if err != nil {
		return err
	}
	template.Version = newVersion
	template.UpdatedAt = time.Now()
	lib.templates[templateID] = template
	return nil
}

// NewMarketplace creates a new template marketplace
func NewMarketplace(secretKey string) *Marketplace {
    return &Marketplace{
        templates: make(map[string]Template),
        secretKey: deriveKey(secretKey),
        balances:  make(map[string]float64),
    }
}

// AddTemplate adds a new template to the marketplace
func (m *Marketplace) AddTemplate(name, description, author, version, code string, price float64) (string, error) {
    id := generateID(name, author, version)
    encryptedCode, err := encrypt(code, m.secretKey)
    if err != nil {
        return "", err
    }

    template := Template{
        ID:            id,
        Name:          name,
        Description:   description,
        Author:        author,
        Version:       version,
        Code:          code,
        CreationDate:  time.Now(),
        UpdateDate:    time.Now(),
        EncryptedCode: encryptedCode,
        Price:         price,
    }

    m.mu.Lock()
    m.templates[id] = template
    m.mu.Unlock()

    return id, nil
}

// UpdateTemplate updates an existing template in the marketplace
func (m *Marketplace) UpdateTemplate(id, name, description, version, code string, price float64) error {
    m.mu.Lock()
    defer m.mu.Unlock()

    template, exists := m.templates[id]
    if !exists {
        return errors.New("template not found")
    }

    encryptedCode, err := encrypt(code, m.secretKey)
    if err != nil {
        return err
    }

    template.Name = name
    template.Description = description
    template.Version = version
    template.Code = code
    template.UpdateDate = time.Now()
    template.EncryptedCode = encryptedCode
    template.Price = price

    m.templates[id] = template
    return nil
}

// GetTemplate retrieves a template by ID from the marketplace
func (m *Marketplace) GetTemplate(id string) (Template, error) {
    m.mu.Lock()
    template, exists := m.templates[id]
    m.mu.Unlock()

    if !exists {
        return Template{}, errors.New("template not found")
    }

    decryptedCode, err := decrypt(template.EncryptedCode, m.secretKey)
    if err != nil {
        return Template{}, err
    }

    template.Code = decryptedCode
    return template, nil
}

// ListTemplates lists all templates in the marketplace
func (m *Marketplace) ListTemplates() []Template {
    m.mu.Lock()
    defer m.mu.Unlock()

    var templateList []Template
    for _, template := range m.templates {
        decryptedCode, err := decrypt(template.EncryptedCode, m.secretKey)
        if err == nil {
            template.Code = decryptedCode
        }
        templateList = append(templateList, template)
    }
    return templateList
}

// DeleteTemplate removes a template from the marketplace by ID
func (m *Marketplace) DeleteTemplate(id string) error {
    m.mu.Lock()
    defer m.mu.Unlock()

    _, exists := m.templates[id]
    if !exists {
        return errors.New("template not found")
    }
    delete(m.templates, id)
    return nil
}

// PurchaseTemplate allows a user to purchase a template
func (m *Marketplace) PurchaseTemplate(templateID, buyerID string) (string, error) {
    m.mu.Lock()
    defer m.mu.Unlock()

    template, exists := m.templates[templateID]
    if !exists {
        return "", errors.New("template not found")
    }

    buyerBalance, exists := m.balances[buyerID]
    if !exists || buyerBalance < template.Price {
        return "", errors.New("insufficient balance")
    }

    // Deduct the template price from the buyer's balance
    m.balances[buyerID] -= template.Price

    // Return the decrypted code to the buyer
    decryptedCode, err := decrypt(template.EncryptedCode, m.secretKey)
    if err != nil {
        return "", err
    }

    return decryptedCode, nil
}

// AddBalance adds balance to a user's account
func (m *Marketplace) AddBalance(userID string, amount float64) {
    m.mu.Lock()
    defer m.mu.Unlock()

    m.balances[userID] += amount
}

// deriveKey derives a key from the given passphrase using scrypt
func deriveKey(passphrase string) []byte {
    salt := make([]byte, 16)
    _, _ = io.ReadFull(rand.Reader, salt)

    key, _ := scrypt.Key([]byte(passphrase), salt, 32768, 8, 1, 32)
    return key
}

// encrypt encrypts plaintext using AES with the given key
func encrypt(plaintext string, key []byte) (string, error) {
    block, err := aes.NewCipher(key)
    if err != nil {
        return "", err
    }

    ciphertext := make([]byte, aes.BlockSize+len(plaintext))
    iv := ciphertext[:aes.BlockSize]
    if _, err := io.ReadFull(rand.Reader, iv); err != nil {
        return "", err
    }

    stream := cipher.NewCFBEncrypter(block, iv)
    stream.XORKeyStream(ciphertext[aes.BlockSize:], []byte(plaintext))

    return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// decrypt decrypts ciphertext using AES with the given key
func decrypt(ciphertext string, key []byte) (string, error) {
    decodedCiphertext, err := base64.StdEncoding.DecodeString(ciphertext)
    if err != nil {
        return "", err
    }

    block, err := aes.NewCipher(key)
    if err != nil {
        return "", err
    }

    if len(decodedCiphertext) < aes.BlockSize {
        return "", errors.New("ciphertext too short")
    }

    iv := decodedCiphertext[:aes.BlockSize]
    decodedCiphertext = decodedCiphertext[aes.BlockSize:]

    stream := cipher.NewCFBDecrypter(block, iv)
    stream.XORKeyStream(decodedCiphertext, decodedCiphertext)

    return string(decodedCiphertext), nil
}

// generateID generates a unique ID for a template
func generateID(name, author, version string) string {
    data := fmt.Sprintf("%s:%s:%s", name, author, version)
    hash := sha256.Sum256([]byte(data))
    return base64.URLEncoding.EncodeToString(hash[:])
}

// NewSecurityAudit creates a new security audit for a smart contract template.
func NewSecurityAudit(templateID, auditor string, findings []Finding) *SecurityAudit {
	audit := &SecurityAudit{
		ID:         generateAuditID(templateID, auditor),
		TemplateID: templateID,
		AuditTime:  time.Now(),
		Auditor:    auditor,
		Findings:   findings,
		Status:     "Pending",
	}
	audit.Sign()
	return audit
}

// Sign generates a digital signature for the audit.
func (audit *SecurityAudit) Sign() {
	auditData, _ := json.Marshal(audit)
	hash := sha256.Sum256(auditData)
	audit.Signature = fmt.Sprintf("%x", hash[:])
}

// ValidateSignature validates the digital signature of the audit.
func (audit *SecurityAudit) ValidateSignature() bool {
	auditData, _ := json.Marshal(audit)
	hash := sha256.Sum256(auditData)
	return audit.Signature == fmt.Sprintf("%x", hash[:])
}

// UpdateStatus updates the status of the security audit.
func (audit *SecurityAudit) UpdateStatus(status string) {
	audit.Status = status
	audit.Sign()
}

// GetFindings returns the findings of the security audit.
func (audit *SecurityAudit) GetFindings() []Finding {
	return audit.Findings
}

// AddFinding adds a new finding to the security audit.
func (audit *SecurityAudit) AddFinding(finding Finding) {
	audit.Findings = append(audit.Findings, finding)
	audit.Sign()
}

// GenerateAuditID generates a unique ID for the audit based on the template ID and auditor.
func generateAuditID(templateID, auditor string) string {
	data := fmt.Sprintf("%s:%s:%d", templateID, auditor, time.Now().UnixNano())
	hash := sha256.Sum256([]byte(data))
	return fmt.Sprintf("%x", hash[:])
}

// NewInMemorySecurityAuditRepository creates a new in-memory security audit repository.
func NewInMemorySecurityAuditRepository() *InMemorySecurityAuditRepository {
	return &InMemorySecurityAuditRepository{
		audits: make(map[string]*SecurityAudit),
	}
}

// Save saves a security audit to the repository.
func (repo *InMemorySecurityAuditRepository) Save(audit *SecurityAudit) error {
	if audit == nil {
		return errors.New("audit is nil")
	}
	repo.audits[audit.ID] = audit
	return nil
}

// FindByID finds a security audit by its ID.
func (repo *InMemorySecurityAuditRepository) FindByID(id string) (*SecurityAudit, error) {
	audit, exists := repo.audits[id]
	if !exists {
		return nil, fmt.Errorf("audit not found: %s", id)
	}
	return audit, nil
}

// FindByTemplateID finds security audits by the template ID.
func (repo *InMemorySecurityAuditRepository) FindByTemplateID(templateID string) ([]*SecurityAudit, error) {
	var audits []*SecurityAudit
	for _, audit := range repo.audits {
		if audit.TemplateID == templateID {
			audits = append(audits, audit)
		}
	}
	return audits, nil
}

// PerformAudit performs a security audit on a smart contract template.
func (auditor *SecurityAuditor) PerformAudit(templateID string, findings []Finding, repo SecurityAuditRepository) (*SecurityAudit, error) {
	audit := NewSecurityAudit(templateID, auditor.Name, findings)
	if err := repo.Save(audit); err != nil {
		return nil, err
	}
	return audit, nil
}

// GetAudits retrieves all audits performed by the auditor.
func (auditor *SecurityAuditor) GetAudits(repo SecurityAuditRepository) ([]*SecurityAudit, error) {
	var audits []*SecurityAudit
	for _, audit := range repo.audits {
		if audit.Auditor == auditor.Name {
			audits = append(audits, audit)
		}
	}
	return audits, nil
}

// NewRemediationAction creates a new remediation action for a security finding.
func NewRemediationAction(auditID, description, performedBy string) *RemediationAction {
	action := &RemediationAction{
		ID:          generateRemediationActionID(auditID, performedBy),
		AuditID:     auditID,
		Description: description,
		PerformedBy: performedBy,
		PerformedAt: time.Now(),
		Status:      "Pending",
	}
	action.Sign()
	return action
}

// Sign generates a digital signature for the remediation action.
func (action *RemediationAction) Sign() {
	actionData, _ := json.Marshal(action)
	hash := sha256.Sum256(actionData)
	action.Signature = fmt.Sprintf("%x", hash[:])
}

// ValidateSignature validates the digital signature of the remediation action.
func (action *RemediationAction) ValidateSignature() bool {
	actionData, _ := json.Marshal(action)
	hash := sha256.Sum256(actionData)
	return action.Signature == fmt.Sprintf("%x", hash[:])
}

// UpdateStatus updates the status of the remediation action.
func (action *RemediationAction) UpdateStatus(status string) {
	action.Status = status
	action.Sign()
}

// GenerateRemediationActionID generates a unique ID for the remediation action based on the audit ID and performer.
func generateRemediationActionID(auditID, performedBy string) string {
	data := fmt.Sprintf("%s:%s:%d", auditID, performedBy, time.Now().UnixNano())
	hash := sha256.Sum256([]byte(data))
	return fmt.Sprintf("%x", hash[:])
}


// NewInMemoryRemediationRepository creates a new in-memory remediation repository.
func NewInMemoryRemediationRepository() *InMemoryRemediationRepository {
	return &InMemoryRemediationRepository{
		actions: make(map[string]*RemediationAction),
	}
}

// Save saves a remediation action to the repository.
func (repo *InMemoryRemediationRepository) Save(action *RemediationAction) error {
	if action == nil {
		return errors.New("action is nil")
	}
	repo.actions[action.ID] = action
	return nil
}

// FindByID finds a remediation action by its ID.
func (repo *InMemoryRemediationRepository) FindByID(id string) (*RemediationAction, error) {
	action, exists := repo.actions[id]
	if !exists {
		return nil, fmt.Errorf("action not found: %s", id)
	}
	return action, nil
}

// FindByAuditID finds remediation actions by the audit ID.
func (repo *InMemoryRemediationRepository) FindByAuditID(auditID string) ([]*RemediationAction, error) {
	var actions []*RemediationAction
	for _, action := range repo.actions {
		if action.AuditID == auditID {
			actions = append(actions, action)
		}
	}
	return actions, nil
}

const (
	Unverified common.VerificationStatus = iota
	Verified
	Rejected
)



// NewVerification creates a new verification record for a smart contract template.
func NewVerification(templateID, verifier, comments string, status VerificationStatus) *Verification {
	verification := &Verification{
		ID:         generateVerificationID(templateID, verifier),
		TemplateID: templateID,
		VerifiedAt: time.Now(),
		Verifier:   verifier,
		Status:     status,
		Comments:   comments,
	}
	verification.Sign()
	return verification
}

// Sign generates a digital signature for the verification.
func (v *Verification) Sign() {
	verificationData, _ := json.Marshal(v)
	hash := sha256.Sum256(verificationData)
	v.Signature = fmt.Sprintf("%x", hash[:])
}

// ValidateSignature validates the digital signature of the verification.
func (v *Verification) ValidateSignature() bool {
	verificationData, _ := json.Marshal(v)
	hash := sha256.Sum256(verificationData)
	return v.Signature == fmt.Sprintf("%x", hash[:])
}

// UpdateStatus updates the status of the verification.
func (v *Verification) UpdateStatus(status VerificationStatus, comments string) {
	v.Status = status
	v.Comments = comments
	v.VerifiedAt = time.Now()
	v.Sign()
}

// GenerateVerificationID generates a unique ID for the verification based on the template ID and verifier.
func generateVerificationID(templateID, verifier string) string {
	data := fmt.Sprintf("%s:%s:%d", templateID, verifier, time.Now().UnixNano())
	hash := sha256.Sum256([]byte(data))
	return fmt.Sprintf("%x", hash[:])
}


// NewInMemoryVerificationRepository creates a new in-memory verification repository.
func NewInMemoryVerificationRepository() *InMemoryVerificationRepository {
	return &InMemoryVerificationRepository{
		verifications: make(map[string]*Verification),
	}
}

// Save saves a verification to the repository.
func (repo *InMemoryVerificationRepository) Save(verification *Verification) error {
	if verification == nil {
		return errors.New("verification is nil")
	}
	repo.verifications[verification.ID] = verification
	return nil
}

// FindByID finds a verification by its ID.
func (repo *InMemoryVerificationRepository) FindByID(id string) (*Verification, error) {
	verification, exists := repo.verifications[id]
	if !exists {
		return nil, fmt.Errorf("verification not found: %s", id)
	}
	return verification, nil
}

// FindByTemplateID finds verifications by the template ID.
func (repo *InMemoryVerificationRepository) FindByTemplateID(templateID string) ([]*Verification, error) {
	var verifications []*Verification
	for _, verification := range repo.verifications {
		if verification.TemplateID == templateID {
			verifications = append(verifications, verification)
		}
	}
	return verifications, nil
}

// PerformVerification performs a verification on a smart contract template.
func (verifier *Verifier) PerformVerification(templateID string, comments string, status VerificationStatus, repo VerificationRepository) (*Verification, error) {
	verification := NewVerification(templateID, verifier.Name, comments, status)
	if err := repo.Save(verification); err != nil {
		return nil, err
	}
	return verification, nil
}

// GetVerifications retrieves all verifications performed by the verifier.
func (verifier *Verifier) GetVerifications(repo VerificationRepository) ([]*Verification, error) {
	var verifications []*Verification
	for _, verification := range repo.verifications {
		if verification.Verifier == verifier.Name {
			verifications = append(verifications, verification)
		}
	}
	return verifications, nil
}

// NewVerificationManager creates a new VerificationManager.
func NewVerificationManager(repo VerificationRepository) *VerificationManager {
	return &VerificationManager{Repository: repo}
}

// VerifyTemplate verifies a template and saves the verification.
func (manager *VerificationManager) VerifyTemplate(templateID, verifierName, comments string, status VerificationStatus) (*Verification, error) {
	verification := NewVerification(templateID, verifierName, comments, status)
	if err := manager.Repository.Save(verification); err != nil {
		return nil, err
	}
	return verification, nil
}

// GetVerificationByID retrieves a verification by its ID.
func (manager *VerificationManager) GetVerificationByID(id string) (*Verification, error) {
	return manager.Repository.FindByID(id)
}

// GetVerificationsByTemplateID retrieves all verifications for a specific template ID.
func (manager *VerificationManager) GetVerificationsByTemplateID(templateID string) ([]*Verification, error) {
	return manager.Repository.FindByTemplateID(templateID)
}

// GetVerificationsByVerifier retrieves all verifications performed by a specific verifier.
func (manager *VerificationManager) GetVerificationsByVerifier(verifierName string) ([]*Verification, error) {
	var verifications []*Verification
	for _, verification := range manager.Repository.verifications {
		if verification.Verifier == verifierName {
			verifications = append(verifications, verification)
		}
	}
	return verifications, nil
}


const (
    LowSeverity    common.SeverityLevel = "Low"
    MediumSeverity SeverityLevel = "Medium"
    HighSeverity   SeverityLevel = "High"
    CriticalSeverity SeverityLevel = "Critical"

    LowRisk    common.RiskLevel = "Low"
    MediumRisk RiskLevel = "Medium"
    HighRisk   RiskLevel = "High"
    CriticalRisk RiskLevel = "Critical"
)


func (s *SecurityAuditService) PerformSecurityAudit(contractCode string) (SecurityAudit, error) {
    // Example audit logic (to be extended)
    findings := []Finding{
        {
            Description: "Example vulnerability found",
            Severity:    HighSeverity,
            Impact:      "Potential funds loss",
        },
    }
    audit := SecurityAudit{
        ContractID:       generateContractID(contractCode),
        AuditTimestamp:   time.Now(),
        Findings:         findings,
        RiskAssessment:   HighRisk,
        RecommendedFixes: []string{"Fix example vulnerability"},
    }
    s.auditTrail.Audits = append(s.auditTrail.Audits, audit)
    return audit, nil
}

func (s *SecurityAuditService) VerifyAuditTrail(contractID string) ([]SecurityAudit, error) {
    var audits []SecurityAudit
    for _, audit := range s.auditTrail.Audits {
        if audit.ContractID == contractID {
            audits = append(audits, audit)
        }
    }
    if len(audits) == 0 {
        return nil, errors.New("no audits found for the given contract ID")
    }
    return audits, nil
}

func (s *SecurityAuditService) EncryptAuditData(data string, passphrase string) (string, error) {
    key, salt, err := s.generateEncryptionKey(passphrase)
    if err != nil {
        return "", err
    }

    block, err := aes.NewCipher(key)
    if err != nil {
        return "", err
    }

    ciphertext := make([]byte, aes.BlockSize+len(data))
    iv := ciphertext[:aes.BlockSize]

    if _, err := io.ReadFull(rand.Reader, iv); err != nil {
        return "", err
    }

    stream := cipher.NewCFBEncrypter(block, iv)
    stream.XORKeyStream(ciphertext[aes.BlockSize:], []byte(data))

    return hex.EncodeToString(salt) + ":" + hex.EncodeToString(ciphertext), nil
}

func (s *SecurityAuditService) DecryptAuditData(data string, passphrase string) (string, error) {
    parts := strings.Split(data, ":")
    if len(parts) != 2 {
        return "", errors.New("invalid data format")
    }

    salt, err := hex.DecodeString(parts[0])
    if err != nil {
        return "", err
    }

    key, _, err := s.generateEncryptionKey(passphrase, salt)
    if err != nil {
        return "", err
    }

    ciphertext, err := hex.DecodeString(parts[1])
    if err != nil {
        return "", err
    }

    block, err := aes.NewCipher(key)
    if err != nil {
        return "", err
    }

    if len(ciphertext) < aes.BlockSize {
        return "", errors.New("ciphertext too short")
    }

    iv := ciphertext[:aes.BlockSize]
    ciphertext = ciphertext[aes.BlockSize:]

    stream := cipher.NewCFBDecrypter(block, iv)
    stream.XORKeyStream(ciphertext, ciphertext)

    return string(ciphertext), nil
}

func (s *SecurityAuditService) GenerateEncryptionKey(passphrase string, salt []byte) ([]byte, []byte, error) {
    if salt == nil {
        salt = make([]byte, 16)
        if _, err := io.ReadFull(rand.Reader, salt); err != nil {
            return nil, nil, err
        }
    }
    key, err := scrypt.Key([]byte(passphrase), salt, 16384, 8, 1, 32)
    if err != nil {
        return nil, nil, err
    }
    return key, salt, nil
}

func generateContractID(contractCode string) string {
    hash := sha256.Sum256([]byte(contractCode))
    return hex.EncodeToString(hash[:])
}


// NewVersionManager initializes a new VersionManager
func NewVersionManager() *VersionManager {
	return &VersionManager{
		versions: make(map[string]SmartContractVersion),
	}
}

// AddVersion adds a new version of the smart contract
func (vm *VersionManager) AddVersion(version, code, hash string) error {
	vm.mutex.Lock()
	defer vm.mutex.Unlock()

	if _, exists := vm.versions[version]; exists {
		return errors.New("version already exists")
	}

	newVersion := SmartContractVersion{
		Version:   version,
		Code:      code,
		Timestamp: time.Now(),
		Hash:      hash,
	}

	vm.versions[version] = newVersion
	return nil
}

// GetVersion retrieves a specific version of the smart contract
func (vm *VersionManager) GetVersion(version string) (SmartContractVersion, error) {
	vm.mutex.RLock()
	defer vm.mutex.RUnlock()

	if v, exists := vm.versions[version]; exists {
		return v, nil
	}
	return SmartContractVersion{}, errors.New("version not found")
}

// ListVersions lists all versions of the smart contract
func (vm *VersionManager) ListVersions() []SmartContractVersion {
	vm.mutex.RLock()
	defer vm.mutex.RUnlock()

	versions := make([]SmartContractVersion, 0, len(vm.versions))
	for _, version := range vm.versions {
		versions = append(versions, version)
	}

	return versions
}

// RollbackVersion rolls back to a specific version of the smart contract
func (vm *VersionManager) RollbackVersion(version string) (SmartContractVersion, error) {
	vm.mutex.Lock()
	defer vm.mutex.Unlock()

	if v, exists := vm.versions[version]; exists {
		// Implement rollback logic here
		// For now, we'll just return the version
		return v, nil
	}
	return SmartContractVersion{}, errors.New("version not found")
}

// IncrementalUpdate applies an incremental update to the current version
func (vm *VersionManager) IncrementalUpdate(baseVersion, newVersion, patch, hash string) error {
	vm.mutex.Lock()
	defer vm.mutex.Unlock()

	if _, exists := vm.versions[baseVersion]; !exists {
		return errors.New("base version not found")
	}

	if _, exists := vm.versions[newVersion]; exists {
		return errors.New("new version already exists")
	}

	// Apply the patch to the base version code
	// This is a simplified example, real implementation would be more complex
	baseCode := vm.versions[baseVersion].Code
	newCode := baseCode + patch

	newVersionStruct := SmartContractVersion{
		Version:   newVersion,
		Code:      newCode,
		Timestamp: time.Now(),
		Hash:      hash,
	}

	vm.versions[newVersion] = newVersionStruct
	return nil
}

// MigrateData migrates data from the old version to the new version
func (vm *VersionManager) MigrateData(oldVersion, newVersion string) error {
	vm.mutex.Lock()
	defer vm.mutex.Unlock()

	if _, exists := vm.versions[oldVersion]; !exists {
		return errors.New("old version not found")
	}

	if _, exists := vm.versions[newVersion]; !exists {
		return errors.New("new version not found")
	}

	// Implement data migration logic here
	// For now, we'll just print a message
	fmt.Printf("Migrating data from version %s to version %s\n", oldVersion, newVersion)
	return nil
}

// SemanticVersioning ensures semantic versioning compliance
func (vm *VersionManager) SemanticVersioning(version string) error {
	// Implement semantic versioning validation logic here
	// This is a simplified example
	if len(version) == 0 {
		return errors.New("invalid version")
	}

	return nil
}

// AutomatedComplianceChecks runs automated compliance checks on the smart contract version
func (vm *VersionManager) AutomatedComplianceChecks(version string) error {
	vm.mutex.RLock()
	defer vm.mutex.RUnlock()

	if v, exists := vm.versions[version]; exists {
		// Implement compliance check logic here
		// For now, we'll just print a message
		fmt.Printf("Running compliance checks on version %s\n", v.Version)
		return nil
	}

	return errors.New("version not found")
}

// CreateSnapshot creates a snapshot of the current state of the smart contract
func (vm *VersionManager) CreateSnapshot(version string) (string, error) {
	vm.mutex.RLock()
	defer vm.mutex.RUnlock()

	if v, exists := vm.versions[version]; exists {
		// Implement snapshot creation logic here
		// For now, we'll just return the version hash
		return v.Hash, nil
	}

	return "", errors.New("version not found")
}

// NewUserGeneratedTemplate creates a new user-generated template.
func NewUserGeneratedTemplate(name, creator, templateCode string) (*UserGeneratedTemplate, error) {
	id, err := generateID()
	if err != nil {
		return nil, err
	}

	creationTime := time.Now()
	version := "1.0.0"
	encryptedCode, decryptionKey, err := encryptCode(templateCode)
	if err != nil {
		return nil, err
	}

	return &UserGeneratedTemplate{
		ID:              id,
		Name:            name,
		Creator:         creator,
		Version:         version,
		CreationTime:    creationTime,
		TemplateCode:    templateCode,
		EncryptedCode:   encryptedCode,
		DecryptionKey:   decryptionKey,
		UsageStatistics: make(map[string]int),
	}, nil
}

// UpdateTemplateCode updates the template code with a new version.
func (t *UserGeneratedTemplate) UpdateTemplateCode(newCode string) error {
	encryptedCode, decryptionKey, err := encryptCode(newCode)
	if err != nil {
		return err
	}
	t.TemplateCode = newCode
	t.EncryptedCode = encryptedCode
	t.DecryptionKey = decryptionKey
	t.Version = incrementVersion(t.Version)
	return nil
}

// incrementVersion increments the version of the template.
func incrementVersion(version string) string {
	verParts := strings.Split(version, ".")
	if len(verParts) != 3 {
		return "1.0.0"
	}
	patch, err := strconv.Atoi(verParts[2])
	if err != nil {
		return "1.0.0"
	}
	patch++
	return fmt.Sprintf("%s.%s.%d", verParts[0], verParts[1], patch)
}

// encryptCode encrypts the template code using AES encryption.
func encryptCode(code string) (string, string, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return "", "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", "", err
	}
	ciphertext := gcm.Seal(nonce, nonce, []byte(code), nil)
	return hex.EncodeToString(ciphertext), hex.EncodeToString(key), nil
}

// decryptCode decrypts the encrypted template code using AES decryption.
func decryptCode(encryptedCode, decryptionKey string) (string, error) {
	key, err := hex.DecodeString(decryptionKey)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	data, err := hex.DecodeString(encryptedCode)
	if err != nil {
		return "", err
	}
	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return "", errors.New("ciphertext too short")
	}
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

// generateID generates a unique ID for the template.
func generateID() (string, error) {
	id, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", id), nil
}

// IncrementUsage increments the usage count for a specific user.
func (t *UserGeneratedTemplate) IncrementUsage(userID string) {
	if _, exists := t.UsageStatistics[userID]; !exists {
		t.UsageStatistics[userID] = 0
	}
	t.UsageStatistics[userID]++
}

// GetUsageStatistics returns the usage statistics of the template.
func (t *UserGeneratedTemplate) GetUsageStatistics() map[string]int {
	return t.UsageStatistics
}

// DecryptTemplateCode decrypts and returns the template code.
func (t *UserGeneratedTemplate) DecryptTemplateCode() (string, error) {
	return decryptCode(t.EncryptedCode, t.DecryptionKey)
}

