package identity_services

import (
	"errors"
	"fmt"
	"time"
)


// NewABACManager creates a new instance of ABACManager
func NewABACManager() *ABACManager {
	return &ABACManager{
		Policies:  []Policy{},
		Users:     []User{},
		Resources: []Resource{},
	}
}

// AddPolicy adds a new policy to the manager
func (m *ABACManager) AddPolicy(policy Policy) {
	m.Policies = append(m.Policies, policy)
}

// AddUser adds a new user to the manager
func (m *ABACManager) AddUser(user User) {
	m.Users = append(m.Users, user)
}

// AddResource adds a new resource to the manager
func (m *ABACManager) AddResource(resource Resource) {
	m.Resources = append(m.Resources, resource)
}

// GetUserAttributes returns the attributes of a user
func (m *ABACManager) GetUserAttributes(userID string) ([]Attribute, error) {
	for _, user := range m.Users {
		if user.ID == userID {
			return user.Attributes, nil
		}
	}
	return nil, errors.New("user not found")
}

// EvaluateCondition evaluates a condition for a given attribute
func EvaluateCondition(attribute Attribute, condition Condition) bool {
	switch condition.Operator {
	case "==":
		return attribute.Value == condition.Value
	case "!=":
		return attribute.Value != condition.Value
	case ">":
		switch attribute.Value.(type) {
		case int:
			return attribute.Value.(int) > condition.Value.(int)
		case float64:
			return attribute.Value.(float64) > condition.Value.(float64)
		case time.Time:
			return attribute.Value.(time.Time).After(condition.Value.(time.Time))
		default:
			return false
		}
	case "<":
		switch attribute.Value.(type) {
		case int:
			return attribute.Value.(int) < condition.Value.(int)
		case float64:
			return attribute.Value.(float64) < condition.Value.(float64)
		case time.Time:
			return attribute.Value.(time.Time).Before(condition.Value.(time.Time))
		default:
			return false
		}
	case "contains":
		switch attribute.Value.(type) {
		case []string:
			for _, v := range attribute.Value.([]string) {
				if v == condition.Value {
					return true
				}
			}
			return false
		default:
			return false
		}
	default:
		return false
	}
}

// CheckAccess checks if a user has access to a resource based on policies
func (m *ABACManager) CheckAccess(userID, resourceID string, permission string) (bool, error) {
	userAttributes, err := m.GetUserAttributes(userID)
	if err != nil {
		return false, err
	}

	for _, policy := range m.Policies {
		if Contains(permission, policy.Permissions) {
			conditionsMet := true
			for _, condition := range policy.Conditions {
				attrFound := false
				for _, attr := range userAttributes {
					if attr.Name == condition.Attribute {
						if !EvaluateCondition(attr, condition) {
							conditionsMet = false
							break
						}
						attrFound = true
					}
				}
				if !attrFound {
					conditionsMet = false
					break
				}
			}
			if conditionsMet {
				return true, nil
			}
		}
	}
	return false, nil
}

// Contains checks if a slice contains a specific element
func Contains(slice []string, element string) bool {
	for _, e := range slice {
		if e == element {
			return true
		}
	}
	return false
}

func main() {
	abacManager := NewABACManager()

	user := User{
		ID: "user1",
		Attributes: []Attribute{
			{Name: "role", Value: "admin"},
			{Name: "age", Value: 30},
			{Name: "department", Value: "engineering"},
		},
	}

	resource := Resource{
		ID:          "resource1",
		Permissions: []string{"read", "write", "delete"},
	}

	abacManager.AddUser(user)
	abacManager.AddResource(resource)

	policy := Policy{
		ID: "policy1",
		Attributes: []Attribute{
			{Name: "role", Value: "admin"},
		},
		Permissions: []string{"read", "write"},
		Conditions: []Condition{
			{Attribute: "department", Operator: "==", Value: "engineering"},
			{Attribute: "age", Operator: ">=", Value: 25},
		},
	}

	abacManager.AddPolicy(policy)

	hasAccess, err := abacManager.CheckAccess("user1", "resource1", "read")
	if err != nil {
		fmt.Println("Error checking access:", err)
	} else {
		fmt.Println("Access granted:", hasAccess)
	}
}

// NewABACManager creates a new instance of ABACManager
func NewABACManager() *ABACManager {
	return &ABACManager{
		Policies:  []Policy{},
		Users:     []User{},
		Resources: []Resource{},
	}
}

// AddPolicy adds a new policy to the manager
func (m *ABACManager) AddPolicy(policy Policy) {
	m.Policies = append(m.Policies, policy)
}

// AddUser adds a new user to the manager
func (m *ABACManager) AddUser(user User) {
	m.Users = append(m.Users, user)
}

// AddResource adds a new resource to the manager
func (m *ABACManager) AddResource(resource Resource) {
	m.Resources = append(m.Resources, resource)
}

// GetUserAttributes returns the attributes of a user
func (m *ABACManager) GetUserAttributes(userID string) ([]Attribute, error) {
	for _, user := range m.Users {
		if user.ID == userID {
			return user.Attributes, nil
		}
	}
	return nil, errors.New("user not found")
}

// EvaluateCondition evaluates a condition for a given attribute
func EvaluateCondition(attribute Attribute, condition Condition) bool {
	switch condition.Operator {
	case "==":
		return attribute.Value == condition.Value
	case "!=":
		return attribute.Value != condition.Value
	case ">":
		switch attribute.Value.(type) {
		case int:
			return attribute.Value.(int) > condition.Value.(int)
		case float64:
			return attribute.Value.(float64) > condition.Value.(float64)
		case time.Time:
			return attribute.Value.(time.Time).After(condition.Value.(time.Time))
		default:
			return false
		}
	case "<":
		switch attribute.Value.(type) {
		case int:
			return attribute.Value.(int) < condition.Value.(int)
		case float64:
			return attribute.Value.(float64) < condition.Value.(float64)
		case time.Time:
			return attribute.Value.(time.Time).Before(condition.Value.(time.Time))
		default:
			return false
		}
	case "contains":
		switch attribute.Value.(type) {
		case []string:
			for _, v := range attribute.Value.([]string) {
				if v == condition.Value {
					return true
				}
			}
			return false
		default:
			return false
		}
	default:
		return false
	}
}

// CheckAccess checks if a user has access to a resource based on policies
func (m *ABACManager) CheckAccess(userID, resourceID string, permission string) (bool, error) {
	userAttributes, err := m.GetUserAttributes(userID)
	if err != nil {
		return false, err
	}

	for _, policy := range m.Policies {
		if Contains(permission, policy.Permissions) {
			conditionsMet := true
			for _, condition := range policy.Conditions {
				attrFound := false
				for _, attr := range userAttributes {
					if attr.Name == condition.Attribute {
						if !EvaluateCondition(attr, condition) {
							conditionsMet = false
							break
						}
						attrFound = true
					}
				}
				if !attrFound {
					conditionsMet = false
					break
				}
			}
			if conditionsMet {
				return true, nil
			}
		}
	}
	return false, nil
}

// Contains checks if a slice contains a specific element
func Contains(slice []string, element string) bool {
	for _, e := range slice {
		if e == element {
			return true
		}
	}
	return false
}

// EncryptData encrypts the given data using AES
func EncryptData(data string, passphrase string) (string, error) {
	salt := []byte("somesalt") // You should use a randomly generated salt
	dk, err := scrypt.Key([]byte(passphrase), salt, 16384, 8, 1, 32)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(dk)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	ciphertext := gcm.Seal(nonce, nonce, []byte(data), nil)
	return hex.EncodeToString(ciphertext), nil
}

// DecryptData decrypts the given data using AES
func DecryptData(data string, passphrase string) (string, error) {
	salt := []byte("somesalt") // You should use the same salt that was used for encryption
	dk, err := scrypt.Key([]byte(passphrase), salt, 16384, 8, 1, 32)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(dk)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	ciphertext, err := hex.DecodeString(data)
	if err != nil {
		return "", err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return "", errors.New("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

func main() {
	abacManager := NewABACManager()

	user := User{
		ID: "user1",
		Attributes: []Attribute{
			{Name: "role", Value: "admin"},
			{Name: "age", Value: 30},
			{Name: "department", Value: "engineering"},
		},
	}

	resource := Resource{
		ID:          "resource1",
		Permissions: []string{"read", "write", "delete"},
	}

	abacManager.AddUser(user)
	abacManager.AddResource(resource)

	policy := Policy{
		ID: "policy1",
		Attributes: []Attribute{
			{Name: "role", Value: "admin"},
		},
		Permissions: []string{"read", "write"},
		Conditions: []Condition{
			{Attribute: "department", Operator: "==", Value: "engineering"},
			{Attribute: "age", Operator: ">=", Value: 25},
		},
	}

	abacManager.AddPolicy(policy)

	hasAccess, err := abacManager.CheckAccess("user1", "resource1", "read")
	if err != nil {
		fmt.Println("Error checking access:", err)
	} else {
		fmt.Println("Access granted:", hasAccess)
	}
}
package access_control

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"time"

	"golang.org/x/crypto/scrypt"
	"github.com/google/uuid"
)

const (
	Admin   Role = "Admin"
	Validator   Role = "Validator"
	User    Role = "User"
	Auditor Role = "Auditor"

	Read    Permission = "Read"
	Write   Permission = "Write"
	Update  Permission = "Update"
	Delete  Permission = "Delete"
	Validate Permission = "Validate"
	Audit   Permission = "Audit"
)

func NewAccessControl() *AccessControl {
	return &AccessControl{
		Users:   make(map[uuid.UUID]*User),
		Policies: make(map[Role]Policy),
	}
}

func (ac *AccessControl) AddUser(user *User) {
	ac.Users[user.ID] = user
}

func (ac *AccessControl) RemoveUser(userID uuid.UUID) {
	delete(ac.Users, userID)
}

func (ac *AccessControl) AssignRole(userID uuid.UUID, role Role) error {
	user, exists := ac.Users[userID]
	if !exists {
		return errors.New("user not found")
	}

	user.Roles = append(user.Roles, role)
	return nil
}

func (ac *AccessControl) RevokeRole(userID uuid.UUID, role Role) error {
	user, exists := ac.Users[userID]
	if !exists {
		return errors.New("user not found")
	}

	for i, r := range user.Roles {
		if r == role {
			user.Roles = append(user.Roles[:i], user.Roles[i+1:]...)
			break
		}
	}
	return nil
}

func (ac *AccessControl) SetPolicy(role Role, permissions []Permission) {
	ac.Policies[role] = Policy{
		Role:        role,
		Permissions: permissions,
	}
}

func (ac *AccessControl) CheckAccess(userID uuid.UUID, permission Permission) bool {
	user, exists := ac.Users[userID]
	if !exists {
		return false
	}

	for _, role := range user.Roles {
		policy, exists := ac.Policies[role]
		if !exists {
			continue
		}
		for _, perm := range policy.Permissions {
			if perm == permission {
				return true
			}
		}
	}
	return false
}

func generateEncryptionKey(password, salt []byte) ([]byte, error) {
	key, err := scrypt.Key(password, salt, 32768, 8, 1, 32)
	if err != nil {
		return nil, err
	}
	return key, nil
}

func encrypt(data, passphrase []byte) (string, error) {
	block, _ := aes.NewCipher(passphrase)
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return base64.URLEncoding.EncodeToString(ciphertext), nil
}

func decrypt(encrypted string, passphrase []byte) ([]byte, error) {
	data, _ := base64.URLEncoding.DecodeString(encrypted)
	block, err := aes.NewCipher(passphrase)
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
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

func (ac *AccessControl) EncryptUserAttributes(userID uuid.UUID, passphrase string) error {
	user, exists := ac.Users[userID]
	if !exists {
		return errors.New("user not found")
	}
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return err
	}
	key, err := generateEncryptionKey([]byte(passphrase), salt)
	if err != nil {
		return err
	}
	for k, v := range user.Attributes {
		encryptedValue, err := encrypt([]byte(v), key)
		if err != nil {
			return err
		}
		user.Attributes[k] = encryptedValue
	}
	user.EncryptionKey = key
	return nil
}

func (ac *AccessControl) DecryptUserAttributes(userID uuid.UUID, passphrase string) error {
	user, exists := ac.Users[userID]
	if !exists {
		return errors.New("user not found")
	}
	key, err := generateEncryptionKey([]byte(passphrase), user.EncryptionKey)
	if err != nil {
		return err
	}
	for k, v := range user.Attributes {
		decryptedValue, err := decrypt(v, key)
		if err != nil {
			return err
		}
		user.Attributes[k] = string(decryptedValue)
	}
	return nil
}

func generateHash(input string) string {
	hash := sha256.Sum256([]byte(input))
	return base64.URLEncoding.EncodeToString(hash[:])
}

func validateHash(input, hash string) bool {
	return generateHash(input) == hash
}

func main() {
	ac := NewAccessControl()

	// Example usage
	user := &User{
		ID:         uuid.New(),
		Roles:      []Role{User},
		Attributes: map[string]string{"email": "user@example.com"},
	}

	ac.AddUser(user)
	ac.SetPolicy(User, []Permission{Read, Write})

	passphrase := "securepassphrase"
	ac.EncryptUserAttributes(user.ID, passphrase)

	hashedPassword := generateHash("securepassword")
	if validateHash("securepassword", hashedPassword) {
		println("Password validated")
	}

	if ac.CheckAccess(user.ID, Read) {
		println("Access granted")
	}
}

const (
	Owner  Role = "Owner"
	Editor Role = "Editor"
	Viewer Role = "Viewer"
)

// NewDAC creates a new DAC instance
func NewDAC() *DAC {
	return &DAC{
		Resources: make(map[uuid.UUID]*Resource),
		Users:     make(map[uuid.UUID]*User),
	}
}

// CreateResource creates a new resource
func (dac *DAC) CreateResource(ownerID uuid.UUID) *Resource {
	resource := &Resource{
		ID:            uuid.New(),
		OwnerID:       ownerID,
		AccessPolicies: make(map[uuid.UUID]AccessPolicy),
	}
	dac.Resources[resource.ID] = resource
	dac.AddPolicy(resource.ID, ownerID, Owner, false)
	return resource
}

// AddPolicy adds an access policy to a resource
func (dac *DAC) AddPolicy(resourceID, userID uuid.UUID, role Role, encrypted bool) error {
	resource, exists := dac.Resources[resourceID]
	if !exists {
		return errors.New("resource not found")
	}
	resource.AccessPolicies[userID] = AccessPolicy{
		UserID:    userID,
		Role:      role,
		Encrypted: encrypted,
	}
	return nil
}

// RemovePolicy removes an access policy from a resource
func (dac *DAC) RemovePolicy(resourceID, userID uuid.UUID) error {
	resource, exists := dac.Resources[resourceID]
	if !exists {
		return errors.New("resource not found")
	}
	delete(resource.AccessPolicies, userID)
	return nil
}

// CheckAccess checks if a user has access to a resource with a specific role
func (dac *DAC) CheckAccess(resourceID, userID uuid.UUID, role Role) bool {
	resource, exists := dac.Resources[resourceID]
	if !exists {
		return false
	}
	policy, exists := resource.AccessPolicies[userID]
	if !exists {
		return false
	}
	return policy.Role == role
}

// Encrypt encrypts data with a passphrase using AES
func Encrypt(data, passphrase []byte) (string, error) {
	block, _ := aes.NewCipher(passphrase)
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return base64.URLEncoding.EncodeToString(ciphertext), nil
}

// Decrypt decrypts data with a passphrase using AES
func Decrypt(encrypted string, passphrase []byte) ([]byte, error) {
	data, _ := base64.URLEncoding.DecodeString(encrypted)
	block, err := aes.NewCipher(passphrase)
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
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

// generateEncryptionKey generates a key using argon2id
func generateEncryptionKey(password, salt []byte) []byte {
	return argon2.IDKey(password, salt, 1, 64*1024, 4, 32)
}

// EncryptResource encrypts the data of a resource
func (dac *DAC) EncryptResource(resourceID uuid.UUID, passphrase string) error {
	resource, exists := dac.Resources[resourceID]
	if !exists {
		return errors.New("resource not found")
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return err
	}
	key := generateEncryptionKey([]byte(passphrase), salt)
	for userID, policy := range resource.AccessPolicies {
		if policy.Encrypted {
			encryptedID, err := Encrypt([]byte(userID.String()), key)
			if err != nil {
				return err
			}
			resource.AccessPolicies[userID] = AccessPolicy{
				UserID:    userID,
				Role:      policy.Role,
				Encrypted: true,
			}
			resource.AccessPolicies[uuid.MustParse(encryptedID)] = policy
			delete(resource.AccessPolicies, userID)
		}
	}
	return nil
}

// DecryptResource decrypts the data of a resource
func (dac *DAC) DecryptResource(resourceID uuid.UUID, passphrase string) error {
	resource, exists := dac.Resources[resourceID]
	if !exists {
		return errors.New("resource not found")
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return err
	}
	key := generateEncryptionKey([]byte(passphrase), salt)
	for userID, policy := range resource.AccessPolicies {
		if policy.Encrypted {
			decryptedID, err := Decrypt(userID.String(), key)
			if err != nil {
				return err
			}
			originalID := uuid.MustParse(string(decryptedID))
			resource.AccessPolicies[originalID] = AccessPolicy{
				UserID:    originalID,
				Role:      policy.Role,
				Encrypted: false,
			}
			delete(resource.AccessPolicies, userID)
		}
	}
	return nil
}

const (
	Owner  Role = "Owner"
	Editor Role = "Editor"
	Viewer Role = "Viewer"
)


const (
	Read   Permission = "Read"
	Write  Permission = "Write"
	Update Permission = "Update"
	Delete Permission = "Delete"
)

func NewDAC() *DAC {
	return &DAC{
		Resources: make(map[uuid.UUID]*Resource),
		Users:     make(map[uuid.UUID]*User),
	}
}

func (dac *DAC) CreateUser(attributes map[string]string, passphrase string) *User {
	user := &User{
		ID:         uuid.New(),
		Attributes: attributes,
	}
	user.EncryptionKey = generateEncryptionKey([]byte(passphrase), user.ID[:])
	dac.Users[user.ID] = user
	return user
}

func (dac *DAC) CreateResource(ownerID uuid.UUID) *Resource {
	resource := &Resource{
		ID:             uuid.New(),
		OwnerID:        ownerID,
		AccessPolicies: make(map[uuid.UUID]AccessPolicy),
	}
	dac.Resources[resource.ID] = resource
	dac.AddPolicy(resource.ID, ownerID, Owner, []Permission{Read, Write, Update, Delete}, nil)
	return resource
}

func (dac *DAC) AddPolicy(resourceID, userID uuid.UUID, role Role, permissions []Permission, expiry *time.Time) error {
	resource, exists := dac.Resources[resourceID]
	if !exists {
		return errors.New("resource not found")
	}
	resource.AccessPolicies[userID] = AccessPolicy{
		UserID:      userID,
		Role:        role,
		Permissions: permissions,
		Expiry:      expiry,
	}
	return nil
}

func (dac *DAC) RemovePolicy(resourceID, userID uuid.UUID) error {
	resource, exists := dac.Resources[resourceID]
	if !exists {
		return errors.New("resource not found")
	}
	delete(resource.AccessPolicies, userID)
	return nil
}

func (dac *DAC) CheckAccess(resourceID, userID uuid.UUID, permission Permission) bool {
	resource, exists := dac.Resources[resourceID]
	if !exists {
		return false
	}
	policy, exists := resource.AccessPolicies[userID]
	if !exists || (policy.Expiry != nil && policy.Expiry.Before(time.Now())) {
		return false
	}
	for _, perm := range policy.Permissions {
		if perm == permission {
			return true
		}
	}
	return false
}

func (dac *DAC) EncryptResource(resourceID uuid.UUID, passphrase string) error {
	resource, exists := dac.Resources[resourceID]
	if !exists {
		return errors.New("resource not found")
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return err
	}
	key := generateEncryptionKey([]byte(passphrase), salt)
	for userID, policy := range resource.AccessPolicies {
		encryptedID, err := Encrypt([]byte(userID.String()), key)
		if err != nil {
			return err
		}
		delete(resource.AccessPolicies, userID)
		resource.AccessPolicies[uuid.MustParse(encryptedID)] = policy
	}
	return nil
}

func (dac *DAC) DecryptResource(resourceID uuid.UUID, passphrase string) error {
	resource, exists := dac.Resources[resourceID]
	if !exists {
		return errors.New("resource not found")
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return err
	}
	key := generateEncryptionKey([]byte(passphrase), salt)
	for encryptedID, policy := range resource.AccessPolicies {
		decryptedID, err := Decrypt(encryptedID.String(), key)
		if err != nil {
			return err
		}
		originalID := uuid.MustParse(string(decryptedID))
		delete(resource.AccessPolicies, encryptedID)
		resource.AccessPolicies[originalID] = policy
	}
	return nil
}

func generateEncryptionKey(password, salt []byte) []byte {
	return argon2.IDKey(password, salt, 1, 64*1024, 4, 32)
}

func Encrypt(data, passphrase []byte) (string, error) {
	block, _ := aes.NewCipher(passphrase)
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return base64.URLEncoding.EncodeToString(ciphertext), nil
}

func Decrypt(encrypted string, passphrase []byte) ([]byte, error) {
	data, _ := base64.URLEncoding.DecodeString(encrypted)
	block, err := aes.NewCipher(passphrase)
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
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

const (
	ECCKey   KeyType = "ECC"   // Elliptic Curve Cryptography
	RSAKey   KeyType = "RSA"   // RSA Cryptography
	AESKey   KeyType = "AES"   // Symmetric AES Key
	Ed25519Key KeyType = "Ed25519" // Ed25519 Signature Key
)


// NewKeyManagement creates a new KeyManagement instance
func NewKeyManagement() *KeyManagement {
	return &KeyManagement{
		Keys:  make(map[uuid.UUID]*KeyPolicy),
		Users: make(map[uuid.UUID]*User),
	}
}

// CreateKey generates a new cryptographic key and its policy
func (km *KeyManagement) CreateKey(ownerID uuid.UUID, keyType KeyType, validUntil *time.Time, permissions []Permission) (*KeyPolicy, error) {
	keyID := uuid.New()
	encryptionKey, err := generateEncryptionKey([]byte(keyID.String()), keyID[:])
	if err != nil {
		return nil, err
	}

	keyPolicy := &KeyPolicy{
		KeyID:         keyID,
		KeyType:       keyType,
		OwnerID:       ownerID,
		CreatedAt:     time.Now(),
		ValidUntil:    validUntil,
		Permissions:   permissions,
		EncryptionKey: encryptionKey,
	}

	km.Keys[keyID] = keyPolicy
	return keyPolicy, nil
}

// RevokeKey revokes a cryptographic key by removing it from the management
func (km *KeyManagement) RevokeKey(keyID uuid.UUID) error {
	_, exists := km.Keys[keyID]
	if !exists {
		return errors.New("key not found")
	}
	delete(km.Keys, keyID)
	return nil
}

// GetKey retrieves a key policy by its ID
func (km *KeyManagement) GetKey(keyID uuid.UUID) (*KeyPolicy, error) {
	key, exists := km.Keys[keyID]
	if !exists {
		return nil, errors.New("key not found")
	}
	return key, nil
}

// CheckKeyAccess verifies if a user has the required permission for a key
func (km *KeyManagement) CheckKeyAccess(keyID, userID uuid.UUID, permission Permission) bool {
	key, exists := km.Keys[keyID]
	if !exists {
		return false
	}

	if key.OwnerID == userID {
		return true
	}

	for _, perm := range key.Permissions {
		if perm == permission {
			return true
		}
	}
	return false
}

// EncryptData encrypts data using the specified key's encryption key
func (km *KeyManagement) EncryptData(keyID uuid.UUID, data []byte) (string, error) {
	key, err := km.GetKey(keyID)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key.EncryptionKey)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return base64.URLEncoding.EncodeToString(ciphertext), nil
}

// DecryptData decrypts data using the specified key's encryption key
func (km *KeyManagement) DecryptData(keyID uuid.UUID, encrypted string) ([]byte, error) {
	key, err := km.GetKey(keyID)
	if err != nil {
		return nil, err
	}

	data, err := base64.URLEncoding.DecodeString(encrypted)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key.EncryptionKey)
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
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

// RotateKey rotates a cryptographic key, updating its encryption key and valid until time
func (km *KeyManagement) RotateKey(keyID uuid.UUID, validUntil *time.Time) error {
	key, err := km.GetKey(keyID)
	if err != nil {
		return err
	}

	newEncryptionKey, err := generateEncryptionKey([]byte(keyID.String()), keyID[:])
	if err != nil {
		return err
	}

	key.EncryptionKey = newEncryptionKey
	key.ValidUntil = validUntil
	key.CreatedAt = time.Now()
	return nil
}

// generateEncryptionKey generates a key using argon2id
func generateEncryptionKey(password, salt []byte) ([]byte, error) {
	return argon2.IDKey(password, salt, 1, 64*1024, 4, 32), nil
}

// Helper functions for encryption/decryption
func Encrypt(data, passphrase []byte) (string, error) {
	block, _ := aes.NewCipher(passphrase)
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return base64.URLEncoding.EncodeToString(ciphertext), nil
}

func Decrypt(encrypted string, passphrase []byte) ([]byte, error) {
	data, _ := base64.URLEncoding.DecodeString(encrypted)
	block, err := aes.NewCipher(passphrase)
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
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

func main() {
	km := NewKeyManagement()

	// Example usage
	userID := uuid.New()
	keyPolicy, _ := km.CreateKey(userID, AESKey, nil, []Permission{Read, Write})

	data := []byte("Sensitive data")
	encryptedData, _ := km.EncryptData(keyPolicy.KeyID, data)
	decryptedData, _ := km.DecryptData(keyPolicy.KeyID, encryptedData)

	println("Original data:", string(data))
	println("Encrypted data:", encryptedData)
	println("Decrypted data:", string(decryptedData))
}

const (
	ECCKey     KeyType = "ECC"     // Elliptic Curve Cryptography
	RSAKey     KeyType = "RSA"     // RSA Cryptography
	AESKey     KeyType = "AES"     // Symmetric AES Key
	Ed25519Key KeyType = "Ed25519" // Ed25519 Signature Key
)

// NewKeyManagement creates a new KeyManagement instance
func NewKeyManagement() *KeyManagement {
	return &KeyManagement{
		Keys:  make(map[uuid.UUID]*KeyPolicy),
		Users: make(map[uuid.UUID]*User),
	}
}

// CreateKey generates a new cryptographic key and its policy
func (km *KeyManagement) CreateKey(ownerID uuid.UUID, keyType KeyType, validUntil *time.Time, permissions []Permission) (*KeyPolicy, error) {
	keyID := uuid.New()
	var encryptionKey []byte
	var err error

	switch keyType {
	case ECCKey, Ed25519Key:
		encryptionKey, err = generateECCKey()
	case RSAKey:
		encryptionKey, err = generateRSAKey()
	case AESKey:
		encryptionKey, err = generateAESKey()
	default:
		return nil, errors.New("unsupported key type")
	}

	if err != nil {
		return nil, err
	}

	keyPolicy := &KeyPolicy{
		KeyID:         keyID,
		KeyType:       keyType,
		OwnerID:       ownerID,
		CreatedAt:     time.Now(),
		ValidUntil:    validUntil,
		Permissions:   permissions,
		EncryptionKey: encryptionKey,
	}

	km.Keys[keyID] = keyPolicy
	return keyPolicy, nil
}

// RevokeKey revokes a cryptographic key by removing it from the management
func (km *KeyManagement) RevokeKey(keyID uuid.UUID) error {
	_, exists := km.Keys[keyID]
	if !exists {
		return errors.New("key not found")
	}
	delete(km.Keys, keyID)
	return nil
}

// GetKey retrieves a key policy by its ID
func (km *KeyManagement) GetKey(keyID uuid.UUID) (*KeyPolicy, error) {
	key, exists := km.Keys[keyID]
	if !exists {
		return nil, errors.New("key not found")
	}
	return key, nil
}

// CheckKeyAccess verifies if a user has the required permission for a key
func (km *KeyManagement) CheckKeyAccess(keyID, userID uuid.UUID, permission Permission) bool {
	key, exists := km.Keys[keyID]
	if !exists {
		return false
	}

	if key.OwnerID == userID {
		return true
	}

	for _, perm := range key.Permissions {
		if perm == permission {
			return true
		}
	}
	return false
}

// EncryptData encrypts data using the specified key's encryption key
func (km *KeyManagement) EncryptData(keyID uuid.UUID, data []byte) (string, error) {
	key, err := km.GetKey(keyID)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key.EncryptionKey)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return base64.URLEncoding.EncodeToString(ciphertext), nil
}

// DecryptData decrypts data using the specified key's encryption key
func (km *KeyManagement) DecryptData(keyID uuid.UUID, encrypted string) ([]byte, error) {
	key, err := km.GetKey(keyID)
	if err != nil {
		return nil, err
	}

	data, err := base64.URLEncoding.DecodeString(encrypted)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key.EncryptionKey)
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
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

// RotateKey rotates a cryptographic key, updating its encryption key and valid until time
func (km *KeyManagement) RotateKey(keyID uuid.UUID, validUntil *time.Time) error {
	key, err := km.GetKey(keyID)
	if err != nil {
		return err
	}

	newEncryptionKey, err := generateEncryptionKey([]byte(keyID.String()), keyID[:])
	if err != nil {
		return err
	}

	key.EncryptionKey = newEncryptionKey
	key.ValidUntil = validUntil
	key.CreatedAt = time.Now()
	return nil
}

// generateEncryptionKey generates a key using argon2id
func generateEncryptionKey(password, salt []byte) ([]byte, error) {
	return argon2.IDKey(password, salt, 1, 64*1024, 4, 32), nil
}

// Helper functions for encryption/decryption
func Encrypt(data, passphrase []byte) (string, error) {
	block, _ := aes.NewCipher(passphrase)
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return base64.URLEncoding.EncodeToString(ciphertext), nil
}

func Decrypt(encrypted string, passphrase []byte) ([]byte, error) {
	data, _ := base64.URLEncoding.DecodeString(encrypted)
	block, err := aes.NewCipher(passphrase)
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
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

func generateECCKey() ([]byte, error) {
	// Generate ECC key here
	// Placeholder implementation, replace with actual ECC key generation
	return []byte("ecc-key-placeholder"), nil
}

func generateRSAKey() ([]byte, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	privASN1 := x509.MarshalPKCS1PrivateKey(privateKey)
	privBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privASN1,
	})
	return privBytes, nil
}

func generateAESKey() ([]byte, error) {
	key := make([]byte, 32) // AES-256
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	return key, nil
}

// NewRBACPolicyManager creates a new RBACPolicyManager
func NewRBACPolicyManager() *RBACPolicyManager {
	return &RBACPolicyManager{
		Roles:           make(map[uuid.UUID]*Role),
		Permissions:     make(map[uuid.UUID]*Permission),
		UserAssignments: make(map[uuid.UUID][]UserRoleAssignment),
	}
}

// CreateRole creates a new role with the given name and parent role
func (m *RBACPolicyManager) CreateRole(name string, parentRoleID *uuid.UUID) (*Role, error) {
	roleID := uuid.New()
	role := &Role{
		ID:          roleID,
		Name:        name,
		Permissions: []Permission{},
	}

	if parentRoleID != nil {
		parentRole, exists := m.Roles[*parentRoleID]
		if !exists {
			return nil, errors.New("parent role not found")
		}
		role.ParentRole = parentRole
	}

	m.Roles[roleID] = role
	return role, nil
}

// CreatePermission creates a new permission with the given name
func (m *RBACPolicyManager) CreatePermission(name string) (*Permission, error) {
	permissionID := uuid.New()
	permission := &Permission{
		ID:   permissionID,
		Name: name,
	}
	m.Permissions[permissionID] = permission
	return permission, nil
}

// AssignRoleToUser assigns a role to a user with an optional expiration time
func (m *RBACPolicyManager) AssignRoleToUser(userID, roleID uuid.UUID, expiresAt *time.Time) error {
	role, exists := m.Roles[roleID]
	if !exists {
		return errors.New("role not found")
	}

	assignment := UserRoleAssignment{
		UserID:    userID,
		RoleID:    roleID,
		ExpiresAt: expiresAt,
	}
	m.UserAssignments[userID] = append(m.UserAssignments[userID], assignment)
	return nil
}

// UnassignRoleFromUser unassigns a role from a user
func (m *RBACPolicyManager) UnassignRoleFromUser(userID, roleID uuid.UUID) error {
	assignments, exists := m.UserAssignments[userID]
	if !exists {
		return errors.New("no roles assigned to the user")
	}

	for i, assignment := range assignments {
		if assignment.RoleID == roleID {
			m.UserAssignments[userID] = append(assignments[:i], assignments[i+1:]...)
			return nil
		}
	}
	return errors.New("role not found in user's assignments")
}

// AddPermissionToRole adds a permission to a role
func (m *RBACPolicyManager) AddPermissionToRole(roleID, permissionID uuid.UUID) error {
	role, exists := m.Roles[roleID]
	if !exists {
		return errors.New("role not found")
	}

	permission, exists := m.Permissions[permissionID]
	if !exists {
		return errors.New("permission not found")
	}

	for _, perm := range role.Permissions {
		if perm.ID == permissionID {
			return errors.New("permission already assigned to role")
		}
	}

	role.Permissions = append(role.Permissions, *permission)
	return nil
}

// RemovePermissionFromRole removes a permission from a role
func (m *RBACPolicyManager) RemovePermissionFromRole(roleID, permissionID uuid.UUID) error {
	role, exists := m.Roles[roleID]
	if !exists {
		return errors.New("role not found")
	}

	for i, perm := range role.Permissions {
		if perm.ID == permissionID {
			role.Permissions = append(role.Permissions[:i], role.Permissions[i+1:]...)
			return nil
		}
	}
	return errors.New("permission not found in role")
}

// CheckUserPermission checks if a user has a specific permission
func (m *RBACPolicyManager) CheckUserPermission(userID, permissionID uuid.UUID) (bool, error) {
	assignments, exists := m.UserAssignments[userID]
	if !exists {
		return false, errors.New("no roles assigned to the user")
	}

	for _, assignment := range assignments {
		if assignment.ExpiresAt != nil && time.Now().After(*assignment.ExpiresAt) {
			continue
		}
		role, exists := m.Roles[assignment.RoleID]
		if !exists {
			continue
		}
		if m.roleHasPermission(role, permissionID) {
			return true, nil
		}
	}

	return false, nil
}

// roleHasPermission checks if a role has a specific permission
func (m *RBACPolicyManager) roleHasPermission(role *Role, permissionID uuid.UUID) bool {
	for _, perm := range role.Permissions {
		if perm.ID == permissionID {
			return true
		}
	}
	if role.ParentRole != nil {
		return m.roleHasPermission(role.ParentRole, permissionID)
	}
	return false
}

// NewRBACPolicyManager creates a new RBACPolicyManager
func NewRBACPolicyManager() *RBACPolicyManager {
	return &RBACPolicyManager{
		Roles:           make(map[uuid.UUID]*Role),
		Permissions:     make(map[uuid.UUID]*Permission),
		UserAssignments: make(map[uuid.UUID][]UserRoleAssignment),
	}
}

// CreateRole creates a new role with the given name and parent role
func (m *RBACPolicyManager) CreateRole(name string, parentRoleID *uuid.UUID) (*Role, error) {
	roleID := uuid.New()
	role := &Role{
		ID:          roleID,
		Name:        name,
		Permissions: []Permission{},
	}

	if parentRoleID != nil {
		parentRole, exists := m.Roles[*parentRoleID]
		if !exists {
			return nil, errors.New("parent role not found")
		}
		role.ParentRole = parentRole
	}

	m.Roles[roleID] = role
	return role, nil
}

// CreatePermission creates a new permission with the given name
func (m *RBACPolicyManager) CreatePermission(name string) (*Permission, error) {
	permissionID := uuid.New()
	permission := &Permission{
		ID:   permissionID,
		Name: name,
	}
	m.Permissions[permissionID] = permission
	return permission, nil
}

// AssignRoleToUser assigns a role to a user with an optional expiration time
func (m *RBACPolicyManager) AssignRoleToUser(userID, roleID uuid.UUID, expiresAt *time.Time) error {
	role, exists := m.Roles[roleID]
	if !exists {
		return errors.New("role not found")
	}

	assignment := UserRoleAssignment{
		UserID:    userID,
		RoleID:    roleID,
		ExpiresAt: expiresAt,
	}
	m.UserAssignments[userID] = append(m.UserAssignments[userID], assignment)
	return nil
}

// UnassignRoleFromUser unassigns a role from a user
func (m *RBACPolicyManager) UnassignRoleFromUser(userID, roleID uuid.UUID) error {
	assignments, exists := m.UserAssignments[userID]
	if !exists {
		return errors.New("no roles assigned to the user")
	}

	for i, assignment := range assignments {
		if assignment.RoleID == roleID {
			m.UserAssignments[userID] = append(assignments[:i], assignments[i+1:]...)
			return nil
		}
	}
	return errors.New("role not found in user's assignments")
}

// AddPermissionToRole adds a permission to a role
func (m *RBACPolicyManager) AddPermissionToRole(roleID, permissionID uuid.UUID) error {
	role, exists := m.Roles[roleID]
	if !exists {
		return errors.New("role not found")
	}

	permission, exists := m.Permissions[permissionID]
	if !exists {
		return errors.New("permission not found")
	}

	for _, perm := range role.Permissions {
		if perm.ID == permissionID {
			return errors.New("permission already assigned to role")
		}
	}

	role.Permissions = append(role.Permissions, *permission)
	return nil
}

// RemovePermissionFromRole removes a permission from a role
func (m *RBACPolicyManager) RemovePermissionFromRole(roleID, permissionID uuid.UUID) error {
	role, exists := m.Roles[roleID]
	if !exists {
		return errors.New("role not found")
	}

	for i, perm := range role.Permissions {
		if perm.ID == permissionID {
			role.Permissions = append(role.Permissions[:i], role.Permissions[i+1:]...)
			return nil
		}
	}
	return errors.New("permission not found in role")
}

// CheckUserPermission checks if a user has a specific permission
func (m *RBACPolicyManager) CheckUserPermission(userID, permissionID uuid.UUID) (bool, error) {
	assignments, exists := m.UserAssignments[userID]
	if !exists {
		return false, errors.New("no roles assigned to the user")
	}

	for _, assignment := range assignments {
		if assignment.ExpiresAt != nil && time.Now().After(*assignment.ExpiresAt) {
			continue
		}
		role, exists := m.Roles[assignment.RoleID]
		if !exists {
			continue
		}
		if m.roleHasPermission(role, permissionID) {
			return true, nil
		}
	}

	return false, nil
}

// roleHasPermission checks if a role has a specific permission
func (m *RBACPolicyManager) roleHasPermission(role *Role, permissionID uuid.UUID) bool {
	for _, perm := range role.Permissions {
		if perm.ID == permissionID {
			return true
		}
	}
	if role.ParentRole != nil {
		return m.roleHasPermission(role.ParentRole, permissionID)
	}
	return false
}

// ListUserRoles lists all roles assigned to a user
func (m *RBACPolicyManager) ListUserRoles(userID uuid.UUID) ([]*Role, error) {
	assignments, exists := m.UserAssignments[userID]
	if !exists {
		return nil, errors.New("no roles assigned to the user")
	}

	var roles []*Role
	for _, assignment := range assignments {
		role, exists := m.Roles[assignment.RoleID]
		if exists {
			roles = append(roles, role)
		}
	}
	return roles, nil
}

// ListRolePermissions lists all permissions assigned to a role
func (m *RBACPolicyManager) ListRolePermissions(roleID uuid.UUID) ([]*Permission, error) {
	role, exists := m.Roles[roleID]
	if !exists {
		return nil, errors.New("role not found")
	}

	var permissions []*Permission
	for _, perm := range role.Permissions {
		permissions = append(permissions, &perm)
	}
	return permissions, nil
}

// RevokeExpiredRoles removes expired roles from a user
func (m *RBACPolicyManager) RevokeExpiredRoles() {
	for userID, assignments := range m.UserAssignments {
		for i, assignment := range assignments {
			if assignment.ExpiresAt != nil && time.Now().After(*assignment.ExpiresAt) {
				m.UserAssignments[userID] = append(assignments[:i], assignments[i+1:]...)
			}
		}
	}
}
