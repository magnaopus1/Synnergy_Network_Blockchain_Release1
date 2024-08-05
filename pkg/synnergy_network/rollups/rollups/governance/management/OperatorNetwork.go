package management

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"sync"
	"time"
)

// Operator represents a node operator in the network
type Operator struct {
	ID        string
	PublicKey *rsa.PublicKey
	Active    bool
}

// OperatorNetwork manages the network of node operators in the governance model
type OperatorNetwork struct {
	Operators map[string]*Operator
	mutex     sync.Mutex
}

// NewOperatorNetwork initializes a new OperatorNetwork
func NewOperatorNetwork() *OperatorNetwork {
	return &OperatorNetwork{
		Operators: make(map[string]*Operator),
	}
}

// AddOperator adds a new operator to the network
func (on *OperatorNetwork) AddOperator(operatorID string, publicKey *rsa.PublicKey) error {
	on.mutex.Lock()
	defer on.mutex.Unlock()

	if _, exists := on.Operators[operatorID]; exists {
		return errors.New("operator already exists")
	}
	on.Operators[operatorID] = &Operator{
		ID:        operatorID,
		PublicKey: publicKey,
		Active:    true,
	}
	return nil
}

// RemoveOperator removes an operator from the network
func (on *OperatorNetwork) RemoveOperator(operatorID string) error {
	on.mutex.Lock()
	defer on.mutex.Unlock()

	if _, exists := on.Operators[operatorID]; !exists {
		return errors.New("operator does not exist")
	}
	delete(on.Operators, operatorID)
	return nil
}

// DeactivateOperator deactivates an operator in the network
func (on *OperatorNetwork) DeactivateOperator(operatorID string) error {
	on.mutex.Lock()
	defer on.mutex.Unlock()

	operator, exists := on.Operators[operatorID]
	if !exists {
		return errors.New("operator does not exist")
	}
	operator.Active = false
	return nil
}

// ActivateOperator reactivates an operator in the network
func (on *OperatorNetwork) ActivateOperator(operatorID string) error {
	on.mutex.Lock()
	defer on.mutex.Unlock()

	operator, exists := on.Operators[operatorID]
	if !exists {
		return errors.New("operator does not exist")
	}
	operator.Active = true
	return nil
}

// ListActiveOperators lists all active operators in the network
func (on *OperatorNetwork) ListActiveOperators() []*Operator {
	on.mutex.Lock()
	defer on.mutex.Unlock()

	activeOperators := []*Operator{}
	for _, operator := range on.Operators {
		if operator.Active {
			activeOperators = append(activeOperators, operator)
		}
	}
	return activeOperators
}

// ValidateOperatorSignature validates the signature of an operator
func (on *OperatorNetwork) ValidateOperatorSignature(operatorID, data string, signature []byte) error {
	on.mutex.Lock()
	defer on.mutex.Unlock()

	operator, exists := on.Operators[operatorID]
	if !exists {
		return errors.New("operator does not exist")
	}

	hashed := sha256.Sum256([]byte(data))
	err := rsa.VerifyPKCS1v15(operator.PublicKey, crypto.SHA256, hashed[:], signature)
	if err != nil {
		return errors.New("invalid signature")
	}
	return nil
}

// GenerateSignature generates a signature for the given data using the private key
func GenerateSignature(privateKey *rsa.PrivateKey, data string) ([]byte, error) {
	hashed := sha256.Sum256([]byte(data))
	return rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hashed[:])
}

// MarshalPublicKey converts a public key to a string
func MarshalPublicKey(publicKey *rsa.PublicKey) (string, error) {
	pubBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return "", err
	}
	pubBlock := pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubBytes,
	}
	return string(pem.EncodeToMemory(&pubBlock)), nil
}

// UnmarshalPublicKey converts a string to a public key
func UnmarshalPublicKey(pubKeyStr string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pubKeyStr))
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing the public key")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	publicKey, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("not an RSA public key")
	}
	return publicKey, nil
}

// GenerateOperatorID generates a unique ID for an operator
func GenerateOperatorID() string {
	id := make([]byte, 16)
	rand.Read(id)
	return hex.EncodeToString(id)
}
