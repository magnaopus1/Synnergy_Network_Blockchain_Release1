package cross_chain_communications

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/pkg/errors"
)

// CrossChainProtocol defines the structure for cross-chain communication protocols.
type CrossChainProtocol struct {
	ProtocolID   string
	SecurityType string
	Version      string
}

// Message represents a cross-chain communication message.
type Message struct {
	Source      string
	Destination string
	Timestamp   time.Time
	Payload     interface{}
	Signature   string
}

// NewCrossChainProtocol initializes a new protocol with security and version specifics.
func NewCrossChainProtocol(protocolID, securityType, version string) *CrossChainProtocol {
	return &CrossChainProtocol{
		ProtocolID:   protocolID,
		SecurityType: securityType,
		Version:      version,
	}
}

// SendMessage creates and sends a message using the specified protocol.
func (ccp *CrossChainProtocol) SendMessage(source, destination string, payload interface{}) (*Message, error) {
	msg := Message{
		Source:      source,
		Destination: destination,
		Timestamp:   time.Now(),
		Payload:     payload,
	}

	data, err := json.Marshal(msg)
	if err != nil {
		return nil, errors.Wrap(err, "failed to marshal message")
	}

	signature, err := ccp.signMessage(data)
	if err != nil {
		return nil, errors.Wrap(err, "failed to sign message")
	}

	msg.Signature = signature
	fmt.Printf("Message sent to %s: %v\n", destination, msg)
	return &msg, nil
}

// signMessage signs the message data using SHA-256 hashing (or any specified secure hash algorithm).
func (ccp *CrossChainProtocol) signMessage(data []byte) (string, error) {
	hash := sha256.New()
	if _, err := hash.Write(data); err != nil {
		return "", errors.Wrap(err, "failed to hash message data")
	}
	signature := hex.EncodeToString(hash.Sum(nil))
	return signature, nil
}

// VerifyMessage checks the integrity and authenticity of the message.
func (ccp *CrossChainProtocol) VerifyMessage(msg *Message) (bool, error) {
	data, err := json.Marshal(msg)
	if err != nil {
		return false, errors.Wrap(err, "failed to marshal message for verification")
	}

	expectedSignature, err := ccp.signMessage(data)
	if err != nil {
		return false, errors.Wrap(err, "failed to sign message for verification")
	}

	if msg.Signature != expectedSignature {
		return false, fmt.Errorf("signature verification failed for message from %s", msg.Source)
	}

	fmt.Println("Message verified successfully")
	return true, nil
}
