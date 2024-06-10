package webrtc_integration

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"

	"github.com/pions/webrtc/v3"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/scrypt"
)

// Node represents a network node with WebRTC capabilities
type Node struct {
	ID              string
	Address         string
	Connection      *webrtc.PeerConnection
	DataChannel     *webrtc.DataChannel
	PrivateKey      *rsa.PrivateKey
	PublicKey       *rsa.PublicKey
	RemotePublicKey *rsa.PublicKey
}

// WebRTCManager manages the WebRTC integration
type WebRTCManager struct {
	nodes         map[string]*Node
	mutex         sync.Mutex
	encryptKey    []byte
	signalingPort int
}

// NewWebRTCManager creates a new WebRTCManager
func NewWebRTCManager(encryptKey []byte, signalingPort int) *WebRTCManager {
	return &WebRTCManager{
		nodes:         make(map[string]*Node),
		encryptKey:    encryptKey,
		signalingPort: signalingPort,
	}
}

// AddNode adds a new node to the network
func (m *WebRTCManager) AddNode(address string) error {
	nodeID := generateNodeID(address)

	m.mutex.Lock()
	defer m.mutex.Unlock()

	if _, exists := m.nodes[nodeID]; exists {
		return errors.New("node already exists")
	}

	config := webrtc.Configuration{}
	peerConnection, err := webrtc.NewPeerConnection(config)
	if err != nil {
		return err
	}

	dataChannel, err := peerConnection.CreateDataChannel("data", nil)
	if err != nil {
		return err
	}

	privateKey, publicKey, err := generateRSAKeyPair()
	if err != nil {
		return err
	}

	node := &Node{
		ID:          nodeID,
		Address:     address,
		Connection:  peerConnection,
		DataChannel: dataChannel,
		PrivateKey:  privateKey,
		PublicKey:   publicKey,
	}

	m.nodes[nodeID] = node
	return nil
}

// RemoveNode removes a node from the network
func (m *WebRTCManager) RemoveNode(nodeID string) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if node, exists := m.nodes[nodeID]; exists {
		node.Connection.Close()
		delete(m.nodes, nodeID)
	}
}

// SendMessage sends an encrypted message to a node
func (m *WebRTCManager) SendMessage(nodeID string, message []byte) error {
	m.mutex.Lock()
	node, exists := m.nodes[nodeID]
	m.mutex.Unlock()

	if !exists {
		return errors.New("node not found")
	}

	encryptedMessage, err := encryptDataRSA(message, node.RemotePublicKey)
	if err != nil {
		return err
	}

	err = node.DataChannel.Send(encryptedMessage)
	if err != nil {
		return err
	}

	return nil
}

// ReceiveMessage receives and decrypts a message from a node
func (m *WebRTCManager) ReceiveMessage(nodeID string) ([]byte, error) {
	m.mutex.Lock()
	node, exists := m.nodes[nodeID]
	m.mutex.Unlock()

	if !exists {
		return nil, errors.New("node not found")
	}

	var message []byte
	node.DataChannel.OnMessage(func(msg webrtc.DataChannelMessage) {
		message, _ = decryptDataRSA(msg.Data, node.PrivateKey)
	})

	return message, nil
}

// StartSignalingServer starts the decentralized signaling server
func (m *WebRTCManager) StartSignalingServer() error {
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", m.signalingPort))
	if err != nil {
		return err
	}
	defer listener.Close()

	for {
		conn, err := listener.Accept()
		if err != nil {
			return err
		}

		go m.handleSignalingConnection(conn)
	}
}

// HandleSignalingConnection handles incoming signaling connections
func (m *WebRTCManager) handleSignalingConnection(conn net.Conn) {
	defer conn.Close()

	var signal map[string]interface{}
	decoder := json.NewDecoder(conn)
	if err := decoder.Decode(&signal); err != nil {
		return
	}

	nodeID := signal["nodeID"].(string)
	action := signal["action"].(string)

	switch action {
	case "offer":
		offer := signal["offer"].(string)
		publicKeyStr := signal["publicKey"].(string)
		m.handleOffer(nodeID, offer, publicKeyStr)
	case "answer":
		answer := signal["answer"].(string)
		m.handleAnswer(nodeID, answer)
	case "candidate":
		candidate := signal["candidate"].(string)
		m.handleCandidate(nodeID, candidate)
	}
}

// HandleOffer handles an offer signal
func (m *WebRTCManager) handleOffer(nodeID, offer, publicKeyStr string) {
	m.mutex.Lock()
	node, exists := m.nodes[nodeID]
	m.mutex.Unlock()

	if !exists {
		return
	}

	publicKey, err := decodeRSAPublicKey(publicKeyStr)
	if err != nil {
		return
	}
	node.RemotePublicKey = publicKey

	err = node.Connection.SetRemoteDescription(webrtc.SessionDescription{
		Type: webrtc.SDPTypeOffer,
		SDP:  offer,
	})
	if err != nil {
		return
	}

	answer, err := node.Connection.CreateAnswer(nil)
	if err != nil {
		return
	}

	err = node.Connection.SetLocalDescription(answer)
	if err != nil {
		return
	}

	signal := map[string]interface{}{
		"nodeID":   nodeID,
		"action":   "answer",
		"answer":   answer.SDP,
		"publicKey": encodeRSAPublicKey(node.PublicKey),
	}
	m.sendSignal(signal)
}

// HandleAnswer handles an answer signal
func (m *WebRTCManager) handleAnswer(nodeID, answer string) {
	m.mutex.Lock()
	node, exists := m.nodes[nodeID]
	m.mutex.Unlock()

	if !exists {
		return
	}

	err := node.Connection.SetRemoteDescription(webrtc.SessionDescription{
		Type: webrtc.SDPTypeAnswer,
		SDP:  answer,
	})
	if err != nil {
		return
	}
}

// HandleCandidate handles a candidate signal
func (m *WebRTCManager) handleCandidate(nodeID, candidate string) {
	m.mutex.Lock()
	node, exists := m.nodes[nodeID]
	m.mutex.Unlock()

	if !exists {
		return
	}

	err := node.Connection.AddICECandidate(webrtc.ICECandidateInit{
		Candidate: candidate,
	})
	if err != nil {
		return
	}
}

// SendSignal sends a signaling message to the appropriate node
func (m *WebRTCManager) sendSignal(signal map[string]interface{}) {
	data, err := json.Marshal(signal)
	if err != nil {
		return
	}

	// In a real implementation, this should be broadcast to the appropriate nodes
	for _, node := range m.nodes {
		if node.Address == signal["nodeID"] {
			node.DataChannel.Send(data)
		}
	}
}

// EncryptDataRSA encrypts data using RSA
func encryptDataRSA(data []byte, publicKey *rsa.PublicKey) ([]byte, error) {
	return rsa.EncryptOAEP(sha256.New(), rand.Reader, publicKey, data, nil)
}

// DecryptDataRSA decrypts data using RSA
func decryptDataRSA(data []byte, privateKey *rsa.PrivateKey) ([]byte, error) {
	return rsa.DecryptOAEP(sha256.New(), rand.Reader, privateKey, data, nil)
}

// GenerateRSAKeyPair generates a new RSA key pair
func generateRSAKeyPair() (*rsa.PrivateKey, *rsa.PublicKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	return privateKey, &privateKey.PublicKey, nil
}

// EncodeRSAPublicKey encodes an RSA public key to a string
func encodeRSAPublicKey(publicKey *rsa.PublicKey) string {
	pubASN1, _ := x509.MarshalPKIXPublicKey(publicKey)
	pubBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: pubASN1,
	})
	return base64.StdEncoding.EncodeToString(pubBytes)
}

// DecodeRSAPublicKey decodes a string to an RSA public key
func decodeRSAPublicKey(publicKeyStr string) (*rsa.PublicKey, error) {
	pubBytes, err := base64.StdEncoding.DecodeString(publicKeyStr)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(pubBytes)
	if block == nil {
		return nil, errors.New("failed to decode PEM block containing public key")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return pub.(*rsa.PublicKey), nil
}

// GenerateEncryptionKey generates an encryption key using scrypt or argon2
func GenerateEncryptionKey(password string, salt []byte, useArgon2 bool) ([]byte, error) {
	if useArgon2 {
		return argon2.Key([]byte(password), salt, 3, 32*1024, 4, 32), nil
	}
	return scrypt.Key([]byte(password), salt, 16384, 8, 1, 32)
}

// GenerateNodeID generates a unique node ID based on the address
func generateNodeID(address string) string {
	hash := sha256.Sum256([]byte(address))
	return fmt.Sprintf("%x", hash[:])
}
