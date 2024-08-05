package network

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"sync"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/scrypt"
	"github.com/gorilla/websocket"
	"github.com/pion/stun"
	"github.com/pion/turn"
	"github.com/pion/webrtc/v3"
)



// NewContractIntegration initializes a new ContractIntegration instance.
func NewContractIntegration(consensusEngine *common.ConsensusEngine) (ContractIntegration *common.ContractIntegration) {
	return &ContractIntegration{
		peers:           make(map[string]*Peer),
		contracts:       make(map[string]*Contract),
		consensusEngine: consensusEngine,
	}
}

// AddPeer adds a new peer to the network.
func (ci *common.ContractIntegration) AddPeer(id, address string, publicKey common.PublicKey) {
	ci.mux.Lock()
	defer ci.mux.Unlock()
	ci.peers[id] = &Peer{ID: id, Address: address, PublicKey: publicKey}
}

// RemovePeer removes a peer from the network.
func (ci *common.ContractIntegration) RemovePeer(id string) {
	ci.mux.Lock()
	defer ci.mux.Unlock()
	delete(ci.peers, id)
}

// DeployContract deploys a new smart contract to the network.
func (ci *common.ContractIntegration) DeployContract(contract *common.Contract) error {
	ci.mux.Lock()
	defer ci.mux.Unlock()
	contractID := contract.ID
	if _, exists := ci.contracts[contractID]; exists {
		return errors.New("contract already exists")
	}

	serializedContract, err := json.Marshal(contract)
	if err != nil {
		return err
	}

	encryptedContract, err := common.encryptData(serializedContract)
	if err != nil {
		return err
	}

	for _, peer := range ci.peers {
		err = ci.sendData(peer, encryptedContract)
		if err != nil {
			return err
		}
	}

	ci.contracts[contractID] = contract
	return nil
}

// ExecuteContract executes a smart contract function.
func (ci *common.ContractIntegration) ExecuteContract(contractID, function string, args []interface{}) (interface{}, error) {
	ci.mux.RLock()
	defer ci.mux.RUnlock()
	contract, exists := ci.contracts[contractID]
	if !exists {
		return nil, errors.New("contract not found")
	}

	result, err := contract.Execute(function, args)
	if err != nil {
		return nil, err
	}

	serializedResult, err := json.Marshal(result)
	if err != nil {
		return nil, err
	}

	encryptedResult, err := common.encryptData(serializedResult)
	if err != nil {
		return nil, err
	}

	for _, peer := range ci.peers {
		err = ci.sendData(peer, encryptedResult)
		if err != nil {
			return nil, err
		}
	}

	return result, nil
}

// sendData sends encrypted data to a peer.
func (ci *common.ContractIntegration) sendData(peer *common.Peer, data []byte) error {
	message := NewMessage(peer.ID, data)
	return Send(peer.Address, message)
}



// NewSignalingServer initializes a new SignalingServer.
func NewSignalingServer() (SignalingServer *common.SignalingServer) {
	return &SignalingServer{
		upgrader: websocket.Upgrader{
			ReadBufferSize:  1024,
			WriteBufferSize: 1024,
			CheckOrigin: func(r *http.Request) bool {
				return true
			},
		},
		connections: make(map[string]*websocket.Conn),
		peerConfigs: make(map[string]*webrtc.Configuration),
	}
}

// HandleWebSocket handles incoming WebSocket connections for signaling.
func (s *common.SignalingServer) HandleWebSocket(w common.http.ResponseWriter, r common.*http.Request) {
	conn, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("Failed to upgrade to WebSocket: %v", err)
		return
	}
	defer conn.Close()

	peerID := r.URL.Query().Get("peer_id")
	if peerID == "" {
		log.Println("Peer ID is missing in the query parameters")
		return
	}

	s.peersLock.Lock()
	s.connections[peerID] = conn
	s.peersLock.Unlock()

	for {
		_, message, err := conn.ReadMessage()
		if err != nil {
			log.Printf("Error reading message: %v", err)
			break
		}
		s.handleSignalMessage(peerID, message)
	}

	s.peersLock.Lock()
	delete(s.connections, peerID)
	s.peersLock.Unlock()
}

// handleSignalMessage processes incoming signaling messages.
func (s *common.SignalingServer) handleSignalMessage(peerID string, message []byte) {
	var msg common.SignalMessage
	err := json.Unmarshal(message, &msg)
	if err != nil {
		log.Printf("Failed to unmarshal message: %v", err)
		return
	}

	switch msg.Type {
	case "offer", "answer", "ice":
		s.forwardSignalMessage(peerID, msg.Data)
	default:
		log.Printf("Unknown signal message type: %s", msg.Type)
	}
}

// forwardSignalMessage forwards signaling messages to the intended peer.
func (s *common.SignalingServer) forwardSignalMessage(peerID, data string) {
	s.peersLock.RLock()
	conn, ok := s.connections[peerID]
	s.peersLock.RUnlock()

	if !ok {
		log.Printf("Peer connection not found for ID: %s", peerID)
		return
	}

	err := conn.WriteMessage(websocket.TextMessage, []byte(data))
	if err != nil {
		log.Printf("Failed to forward signal message: %v", err)
	}
}

// InitiateWebRTCConnection initiates a WebRTC connection between peers.
func (s *common.SignalingServer) InitiateWebRTCConnection(peerID string, config *common.webrtc.Configuration) (*common.webrtc.PeerConnection, error) {
	peerConnection, err := webrtc.NewPeerConnection(*config)
	if err != nil {
		return nil, err
	}

	s.peersLock.Lock()
	s.peerConfigs[peerID] = config
	s.peersLock.Unlock()

	_, err = peerConnection.CreateDataChannel("data", nil)
	if err != nil {
		return nil, err
	}

	return peerConnection, nil
}

// HandleICECandidate handles ICE candidate exchange.
func (s *SignalingServer) HandleICECandidate(peerConnection *webrtc.PeerConnection, candidate webrtc.ICECandidateInit) {
	err := peerConnection.AddICECandidate(candidate)
	if err != nil {
		log.Printf("Failed to add ICE candidate: %v", err)
	}
}


// RunServer starts the signaling server.
func (s *common.SignalingServer) RunServer(addr string) {
	http.HandleFunc("/ws", s.HandleWebSocket)
	log.Printf("Signaling server started at %s", addr)
	err := http.ListenAndServe(addr, nil)
	if err != nil {
		log.Fatalf("Failed to start signaling server: %v", err)
	}
}



// EncryptAndSendMessage encrypts a message and sends it to a peer.
func (e *common.EndToEndEncryption) EncryptAndSendMessage(peerID string, data []byte) error {
	encryptedData, err := e.EncryptData(peerID, data)
	if err != nil {
		return err
	}

	msg := NewMessage(peerID, encryptedData)
	return Send(peerID, msg)
}

// ReceiveAndDecryptMessage receives and decrypts a message from a peer.
func (e *common.EndToEndEncryption) ReceiveAndDecryptMessage(encryptedData []byte) ([]byte, error) {
	return e.DecryptData(encryptedData)
}

// KeyExchange handles secure key exchange between peers.
func (e *common.EndToEndEncryption) KeyExchange(peerID string, publicKey PublicKey, privateKey PrivateKey) error {
	sharedSecret := DeriveSharedSecret(privateKey, publicKey)
	salt := sha256.Sum256([]byte(peerID))

	key, err := e.GenerateKey(sharedSecret, salt[:], true)
	if err != nil {
		return err
	}

	e.StoreKey(peerID, key)
	return nil
}

// AddICEServer adds a new ICE server to the NATTraversal configuration.
func (nt *common.NATTraversal) AddICEServer(server common.webrtc.ICEServer) {
	nt.iceServers = append(nt.iceServers, server)
}

// SetupTURNServer sets up a TURN server for NAT traversal.
func (nt *common.NATTraversal) SetupTURNServer(username, password, realm, listeningPort string) error {
	nt.turnServerLock.Lock()
	defer nt.turnServerLock.Unlock()

	if nt.turnServer != nil {
		return errors.New("TURN server already set up")
	}

	udpListener, err := net.ListenPacket("udp4", ":"+listeningPort)
	if err != nil {
		return err
	}

	turnServer, err := turn.NewServer(turn.ServerConfig{
		Realm:         realm,
		AuthHandler:   func(username, realm string, srcAddr net.Addr) ([]byte, bool) { return turn.GenerateAuthKey(username, realm, password), true },
		PacketConnConfigs: []turn.PacketConnConfig{{PacketConn: udpListener, RelayAddressGenerator: &turn.RelayAddressGeneratorNone{}}},
	})
	if err != nil {
		return err
	}

	nt.turnServer = turnServer
	return nil
}

// ConnectToPeer initializes a connection to a peer using WebRTC.
func (nt *common.NATTraversal) ConnectToPeer(peerID, signalData string) (*common.webrtc.PeerConnection, error) {
	nt.peersLock.Lock()
	defer nt.peersLock.Unlock()

	peerConnection, err := webrtc.NewPeerConnection(common.webrtc.Configuration{
		ICEServers: nt.iceServers,
	})
	if err != nil {
		return nil, err
	}

	peerConnection.OnICECandidate(func(candidate *webrtc.ICECandidate) {
		if candidate == nil {
			return
		}
		candidateJSON, err := json.Marshal(candidate.ToJSON())
		if err != nil {
			log.Printf("Failed to marshal ICE candidate: %v", err)
			return
		}
		message := NewMessage(peerID, candidateJSON)
		Send(peerID, message)
	})

	peerConnection.OnICEConnectionStateChange(func(state webrtc.ICEConnectionState) {
		log.Printf("ICE Connection State has changed: %s", state.String())
		if state == webrtc.ICEConnectionStateDisconnected || state == webrtc.ICEConnectionStateFailed {
			nt.RemovePeer(peerID)
		}
	})

	nt.peers[peerID] = peerConnection
	return peerConnection, nil
}

// RemovePeer removes a peer from the NATTraversal instance.
func (nt *common.NATTraversal) RemovePeer(peerID string) {
	nt.peersLock.Lock()
	defer nt.peersLock.Unlock()

	if peer, exists := nt.peers[peerID]; exists {
		peer.Close()
		delete(nt.peers, peerID)
	}
}

// HandleSignalData processes incoming signaling data from a peer.
func (nt *common.NATTraversal) HandleSignalData(peerID, signalData string) error {
	nt.peersLock.Lock()
	defer nt.peersLock.Unlock()

	peerConnection, exists := nt.peers[peerID]
	if !exists {
		return errors.New("peer connection not found")
	}

	var candidate webrtc.ICECandidateInit
	if err := json.Unmarshal([]byte(signalData), &candidate); err != nil {
		return err
	}

	return peerConnection.AddICECandidate(candidate)
}

// EncryptSignalData encrypts signaling data using AES-GCM.
func EncryptSignalData(data []byte) ([]byte, error) {
	key, err := generateKey()
	if err != nil {
		return nil, err
	}
	return encryptAESGCM(data, key)
}

// DecryptSignalData decrypts signaling data using AES-GCM.
func DecryptSignalData(data []byte, key []byte) ([]byte, error) {
	return decryptAESGCM(data, key)
}

// GenerateAuthKey generates a secure authentication key for TURN server.
func GenerateAuthKey(username, realm, password string) []byte {
	hash := sha256.Sum256([]byte(username + ":" + realm + ":" + password))
	return hash[:]
}

// RunNATTraversal initializes the NAT traversal process for the given peer ID.
func (nt *common.NATTraversal) RunNATTraversal(peerID, signalData string) error {
	peerConnection, err := nt.ConnectToPeer(peerID, signalData)
	if err != nil {
		return err
	}

	offer, err := peerConnection.CreateOffer(nil)
	if err != nil {
		return err
	}

	if err := peerConnection.SetLocalDescription(offer); err != nil {
		return err
	}

	offerJSON, err := json.Marshal(offer)
	if err != nil {
		return err
	}

	encryptedOffer, err := EncryptSignalData(offerJSON)
	if err != nil {
		return err
	}

	message := NewMessage(peerID, encryptedOffer)
	return Send(peerID, message)
}


// CreatePeerConnection creates a new WebRTC peer connection for a given peer ID.
func (pcm *common.PeerConnectionManager) CreatePeerConnection(peerID string) (*webrtc.PeerConnection, error) {
	pcm.mux.Lock()
	defer pcm.mux.Unlock()

	if _, exists := pcm.peerConnections[peerID]; exists {
		return nil, errors.New("peer connection already exists")
	}

	peerConnection, err := webrtc.NewPeerConnection(pcm.peerConfig)
	if err != nil {
		return nil, err
	}

	pcm.peerConnections[peerID] = peerConnection
	pcm.peerLocks[peerID] = &sync.Mutex{}

	peerConnection.OnICECandidate(func(candidate *webrtc.ICECandidate) {
		if candidate == nil {
			return
		}
		candidateJSON, err := json.Marshal(candidate.ToJSON())
		if err != nil {
			log.Printf("Failed to marshal ICE candidate: %v", err)
			return
		}
		message := NewMessage(peerID, candidateJSON)
		Send(peerID, message)
	})

	peerConnection.OnICEConnectionStateChange(func(state webrtc.ICEConnectionState) {
		log.Printf("ICE Connection State has changed: %s", state.String())
		if state == webrtc.ICEConnectionStateDisconnected || state == webrtc.ICEConnectionStateFailed {
			pcm.RemovePeerConnection(peerID)
		}
	})

	return peerConnection, nil
}

// RemovePeerConnection removes a peer connection for a given peer ID.
func (pcm *common.PeerConnectionManager) RemovePeerConnection(peerID string) {
	pcm.mux.Lock()
	defer pcm.mux.Unlock()

	if peer, exists := pcm.peerConnections[peerID]; exists {
		peer.Close()
		delete(pcm.peerConnections, peerID)
		delete(pcm.peerLocks, peerID)
	}
}

// HandleSignalData handles incoming signaling data for a peer connection.
func (pcm *common.PeerConnectionManager) HandleSignalData(peerID string, signalData []byte) error {
	pcm.mux.RLock()
	defer pcm.mux.RUnlock()

	peerConnection, exists := pcm.peerConnections[peerID]
	if !exists {
		return errors.New("peer connection not found")
	}

	var candidate webrtc.ICECandidateInit
	if err := json.Unmarshal(signalData, &candidate); err != nil {
		return err
	}

	return peerConnection.AddICECandidate(candidate)
}

// EstablishConnection initiates the connection process with a peer.
func (pcm *common.PeerConnectionManager) EstablishConnection(peerID string, offer webrtc.SessionDescription) error {
	peerConnection, err := pcm.CreatePeerConnection(peerID)
	if err != nil {
		return err
	}

	if err := peerConnection.SetRemoteDescription(offer); err != nil {
		return err
	}

	answer, err := peerConnection.CreateAnswer(nil)
	if err != nil {
		return err
	}

	if err := peerConnection.SetLocalDescription(answer); err != nil {
		return err
	}

	answerJSON, err := json.Marshal(answer)
	if err != nil {
		return err
	}

	encryptedAnswer, err := encryptData(answerJSON)
	if err != nil {
		return err
	}

	message := NewMessage(peerID, encryptedAnswer)
	return Send(peerID, message)
}

// CreateOffer creates a connection offer to initiate a connection with a peer.
func (pcm *common.PeerConnectionManager) CreateOffer(peerID string) ([]byte, error) {
	peerConnection, err := pcm.CreatePeerConnection(peerID)
	if err != nil {
		return nil, err
	}

	offer, err := peerConnection.CreateOffer(nil)
	if err != nil {
		return nil, err
	}

	if err := peerConnection.SetLocalDescription(offer); err != nil {
		return nil, err
	}

	offerJSON, err := json.Marshal(offer)
	if err != nil {
		return nil, err
	}

	encryptedOffer, err := encryptData(offerJSON)
	if err != nil {
		return nil, err
	}

	return encryptedOffer, nil
}

// PeerExists checks if a peer connection exists.
func (pcm *common.PeerConnectionManager) PeerExists(peerID string) bool {
	pcm.mux.RLock()
	defer pcm.mux.RUnlock()
	_, exists := pcm.peerConnections[peerID]
	return exists
}

// CloseAllConnections closes all active peer connections.
func (pcm *common.PeerConnectionManager) CloseAllConnections() {
	pcm.mux.Lock()
	defer pcm.mux.Unlock()
	for peerID, conn := range pcm.peerConnections {
		conn.Close()
		delete(pcm.peerConnections, peerID)
		delete(pcm.peerLocks, peerID)
	}
}



// CreateConnection initializes a new WebRTC connection.
func (wm *common.WebRTCManager) CreateConnection(peerID string) (*webrtc.PeerConnection, error) {
	wm.connectionsLock.Lock()
	defer wm.connectionsLock.Unlock()

	if _, exists := wm.connections[peerID]; exists {
		return nil, errors.New("connection already exists")
	}

	config := webrtc.Configuration{
		ICEServers: wm.iceServers,
	}

	peerConnection, err := webrtc.NewPeerConnection(config)
	if err != nil {
		return nil, err
	}

	peerConnection.OnICECandidate(func(candidate *webrtc.ICECandidate) {
		if candidate == nil {
			return
		}
		candidateJSON, err := json.Marshal(candidate.ToJSON())
		if err != nil {
			log.Printf("Failed to marshal ICE candidate: %v", err)
			return
		}
		message := NewMessage(peerID, candidateJSON)
		Send(peerID, message)
	})

	peerConnection.OnICEConnectionStateChange(func(state webrtc.ICEConnectionState) {
		log.Printf("ICE Connection State has changed: %s", state.String())
		if state == webrtc.ICEConnectionStateDisconnected || state == webrtc.ICEConnectionStateFailed {
			wm.RemoveConnection(peerID)
		}
	})

	wm.connections[peerID] = peerConnection
	return peerConnection, nil
}

// RemoveConnection removes a WebRTC connection.
func (wm *common.WebRTCManager) RemoveConnection(peerID string) {
	wm.connectionsLock.Lock()
	defer wm.connectionsLock.Unlock()

	if conn, exists := wm.connections[peerID]; exists {
		conn.Close()
		delete(wm.connections, peerID)
	}
}

// HandleSignalingMessage processes incoming signaling messages.
func (wm *common.WebRTCManager) HandleSignalingMessage(peerID string, message []byte) error {
	wm.connectionsLock.RLock()
	defer wm.connectionsLock.RUnlock()

	peerConnection, exists := wm.connections[peerID]
	if !exists {
		return errors.New("connection not found")
	}

	var candidate webrtc.ICECandidateInit
	if err := json.Unmarshal(message, &candidate); err != nil {
		return err
	}

	return peerConnection.AddICECandidate(candidate)
}

// CreateOffer creates an SDP offer.
func (wm *common.WebRTCManager) CreateOffer(peerID string) ([]byte, error) {
	peerConnection, err := wm.CreateConnection(peerID)
	if err != nil {
		return nil, err
	}

	offer, err := peerConnection.CreateOffer(nil)
	if err != nil {
		return nil, err
	}

	if err := peerConnection.SetLocalDescription(offer); err != nil {
		return nil, err
	}

	offerJSON, err := json.Marshal(offer)
	if err != nil {
		return nil, err
	}

	return encryptData(offerJSON)
}

// HandleOffer handles an incoming SDP offer.
func (wm *common.WebRTCManager) HandleOffer(peerID string, offer webrtc.SessionDescription) ([]byte, error) {
	peerConnection, err := wm.CreateConnection(peerID)
	if err != nil {
		return nil, err
	}

	if err := peerConnection.SetRemoteDescription(offer); err != nil {
		return nil, err
	}

	answer, err := peerConnection.CreateAnswer(nil)
	if err != nil {
		return nil, err
	}

	if err := peerConnection.SetLocalDescription(answer); err != nil {
		return nil, err
	}

	answerJSON, err := json.Marshal(answer)
	if err != nil {
		return nil, err
	}

	return encryptData(answerJSON)
}

// HandleAnswer processes an incoming SDP answer.
func (wm *common.WebRTCManager) HandleAnswer(peerID string, answer webrtc.SessionDescription) error {
	wm.connectionsLock.RLock()
	defer wm.connectionsLock.RUnlock()

	peerConnection, exists := wm.connections[peerID]
	if !exists {
		return errors.New("connection not found")
	}

	return peerConnection.SetRemoteDescription(answer)
}

// SetupDataChannel initializes a data channel for the given peer.
func (wm *common.WebRTCManager) SetupDataChannel(peerID string) (*webrtc.DataChannel, error) {
	peerConnection, exists := wm.connections[peerID]
	if !exists {
		return nil, errors.New("connection not found")
	}

	dataChannel, err := peerConnection.CreateDataChannel("data", nil)
	if err != nil {
		return nil, err
	}

	dataChannel.OnOpen(func() {
		log.Printf("Data channel with peer %s opened", peerID)
	})

	dataChannel.OnClose(func() {
		log.Printf("Data channel with peer %s closed", peerID)
	})

	dataChannel.OnMessage(func(msg webrtc.DataChannelMessage) {
		log.Printf("Received message from peer %s: %s", peerID, string(msg.Data))
	})

	return dataChannel, nil
}

// SendMessage sends a message to a peer via the data channel.
func (wm *common.WebRTCManager) SendMessage(peerID string, message []byte) error {
	peerConnection, exists := wm.connections[peerID]
	if !exists {
		return errors.New("connection not found")
	}

	dataChannel, err := wm.SetupDataChannel(peerID)
	if err != nil {
		return err
	}

	return dataChannel.SendText(string(message))
}

// Initialize initializes the WebRTCManager with necessary configurations.
func (wm *common.WebRTCManager) Initialize() error {
	peers, err := wm.peerDiscovery.DiscoverPeers()
	if err != nil {
		return err
	}

	for _, peer := range peers {
		_, err := wm.CreateConnection(peer.ID)
		if err != nil {
			log.Printf("Failed to create connection with peer %s: %v", peer.ID, err)
			continue
		}

		offer, err := wm.CreateOffer(peer.ID)
		if err != nil {
			log.Printf("Failed to create offer for peer %s: %v", peer.ID, err)
			continue
		}

		err = wm.signalingServer.SendSignal(peer.ID, offer)
		if err != nil {
			log.Printf("Failed to send offer to peer %s: %v", peer.ID, err)
		}
	}

	return nil
}
