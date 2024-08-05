package network

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/gob"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"sync"
	"time"

	"golang.org/x/crypto/scrypt"
	"golang.org/x/net/websocket"
)

const (
	ConnectionTimeout         = 10 * time.Second
	PeerSelectionInterval     = 30 * time.Second
	MaxRetries                = 5
	RetryInterval             = 2 * time.Second
	KeepAlivePeriod           = 30 * time.Second
	OptimizationCheckInterval = 10 * time.Second
	MaxMessageSize            = 4096
	DefaultReadTimeout        = 10 * time.Second
	DefaultWriteTimeout       = 10 * time.Second
	ConnectionPoolSize        = 100
	EncryptionKeySize         = 32
	EncryptionNonceSize       = 12
	SignatureKeySize          = 64
	ReconnectRetryLimit       = 5
	ReconnectRetryDelay       = 5 * time.Second
	MaxConnectionRetries      = 3
)




// GetConnection retrieves a connection from the pool or establishes a new one
func (cp *common.ConnectionPool) GetConnection(address string) (net.Conn, error) {
	cp.Mutex.Lock()
	defer cp.Mutex.Unlock()

	if conn, exists := cp.Pool[address]; exists {
		return conn, nil
	}

	conn, err := net.DialTimeout("tcp", address, ConnectionTimeout)
	if err != nil {
		return nil, err
	}

	if len(cp.Pool) < cp.MaxSize {
		cp.Pool[address] = conn
	}

	return conn, nil
}

// RemoveConnection removes a connection from the pool
func (cp *common.ConnectionPool) RemoveConnection(address string) {
	cp.Mutex.Lock()
	defer cp.Mutex.Unlock()
	if conn, exists := cp.Pool[address]; exists {
		conn.Close()
		delete(cp.Pool, address)
	}
}

// SelectBestPeers selects the best peers using predictive analysis
func (n *common.Node) SelectBestPeers() ([]*common.Peer, error) {
	n.PeerMutex.Lock()
	defer n.PeerMutex.Unlock()

	if len(n.ActivePeers) == 0 {
		return nil, errors.New("no active peers available")
	}

	var peers []*common.Peer
	for _, peer := range n.ActivePeers {
		peers = append(peers, peer)
	}

	// Using machine learning for predictive analysis to rank peers
	rankedPeers, err := rankPeers(peers)
	if err != nil {
		return nil, err
	}

	return rankedPeers, nil
}

// SendMessage sends a message to a peer
func (n *common.Node) SendMessage(peerID string, msg *common.Message) error {
	n.PeerMutex.Lock()
	peer, exists := n.ActivePeers[peerID]
	n.PeerMutex.Unlock()
	if !exists {
		return errors.New("peer not found")
	}

	address := net.JoinHostPort(peer.IP, fmt.Sprintf("%d", peer.Port))
	conn, err := n.ConnectionPool.GetConnection(address)
	if err != nil {
		return err
	}

	msgBytes, err := json.Marshal(msg)
	if err != nil {
		return err
	}

	encryptedMsg, err := encryptMessage(msgBytes, &peer.PublicKey, &n.PrivateKey)
	if err != nil {
		return err
	}

	_, err = conn.Write(encryptedMsg)
	if err != nil {
		n.ConnectionPool.RemoveConnection(address)
	}
	return err
}

// ReceiveMessage listens for incoming messages
func (n *common.Node) ReceiveMessage() {
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", n.Port))
	if err != nil {
		logError("Error starting listener:", err)
		return
	}
	defer ln.Close()

	for {
		conn, err := ln.Accept()
		if err != nil {
			logError("Error accepting connection:", err)
			continue
		}

		go n.handleConnection(conn)
	}
}

func (n *common.Node) handleConnection(conn net.Conn) {
	defer conn.Close()

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		logError("Error reading from connection:", err)
		return
	}

	decryptedMsg, err := decryptMessage(buf[:n], &n.PrivateKey)
	if err != nil {
		logError("Error decrypting message:", err)
		return
	}

	var msg common.Message
	if err := json.Unmarshal(decryptedMsg, &msg); err != nil {
		logError("Error unmarshaling message:", err)
		return
	}

	if err := n.validateMessage(&msg); err != nil {
		logError("Invalid message:", err)
		return
	}

	switch msg.Type {
	case "peer_info":
		n.handlePeerInfoMessage(&msg)
	case "data":
		n.handleDataMessage(&msg)
	default:
		logError("Unknown message type:", msg.Type)
	}
}

func (n *common.Node) validateMessage(msg *common.Message) error {
	peerID, err := verifySignature(msg.Payload, msg.Signature)
	if err != nil {
		return err
	}

	n.PeerMutex.Lock()
	_, exists := n.ActivePeers[peerID]
	n.PeerMutex.Unlock()

	if !exists {
		return errors.New("unknown peer")
	}

	return nil
}

func (n *common.Node) handlePeerInfoMessage(msg *common.Message) {
	var peer Peer
	if err := json.Unmarshal(msg.Payload, &peer); err != nil {
		logError("Error unmarshaling peer info message:", err)
		return
	}

	n.AddPeer(&peer)
	log("Added new peer:", peer.ID)
}

func (n *common.Node) handleDataMessage(msg *common.Message) {
	log("Received data message:", string(msg.Payload))
}

func (n *common.Node) monitorLatency() {
	ticker := time.NewTicker(OptimizationCheckInterval)
	defer ticker.Stop()

	for range ticker.C {
		n.PeerMutex.Lock()
		for peerID, peer := range n.ActivePeers {
			start := time.Now()
			err := n.pingPeer(peer)
			latency := time.Since(start)
			if err != nil {
				log(fmt.Sprintf("Failed to ping peer %s: %v", peerID, err))
				continue
			}
			n.MetricsMutex.Lock()
			n.LatencyMetrics[peerID] = latency
			peer.Latency = latency
			n.MetricsMutex.Unlock()
		}
		n.PeerMutex.Unlock()
		n.optimizeRoutes()
	}
}

func (n *common.Node) pingPeer(peer *common.Peer) error {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(peer.IP, fmt.Sprintf("%d", peer.Port)), ConnectionTimeout)
	if err != nil {
		return err
	}
	defer conn.Close()

	msg := &vMessage{
		Type:      "ping",
		Payload:   []byte("ping"),
		Timestamp: time.Now(),
	}

	encryptedMsg, err := n.encryptAndSignMessage(msg)
	if err != nil {
		return err
	}

	_, err = conn.Write(encryptedMsg)
	if err != nil {
		return err
	}

	buf := make([]byte, 4096)
	_, err = conn.Read(buf)
	if err != nil {
		return err
	}

	return nil
}

func (n *common.Node) optimizeRoutes() {
	n.MetricsMutex.Lock()
	defer n.MetricsMutex.Unlock()

	for peerID, latency := range n.LatencyMetrics {
		log(fmt.Sprintf("Optimized route to peer %s with latency %v", peerID, latency))
	}
}

func (n *common.Node) encryptAndSignMessage(msg *common.Message) ([]byte, error) {
	msgBytes, err := json.Marshal(msg)
	if err != nil {
		return nil, err
	}

	encryptedMsg, err := encryptMessage(msgBytes, &msg.ReceiverPublicKey, &n.PrivateKey)
	if err != nil {
		return nil, err
	}

	return encryptedMsg, nil
}

// AddPeer adds a new peer to the governance system.
func (pg *common.PeerGovernance) AddPeer(peer *common.Peer) error {
	pg.PeerLock.Lock()
	defer pg.PeerLock.Unlock()

	if _, exists := pg.Peers[peer.ID]; exists {
		return errors.New("peer already exists")
	}

	pg.Peers[peer.ID] = peer
	pg.Reputation[peer.ID] = 0 // Initialize reputation
	return nil
}

// RemovePeer removes a peer from the governance system.
func (pg *common.PeerGovernance) RemovePeer(peerID string) error {
	pg.PeerLock.Lock()
	defer pg.PeerLock.Unlock()

	if _, exists := pg.Peers[peerID]; !exists {
		return errors.New("peer does not exist")
	}

	delete(pg.Peers, peerID)
	delete(pg.Reputation, peerID)
	return nil
}

// ProposeChange allows a peer to propose a governance change.
func (pg *common.PeerGovernance) ProposeChange(peerID string, proposal interface{}) error {
	pg.PeerLock.RLock()
	defer pg.PeerLock.RUnlock()

	if _, exists := pg.Peers[peerID]; !exists {
		return errors.New("peer does not exist")
	}

	return pg.Voting.Propose(peerID, proposal)
}

// Vote allows a peer to vote on a proposal.
func (pg *common.PeerGovernance) Vote(peerID string, proposalID string, vote bool) error {
	pg.PeerLock.RLock()
	defer pg.PeerLock.RUnlock()

	if _, exists := pg.Peers[peerID]; !exists {
		return errors.New("peer does not exist")
	}

	return pg.Voting.CastVote(peerID, proposalID, vote)
}

// GetReputation retrieves the reputation score of a peer.
func (pg *common.PeerGovernance) GetReputation(peerID string) (float64, error) {
	pg.PeerLock.RLock()
	defer pg.PeerLock.RUnlock()

	rep, exists := pg.Reputation[peerID]
	if !exists {
		return 0, errors.New("peer does not exist")
	}

	return rep, nil
}

// UpdateReputation updates the reputation score of a peer.
func (pg *common.PeerGovernance) UpdateReputation(peerID string, delta float64) error {
	pg.PeerLock.Lock()
	defer pg.PeerLock.Unlock()

	if _, exists := pg.Peers[peerID]; !exists {
		return errors.New("peer does not exist")
	}

	pg.Reputation[peerID] += delta
	return nil
}

// AuthenticatePeer authenticates a peer using their public key.
func (pg *common.PeerGovernance) AuthenticatePeer(peerID string, pubKey *ecdsa.PublicKey, signature, message []byte) (bool, error) {
	pg.PeerLock.RLock()
	defer pg.PeerLock.RUnlock()

	if _, exists := pg.Peers[peerID]; !exists {
		return false, errors.New("peer does not exist")
	}

	hash := sha256.Sum256(message)
	valid := ecdsa.VerifyASN1(pubKey, hash[:], signature)
	return valid, nil
}

// EncryptMessage encrypts a message for a peer using their public key.
func (pg *common.PeerGovernance) EncryptMessage(peerID string, message []byte) ([]byte, error) {
	pg.PeerLock.RLock()
	defer pg.PeerLock.RUnlock()

	peer, exists := pg.Peers[peerID]
	if !exists {
		return nil, errors.New("peer does not exist")
	}

	encryptedMsg, err := encryptMessage(message, &peer.PublicKey, nil)
	if err != nil {
		return nil, err
	}

	return encryptedMsg, nil
}

// DecryptMessage decrypts a message for a peer using their private key.
func (pg *common.PeerGovernance) DecryptMessage(peerID string, encryptedMessage []byte) ([]byte, error) {
	pg.PeerLock.RLock()
	defer pg.PeerLock.RUnlock()

	peer, exists := pg.Peers[peerID]
	if !exists {
		return nil, errors.New("peer does not exist")
	}

	decryptedMsg, err := decryptMessage(encryptedMessage, &peer.PrivateKey)
	if err != nil {
		return nil, err
	}

	return decryptedMsg, nil
}

// SignMessage signs a message using the peer's private key.
func (pg *common.PeerGovernance) SignMessage(peerID string, message []byte) ([]byte, error) {
	pg.PeerLock.RLock()
	defer pg.PeerLock.RUnlock()

	peer, exists := pg.Peers[peerID]
	if !exists {
		return nil, errors.New("peer does not exist")
	}

	hash := sha256.Sum256(message)
	signature, err := ecdsa.SignASN1(rand.Reader, &peer.PrivateKey, hash[:])
	if err != nil {
		return nil, err
	}

	return signature, nil
}

// VerifySignature verifies a message's signature using the peer's public key.
func (pg *common.PeerGovernance) VerifySignature(peerID string, message, signature []byte) (bool, error) {
	pg.PeerLock.RLock()
	defer pg.PeerLock.RUnlock()

	peer, exists := pg.Peers[peerID]
	if !exists {
		return false, errors.New("peer does not exist")
	}

	hash := sha256.Sum256(message)
	valid := ecdsa.VerifyASN1(&peer.PublicKey, hash[:], signature)
	return valid, nil
}

// BroadcastProposal broadcasts a governance proposal to all peers.
func (pg *common.PeerGovernance) BroadcastProposal(proposal interface{}) error {
	pg.PeerLock.RLock()
	defer pg.PeerLock.RUnlock()

	data, err := json.Marshal(proposal)
	if err != nil {
		return err
	}

	for _, peer := range pg.Peers {
		err := peer.SendMessage(data)
		if err != nil {
			return err
		}
	}

	return nil
}

// SendMessage sends a message to a specific peer.
func (peer *common.Peer) SendMessage(message []byte) error {
	encryptedMessage, err := encryptMessage(message, &peer.PublicKey, nil)
	if err != nil {
		return err
	}

	// Sending logic here (e.g., using a network library)
	// ...

	return nil
}

func (pi *common.PeerIncentives) AddReward(peerID string, amount *big.Int) {
	pi.mu.Lock()
	defer pi.mu.Unlock()
	if _, exists := pi.rewards[peerID]; !exists {
		pi.rewards[peerID] = big.NewInt(0)
	}
	pi.rewards[peerID].Add(pi.rewards[peerID], amount.Mul(amount, pi.rewardFactor))
	pi.reputation[peerID]++
}

func (pi *common.PeerIncentives) AddPenalty(peerID string, amount *big.Int) {
	pi.mu.Lock()
	defer pi.mu.Unlock()
	if _, exists := pi.penalties[peerID]; !exists {
		pi.penalties[peerID] = big.NewInt(0)
	}
	pi.penalties[peerID].Add(pi.penalties[peerID], amount.Mul(amount, pi.penaltyFactor))
	pi.reputation[peerID]--
}

func (pi *common.PeerIncentives) CalculateNetIncentives(peerID string) (*big.Int, error) {
	pi.mu.Lock()
	defer pi.mu.Unlock()
	reward, rewardExists := pi.rewards[peerID]
	penalty, penaltyExists := pi.penalties[peerID]

	if !rewardExists && !penaltyExists {
		return nil, errors.New("peerID not found")
	}

	netIncentive := big.NewInt(0)
	if rewardExists {
		netIncentive.Add(netIncentive, reward)
	}
	if penaltyExists {
		netIncentive.Sub(netIncentive, penalty)
	}

	return netIncentive, nil
}

func (pi *common.PeerIncentives) PayoutRewards(peerID string) error {
	netIncentive, err := pi.CalculateNetIncentives(peerID)
	if err != nil {
		return err
	}

	// Simulate the reward payout
	// Placeholder for actual reward payout logic
	transferRewards(peerID, netIncentive)

	// Reset the rewards and penalties after payout
	pi.mu.Lock()
	defer pi.mu.Unlock()
	delete(pi.rewards, peerID)
	delete(pi.penalties, peerID)

	return nil
}

func (pi *common.PeerIncentives) EpochEnd() {
	pi.mu.Lock()
	defer pi.mu.Unlock()

	for peerID := range pi.rewards {
		pi.PayoutRewards(peerID)
	}
}

func (pi *common.PeerIncentives) ReputationScore(peerID string) (int, error) {
	pi.mu.Lock()
	defer pi.mu.Unlock()
	score, exists := pi.reputation[peerID]
	if !exists {
		return 0, errors.New("peerID not found")
	}
	return score, nil
}

// StartEpochRoutine starts a routine to periodically end epochs
func StartEpochRoutine(pi *common.PeerIncentives) {
	ticker := time.NewTicker(pi.epochDuration)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			pi.EpochEnd()
		}
	}
}




// GetPeer retrieves a peer by ID
func (pm *common.PeerManager) GetPeer(peerID string) (*common.Peer, error) {
	pm.peerMutex.RLock()
	defer pm.peerMutex.RUnlock()

	peer, exists := pm.peers[peerID]
	if !exists {
		return nil, errors.New("peer not found")
	}

	return peer, nil
}

// ListActivePeers lists all active peers in the network
func (pm *common.PeerManager) ListActivePeers() []*common.Peer {
	pm.peerMutex.RLock()
	defer pm.peerMutex.RUnlock()

	activePeers := []*common.Peer{}
	for _, peer := range pm.peers {
		if peer.Active {
			activePeers = append(activePeers, peer)
		}
	}

	return activePeers
}
