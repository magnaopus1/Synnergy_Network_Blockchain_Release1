package interoperability

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"sync"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p-core/crypto"
	"github.com/libp2p/go-libp2p-core/host"
	"github.com/libp2p/go-libp2p-core/network"
	"github.com/libp2p/go-libp2p-core/peer"
	"github.com/libp2p/go-libp2p-core/protocol"
	"synthron_blockchain/pkg/layer0/core/storage"
)

// ProtocolManager manages the set of interoperability protocols.
type ProtocolManager struct {
	host  host.Host
	peers map[peer.ID]*peer.AddrInfo
	mutex sync.Mutex
}

// NewProtocolManager initializes a new protocol manager with the necessary libp2p configurations.
func NewProtocolManager() (*ProtocolManager, error) {
	// Generate a new key pair for this host
	priv, _, err := crypto.GenerateKeyPair(crypto.RSA, 2048)
	if err != nil {
		return nil, err
	}

	h, err := libp2p.New(libp2p.Identity(priv))
	if err != nil {
		return nil, err
	}

	return &ProtocolManager{
		host:  h,
		peers: make(map[peer.ID]*peer.AddrInfo),
	}, nil
}

// ConnectPeer adds and connects to a new peer in the network.
func (pm *ProtocolManager) ConnectPeer(info peer.AddrInfo) error {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	if _, exists := pm.peers[info.ID]; exists {
		return errors.New("peer already connected")
	}

	if err := pm.host.Connect(context.Background(), info); err != nil {
		return err
	}

	pm.peers[info.ID] = &info
	return nil
}

// BroadcastMessage sends a message to all connected peers using a specified protocol.
func (pm *ProtocolManager) BroadcastMessage(protocolID protocol.ID, message string) error {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	for _, peerInfo := range pm.peers {
		if err := pm.sendMessage(peerInfo.ID, protocolID, message); err != nil {
			return err
		}
	}
	return nil
}

// sendMessage sends a message to a specific peer.
func (pm *ProtocolManager) sendMessage(peerID peer.ID, protocolID protocol.ID, message string) error {
	stream, err := pm.host.NewStream(context.Background(), peerID, protocolID)
	if err != nil {
		return err
	}
	defer stream.Close()

	_, err = stream.Write([]byte(message))
	return err
}

// HandleProtocol sets up handling for a specific protocol.
func (pm *ProtocolManager) HandleProtocol(protocolID protocol.ID, handler func(stream network.Stream)) {
	pm.host.SetStreamHandler(protocolID, handler)
}

// handleAssetTransfer is an example of a protocol handler function.
func handleAssetTransfer(stream network.Stream) {
	defer stream.Close()
	var msg storage.AssetTransfer
	if err := json.NewDecoder(stream).Decode(&msg); err != nil {
		// Log and handle error
		return
	}

	// Process asset transfer...
	// Validate, authenticate, and apply the asset transfer
}

// DisconnectPeer safely disconnects a peer from the host.
func (pm *ProtocolManager) DisconnectPeer(peerID peer.ID) error {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	if _, exists := pm.peers[peerID]; !exists {
		return errors.New("peer not found")
	}

	if err := pm.host.ClosePeerConnection(peerID); err != nil {
		return err
	}

	delete(pm.peers, peerID)
	return nil
}

