package offchain

import (
	"context"
	"errors"
	"sync"

	"synthron_blockchain/pkg/layer0/core/crypto"
	"synthron_blockchain/pkg/layer0/core/storage"
	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p-core/host"
	"github.com/libp2p/go-libp2p-core/peer"
	"github.com/libp2p/go-libp2p-core/network"
	"github.com/libp2p/go-libp2p-core/protocol"
)

// ProtocolManager manages the set of interoperability protocols, handling secure data transfer across different blockchain networks.
type ProtocolManager struct {
	host   host.Host
	peers  map[peer.ID]*peer.AddrInfo
	mutex  sync.Mutex
}

// NewProtocolManager initializes a new protocol manager with the necessary libp2p configurations and security settings.
func NewProtocolManager() (*ProtocolManager, error) {
	h, err := libp2p.New(libp2p.NATPortMap(), libp2p.EnableRelay())
	if err != nil {
		return nil, err
	}

	return &ProtocolManager{
		host:  h,
		peers: make(map[peer.ID]*peer.AddrRef),
	}, nil
}

// ConnectPeer adds and securely connects to a new peer in the network.
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

// BroadcastMessage securely sends a message to all connected peers using a specified protocol, with encryption as needed.
func (pm *ProtocolManager) BroadcastMessage(protocolID protocol.ID, message []byte) error {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	for _, peerInfo := range pm.peers {
		if err := pm.sendMessage(peerInfo.ID, protocolID, message); err != nil {
			return err
		}
	}
	return nil
}

// sendMessage encrypts and sends a message to a specific peer.
func (pm *ProtocolManager) sendMessage(peerID peer.ID, protocolID protocol.ID, message []byte) error {
	stream, err := pm.host.NewStream(context.Background(), peerID, protocolID)
	if err != nil {
	return err
	}
	defer stream.Close()

	// Encrypt the message before sending
	encryptedMessage, err := crypto.EncryptMessage(message)
	if err != nil {
	return err
	}

	_, err = stream.Write(encryptedMessage)
	return err
}

// HandleProtocol sets up handling for a specific protocol, with decryption as needed.
func (pm *ProtocolManager) HandleProtocol(protocolID protocol.ID, handler func(stream network.Stream)) {
	pm.host.SetStreamHandler(protocolID, func(stream network.Stream) {
		defer stream.Close()
		// Decrypt the incoming message
		encryptedMessage, err := io.ReadAll(stream)
		if err != nil {
			log.Println("Error reading from stream:", err)
			return
		}

		message, err := crypto.DecryptMessage(encryptedMessage)
		if err != nil {
			log.Println("Error decrypting message:", err)
			return
		}

		handler(message, stream)
	})
}

// Example of a protocol handler function for asset transfer
func handleAssetTransfer(message []byte, stream network.Stream) {
	var msg storage.AssetTransfer
	if err := json.Unmarshal(message, &msg); err != nil {
		log.Println("Error unmarshalling asset transfer:", err)
		return
	}

	// Process the asset transfer...
}
