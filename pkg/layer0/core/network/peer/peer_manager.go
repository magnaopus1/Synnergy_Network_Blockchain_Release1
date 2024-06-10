package peer

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p-core/host"
	"github.com/libp2p/go-libp2p-core/network"
	"github.com/libp2p/go-libp2p-core/peer"
	"github.com/libp2p/go-libp2p-peerstore"
)

// PeerManager handles the lifecycle and management of peers in the network.
type PeerManager struct {
	Host        host.Host
	PeerStore   peerstore.Peerstore
	Connections sync.Map // map[peer.ID]network.Conn
}

// NewPeerManager creates a new PeerManager with initialized libp2p host and peer store.
func NewPeerManager(ctx context.Context, listenAddr string) (*PeerManager, error) {
	h, err := libp2p.New(ctx, libp2p.ListenAddrStrings(listenAddr))
	if err != nil {
		return nil, fmt.Errorf("failed to create libp2p host: %v", err)
	}

	return &PeerManager{
		Host:      h,
		PeerStore: h.Peerstore(),
	}, nil
}

// Start initiates the peer management, handling connections and disconnections.
func (pm *PeerManager) Start(ctx context.Context) {
	pm.Host.Network().Notify(&network.NotifyBundle{
		ConnectedF:    pm.onConnect,
		DisconnectedF: pm.onDisconnect,
	})

	// Example of proactive peer discovery and connection
	go pm.manageConnections(ctx)
}

// onConnect handles logic when a connection to a peer is made.
func (pm *PeerManager) onConnect(n network.Network, conn network.Conn) {
	fmt.Println("Connected to:", conn.RemotePeer())
	pm.Connections.Store(conn.RemotePeer(), conn)
}

// onDisconnect handles logic when a peer disconnects.
func (pm *PeerManager) onDisconnect(n network.Network, conn network.Conn) {
	fmt.Println("Disconnected from:", conn.RemotePeer())
	pm.Connections.Delete(conn.RemotePeer())
}

// manageConnections periodically checks and optimizes connections.
func (pm *PeerManager) manageConnections(ctx context.Context) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			pm.optimizeConnections()
		}
	}
}

// optimizeConnections reviews and manages the current connections for optimization.
func (pm *PeerManager) optimizeConnections() {
	// Implementation for connection optimization such as eviction of low-quality peers.
	fmt.Println("Optimizing connections...")
}

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	pm, err := NewPeerManager(ctx, "/ip4/0.0.0.0/tcp/4001")
	if err != nil {
		fmt.Println("Error creating Peer Manager:", err)
		return
	}

	pm.Start(ctx)
	select {}
}
