package peer

import (
	"context"
	"crypto/rand"
	"fmt"
	"time"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p-core/crypto"
	"github.com/libp2p/go-libp2p-core/host"
	"github.com/libp2p/go-libp2p-core/peer"
	dht "github.com/libp2p/go-libp2p-kad-dht"
	"github.com/libp2p/go-libp2p-peerstore"
	"github.com/multiformats/go-multiaddr"
)

// PeerDiscovery manages the discovery of new peers within the Synnergy Network.
type PeerDiscovery struct {
	Host *host.Host
	DHT  *dht.IpfsDHT
}

// NewPeerDiscovery creates a new peer discovery service with the necessary settings.
func NewPeerDiscovery(ctx context.Context, listenAddr string) (*PeerDiscovery, error) {
	// Generate a new key pair for this host.
	priv, _, err := crypto.GenerateKeyPairWithReader(crypto.Ed25519, -1, rand.Reader)
	if err != nil {
		return nil, err
	}

	// Create a multiaddress.
	addr, _ := multiaddr.NewMultiaddr(listenAddr)

	// Initialize the host.
	h, err := libp2p.New(ctx,
		libp2p.ListenAddrs(addr),
		libp2p.Identity(priv),
	)
	if err != nil {
		return nil, err
	}

	// Set up a DHT for peer discovery.
	kadDHT, err := dht.New(ctx, h)
	if err != nil {
		return nil, err
	}

	return &PeerDiscovery{
		Host: &h,
		DHT:  kadDHT,
	}, nil
}

// DiscoverPeers starts the discovery process using the DHT.
func (pd *PeerDiscovery) DiscoverPeers(ctx context.Context) error {
	// Bootstrap the DHT.
	if err := pd.DHT.Bootstrap(ctx); err != nil {
		return err
	}

	// Use the DHT to find peers.
	peerChan, err := pd.DHT.FindPeers(ctx, "synnergy-network")
	if err != nil {
		return err
	}

	for p := range peerChan {
		if p.ID == (*pd.Host).ID() || len(p.Addrs) == 0 {
			continue
		}

		// Connect to the peer.
		if err := (*pd.Host).Connect(ctx, p); err != nil {
			fmt.Println("Failed to connect to peer:", err)
			continue
		}
		fmt.Println("Connected to:", p.ID)
	}

	return nil
}

// Run starts the peer discovery service.
func (pd *PeerDiscovery) Run() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := pd.DiscoverPeers(ctx); err != nil {
		fmt.Println("Error during peer discovery:", err)
		return
	}
}

func main() {
	// Example usage of the PeerDiscovery system.
	pd, err := NewPeerDiscovery(context.Background(), "/ip4/0.0.0.0/tcp/4001")
	if err != nil {
		fmt.Println("Error setting up peer discovery:", err)
		return
	}

	pd.Run()
}
