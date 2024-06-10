package discovery

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log"
	"net"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p-core/discovery"
	"github.com/libp2p/go-libp2p-core/host"
	"github.com/libp2p/go-libp2p-core/network"
	"github.com/libp2p/go-libp2p-core/peer"
	"github.com/libp2p/go-libp2p-peerstore/peerstore"
	"github.com/libp2p/go-libp2p/p2p/discovery/routing"
	"github.com/libp2p/go-libp2p-kad-dht"
	"github.com/multiformats/go-multiaddr"
)

// PeerAdvertisementService manages peer advertisement and discovery
type PeerAdvertisementService struct {
	Host           host.Host
	DHT            *dht.IpfsDHT
	Discovery      discovery.Discovery
	BootstrapNodes []peer.AddrInfo
	ctx            context.Context
	cancel         context.CancelFunc
}

// NewPeerAdvertisementService initializes a new PeerAdvertisementService
func NewPeerAdvertisementService() (*PeerAdvertisementService, error) {
	ctx, cancel := context.WithCancel(context.Background())

	// Generate a new identity for the host
	priv, _, err := crypto.GenerateEd25519Key(rand.Reader)
	if err != nil {
		return nil, err
	}

	// Create a new libp2p host
	h, err := libp2p.New(
		libp2p.Identity(priv),
		libp2p.ListenAddrStrings("/ip4/0.0.0.0/tcp/0"),
	)
	if err != nil {
		return nil, err
	}

	// Create a new Kademlia DHT
	kademliaDHT, err := dht.New(ctx, h)
	if err != nil {
		return nil, err
	}

	// Bootstrap the DHT
	if err := kademliaDHT.Bootstrap(ctx); err != nil {
		return nil, err
	}

	// Initialize PeerAdvertisementService
	pas := &PeerAdvertisementService{
		Host:           h,
		DHT:            kademliaDHT,
		BootstrapNodes: BootstrapNodeList,
		ctx:            ctx,
		cancel:         cancel,
	}

	// Initialize bootstrap nodes
	pas.initBootstrapNodes()

	// Set up routing discovery
	pas.Discovery = routing.NewRoutingDiscovery(kademliaDHT)

	return pas, nil
}

// initBootstrapNodes initializes the bootstrap nodes in the DHT
func (pas *PeerAdvertisementService) initBootstrapNodes() {
	for _, node := range pas.BootstrapNodes {
		pas.Host.Peerstore().AddAddr(node.ID, node.Addrs[0], peerstore.PermanentAddrTTL)
	}
}

// AdvertisePresence advertises the presence of this node to the network
func (pas *PeerAdvertisementService) AdvertisePresence() error {
	ctx, cancel := context.WithTimeout(pas.ctx, discoveryTimeout)
	defer cancel()

	// Advertise the node's presence
	discovery.Advertise(ctx, pas.Discovery, "synthron-network")

	log.Println("Node advertised successfully")
	return nil
}

// HandleIncomingConnections handles incoming connections from other peers
func (pas *PeerAdvertisementService) HandleIncomingConnections() {
	pas.Host.SetStreamHandler("/synthron/1.0.0", func(s network.Stream) {
		defer s.Close()
		log.Println("New incoming connection from", s.Conn().RemotePeer().String())

		// Handle stream data
		buf := make([]byte, 1024)
		for {
			n, err := s.Read(buf)
			if err != nil {
				break
			}
			log.Printf("Received %s", string(buf[:n]))
		}
	})
}

// DiscoverPeers discovers peers in the network
func (pas *PeerAdvertisementService) DiscoverPeers() ([]peer.AddrInfo, error) {
	ctx, cancel := context.WithTimeout(pas.ctx, discoveryTimeout)
	defer cancel()

	peers, err := pas.Discovery.FindPeers(ctx, "synthron-network")
	if err != nil {
		return nil, err
	}

	var discoveredPeers []peer.AddrInfo
	for peer := range peers {
		if peer.ID == pas.Host.ID() {
			continue
		}
		discoveredPeers = append(discoveredPeers, peer)
	}

	return discoveredPeers, nil
}

// EncodePeerInfo encodes peer information to JSON
func EncodePeerInfo(pi peer.AddrInfo) ([]byte, error) {
	return json.Marshal(pi)
}

// DecodePeerInfo decodes JSON to peer information
func DecodePeerInfo(data []byte) (peer.AddrInfo, error) {
	var pi peer.AddrInfo
	err := json.Unmarshal(data, &pi)
	return pi, err
}

// CLI Commands
// To start the peer advertisement service and advertise presence, use:
// synthron advertise start
// To discover peers in the network, use:
// synthron advertise peers

// API Endpoints
// POST /api/v1/advertise/start: Start the peer advertisement service
// GET /api/v1/advertise/peers: Discover peers in the network

// BootstrapNodeList holds a list of bootstrap nodes
var BootstrapNodeList = []peer.AddrInfo{
	// Example Bootstrap Nodes
	{ID: peer.ID("QmYwAPJzv5CZsnAzt8auVZRnJfMT5m9rG1p2PZf9JKCS7V"), Addrs: []multiaddr.Multiaddr{multiaddr.StringCast("/ip4/104.131.131.82/tcp/4001")}},
	{ID: peer.ID("QmTeqw4okyR1E93V3R1TtxeBfTt7SD7oNLZwK7He6vMGFJ"), Addrs: []multiaddr.Multiaddr{multiaddr.StringCast("/ip4/104.236.179.241/tcp/4001")}},
}

const discoveryTimeout = time.Second * 30

func main() {
	pas, err := NewPeerAdvertisementService()
	if err != nil {
		log.Fatalf("Failed to create PeerAdvertisementService: %v", err)
	}

	// Start advertisement
	go func() {
		if err := pas.AdvertisePresence(); err != nil {
			log.Fatalf("Failed to advertise presence: %v", err)
		}
	}()

	// Handle incoming connections
	go pas.HandleIncomingConnections()

	for {
		// Discover peers
		peers, err := pas.DiscoverPeers()
		if err != nil {
			log.Fatalf("Failed to discover peers: %v", err)
		}

		for _, peer := range peers {
			peerInfo, err := EncodePeerInfo(peer)
			if err != nil {
				log.Printf("Failed to encode peer info: %v", err)
				continue
			}
			log.Printf("Discovered peer: %s", string(peerInfo))
		}

		time.Sleep(time.Minute)
	}
}
