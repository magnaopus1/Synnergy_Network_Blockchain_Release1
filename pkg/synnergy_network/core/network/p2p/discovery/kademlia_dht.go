package discovery

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"time"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p-core/crypto"
	"github.com/libp2p/go-libp2p-core/host"
	"github.com/libp2p/go-libp2p-core/peer"
	"github.com/libp2p/go-libp2p-core/peerstore"
	"github.com/libp2p/go-libp2p-discovery"
	"github.com/libp2p/go-libp2p-kad-dht"
	"github.com/multiformats/go-multiaddr"
)

// GeoLocation represents the geographical location of a node
type GeoLocation struct {
	Latitude  float64
	Longitude float64
}

// GeoLocationNode represents a node with geolocation data
type GeoLocationNode struct {
	peer.AddrInfo
	GeoLocation
}

// KademliaDHTService handles the Kademlia DHT peer discovery process
type KademliaDHTService struct {
	Host           host.Host
	DHT            *dht.IpfsDHT
	Discovery      discovery.Discovery
	BootstrapNodes []peer.AddrInfo
	PeerChan       chan GeoLocationNode
	ctx            context.Context
	cancel         context.CancelFunc
}

// NewKademliaDHTService creates a new Kademlia DHT service
func NewKademliaDHTService() (*KademliaDHTService, error) {
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

	// Initialize Kademlia DHT Service
	kds := &KademliaDHTService{
		Host:           h,
		DHT:            kademliaDHT,
		BootstrapNodes: BootstrapNodeList,
		PeerChan:       make(chan GeoLocationNode),
		ctx:            ctx,
		cancel:         cancel,
	}

	// Initialize bootstrap nodes
	kds.initBootstrapNodes()

	return kds, nil
}

// initBootstrapNodes initializes the bootstrap nodes in the DHT
func (kds *KademliaDHTService) initBootstrapNodes() {
	for _, node := range kds.BootstrapNodes {
		kds.Host.Peerstore().AddAddr(node.ID, node.Addrs[0], peerstore.PermanentAddrTTL)
	}
}

// DiscoverPeers discovers peers in the network with geolocation prioritization
func (kds *KademliaDHTService) DiscoverPeers() ([]GeoLocationNode, error) {
	ctx, cancel := context.WithTimeout(kds.ctx, time.Second*30)
	defer cancel()

	routingDiscovery := discovery.NewRoutingDiscovery(kds.DHT)
	peers, err := routingDiscovery.FindPeers(ctx, "synthron-network")
	if err != nil {
		return nil, err
	}

	var discoveredPeers []GeoLocationNode
	for peer := range peers {
		if peer.ID == kds.Host.ID() {
			continue
		}
		location, err := kds.getGeolocation(peer.Addrs)
		if err != nil {
			continue
		}
		discoveredPeers = append(discoveredPeers, GeoLocationNode{peer, location})
	}

	return discoveredPeers, nil
}

// AdvertisePresence advertises the presence of this node to the network
func (kds *KademliaDHTService) AdvertisePresence() error {
	ctx, cancel := context.WithTimeout(kds.ctx, time.Second*30)
	defer cancel()

	routingDiscovery := discovery.NewRoutingDiscovery(kds.DHT)
	discovery.Advertise(ctx, routingDiscovery, "synthron-network")

	return nil
}

// HandleIncomingConnections handles incoming connections from other peers
func (kds *KademliaDHTService) HandleIncomingConnections() {
	kds.Host.SetStreamHandler("/synthron/1.0.0", func(s network.Stream) {
		defer s.Close()
		// Implement specific logic for incoming streams
	})
}

// getGeolocation fetches the geolocation data for a given multiaddress
func (kds *KademliaDHTService) getGeolocation(addrs []multiaddr.Multiaddr) (GeoLocation, error) {
	// Placeholder implementation for geolocation fetching
	for _, addr := range addrs {
		ip, err := addr.ValueForProtocol(multiaddr.P_IP4)
		if err != nil {
			ip, err = addr.ValueForProtocol(multiaddr.P_IP6)
			if err != nil {
				continue
			}
		}
		// Simulate a geolocation lookup
		// Replace with actual implementation
		return GeoLocation{
			Latitude:  37.7749,
			Longitude: -122.4194,
		}, nil
	}
	return GeoLocation{}, errors.New("geolocation not found")
}

// GeneratePeerID generates a new peer ID
func GeneratePeerID() (peer.ID, error) {
	idBytes := make([]byte, 16)
	if _, err := rand.Read(idBytes); err != nil {
		return "", err
	}
	return peer.ID(hex.EncodeToString(idBytes)), nil
}

// CLI Commands
// To start the peer discovery service and advertise presence, use:
// synthron discover start
// To discover peers in the network, use:
// synthron discover peers

// API Endpoints
// POST /api/v1/discover/start: Start the peer discovery service
// GET /api/v1/discover/peers: Discover peers in the network

// BootstrapNodeList holds a list of bootstrap nodes
var BootstrapNodeList = []peer.AddrInfo{
	// Add bootstrap nodes here
	// Example:
	// {ID: "12D3KooWQ...", Addrs: []multiaddr.Multiaddr{multiaddr.StringCast("/ip4/127.0.0.1/tcp/4001")}},
}

func main() {
	kds, err := NewKademliaDHTService()
	if err != nil {
		panic(err)
	}

	go kds.AdvertisePresence()

	kds.HandleIncomingConnections()

	for {
		peers, err := kds.DiscoverPeers()
		if err != nil {
			panic(err)
		}

		for _, peer := range peers {
			locationData := fmt.Sprintf("Latitude: %f, Longitude: %f", peer.GeoLocation.Latitude, peer.GeoLocation.Longitude)
			fmt.Println("Discovered peer:", peer.ID.String(), "Location:", locationData)
		}

		time.Sleep(time.Minute)
	}
}
