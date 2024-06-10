package discovery

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/ip2location/ip2location-go/v9"
	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p-core/crypto"
	"github.com/libp2p/go-libp2p-core/host"
	"github.com/libp2p/go-libp2p-core/peer"
	"github.com/libp2p/go-libp2p-core/peerstore"
	"github.com/libp2p/go-libp2p-discovery"
	"github.com/libp2p/go-libp2p-kad-dht"
	"github.com/multiformats/go-multiaddr"
)

const (
	GeolocationAPI = "http://api.ipstack.com/"
	APIKey         = "your_api_key"
)

// GeoLocation represents the geographical location of a node
type GeoLocation struct {
	Latitude  float64 `json:"latitude"`
	Longitude float64 `json:"longitude"`
}

// GeoLocationNode represents a node with geolocation data
type GeoLocationNode struct {
	peer.AddrInfo
	GeoLocation
}

// PeerDiscoveryService handles the peer discovery process
type PeerDiscoveryService struct {
	Host           host.Host
	DHT            *dht.IpfsDHT
	Discovery      discovery.Discovery
	BootstrapNodes []BootstrapNode
	PeerChan       chan GeoLocationNode
	ctx            context.Context
	cancel         context.CancelFunc
	mutex          sync.Mutex
	ip2LocationDB  *ip2location.DB
}

// BootstrapNode represents a bootstrap node in the network
type BootstrapNode struct {
	ID       peer.ID
	Addr     multiaddr.Multiaddr
	PeerInfo peer.AddrInfo
}

// NewPeerDiscoveryService creates a new peer discovery service
func NewPeerDiscoveryService() (*PeerDiscoveryService, error) {
	ctx, cancel := context.WithCancel(context.Background())

	// Generate a new identity for the host
	priv, pub, err := crypto.GenerateEd25519Key(rand.Reader)
	if err != nil {
		return nil, err
	}

	id, err := peer.IDFromPublicKey(pub)
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

	// Load IP2Location database
	db, err := ip2location.OpenDB("IP2LOCATION-LITE-DB1.BIN")
	if err != nil {
		return nil, err
	}

	// Initialize Peer Discovery Service
	pds := &PeerDiscoveryService{
		Host:           h,
		DHT:            kademliaDHT,
		BootstrapNodes: BootstrapNodeList,
		PeerChan:       make(chan GeoLocationNode),
		ctx:            ctx,
		cancel:         cancel,
		ip2LocationDB:  db,
	}

	// Initialize bootstrap nodes
	pds.initBootstrapNodes()

	return pds, nil
}

// initBootstrapNodes initializes the bootstrap nodes in the DHT
func (pds *PeerDiscoveryService) initBootstrapNodes() {
	for _, node := range pds.BootstrapNodes {
		pds.Host.Peerstore().AddAddr(node.ID, node.Addr, peerstore.PermanentAddrTTL)
	}
}

// DiscoverPeers discovers peers in the network with geolocation prioritization
func (pds *PeerDiscoveryService) DiscoverPeers() ([]GeoLocationNode, error) {
	ctx, cancel := context.WithTimeout(pds.ctx, time.Second*30)
	defer cancel()

	routingDiscovery := discovery.NewRoutingDiscovery(pds.DHT)
	peers, err := routingDiscovery.FindPeers(ctx, "synthron-network")
	if err != nil {
		return nil, err
	}

	var discoveredPeers []GeoLocationNode
	for peer := range peers {
		if peer.ID == pds.Host.ID() {
			continue
		}
		location, err := pds.getGeolocation(peer.Addrs)
		if err != nil {
			continue
		}
		discoveredPeers = append(discoveredPeers, GeoLocationNode{peer, location})
	}

	return discoveredPeers, nil
}

// AdvertisePresence advertises the presence of this node to the network
func (pds *PeerDiscoveryService) AdvertisePresence() error {
	ctx, cancel := context.WithTimeout(pds.ctx, time.Second*30)
	defer cancel()

	routingDiscovery := discovery.NewRoutingDiscovery(pds.DHT)
	discovery.Advertise(ctx, routingDiscovery, "synthron-network")

	return nil
}

// HandleIncomingConnections handles incoming connections from other peers
func (pds *PeerDiscoveryService) HandleIncomingConnections() {
	pds.Host.SetStreamHandler("/synthron/1.0.0", func(s network.Stream) {
		// Handle the incoming stream
		defer s.Close()
		// Implement the specific logic for incoming streams here
	})
}

// getGeolocation fetches the geolocation data for a given multiaddress
func (pds *PeerDiscoveryService) getGeolocation(addrs []multiaddr.Multiaddr) (GeoLocation, error) {
	for _, addr := range addrs {
		ip, err := addr.ValueForProtocol(multiaddr.P_IP4)
		if err != nil {
			ip, err = addr.ValueForProtocol(multiaddr.P_IP6)
			if err != nil {
				continue
			}
		}
		record, err := pds.ip2LocationDB.Get_all(ip)
		if err != nil {
			continue
		}
		return GeoLocation{
			Latitude:  record.Latitude,
			Longitude: record.Longitude,
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
var BootstrapNodeList = []BootstrapNode{
	// Add bootstrap nodes here
	// Example:
	// {ID: "12D3KooWQ...", Addr: "/ip4/127.0.0.1/tcp/4001"},
}

func main() {
	pds, err := NewPeerDiscoveryService()
	if err != nil {
		panic(err)
	}

	go pds.AdvertisePresence()

	pds.HandleIncomingConnections()

	for {
		peers, err := pds.DiscoverPeers()
		if err != nil {
			panic(err)
		}

		for _, peer := range peers {
			locationData, _ := json.Marshal(peer.GeoLocation)
			println("Discovered peer:", peer.ID.String(), "Location:", string(locationData))
		}

		time.Sleep(time.Minute)
	}
}
