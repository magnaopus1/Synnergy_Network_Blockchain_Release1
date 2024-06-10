package mesh_networking

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/go-resty/resty/v2"
	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p-core/host"
	"github.com/libp2p/go-libp2p-core/peer"
	"github.com/libp2p/go-libp2p-core/protocol"
	"github.com/libp2p/go-libp2p-discovery"
	dht "github.com/libp2p/go-libp2p-kad-dht"
	"github.com/multiformats/go-multiaddr"
)

// PeerInfo represents the basic information of a peer
type PeerInfo struct {
	ID        string
	Addresses []string
}

// NetworkFormation handles the dynamic formation of the network
type NetworkFormation struct {
	host        host.Host
	dht         *dht.IpfsDHT
	discovery   *discovery.RoutingDiscovery
	peerInfo    map[peer.ID]*PeerInfo
	peerInfoMux sync.RWMutex
	client      *resty.Client
}

// NewNetworkFormation initializes the network formation process
func NewNetworkFormation(listenPort int, bootstrapPeers []multiaddr.Multiaddr) (*NetworkFormation, error) {
	h, err := libp2p.New(libp2p.ListenAddrStrings(fmt.Sprintf("/ip4/0.0.0.0/tcp/%d", listenPort)))
	if err != nil {
		return nil, fmt.Errorf("failed to create host: %v", err)
	}

	kademliaDHT, err := dht.New(context.Background(), h)
	if err != nil {
		return nil, fmt.Errorf("failed to create DHT: %v", err)
	}

	if err = kademliaDHT.Bootstrap(context.Background()); err != nil {
		return nil, fmt.Errorf("failed to bootstrap DHT: %v", err)
	}

	routingDiscovery := discovery.NewRoutingDiscovery(kademliaDHT)

	for _, addr := range bootstrapPeers {
		peerinfo, _ := peer.AddrInfoFromP2pAddr(addr)
		if err := h.Connect(context.Background(), *peerinfo); err != nil {
			log.Printf("failed to connect to bootstrap peer: %v", err)
		}
	}

	return &NetworkFormation{
		host:      h,
		dht:       kademliaDHT,
		discovery: routingDiscovery,
		peerInfo:  make(map[peer.ID]*PeerInfo),
		client:    resty.New(),
	}, nil
}

// StartPeerDiscovery starts the peer discovery process
func (nf *NetworkFormation) StartPeerDiscovery(serviceTag string) {
	discovery.Advertise(context.Background(), nf.discovery, serviceTag)

	go func() {
		for {
			peers, err := discovery.FindPeers(context.Background(), nf.discovery, serviceTag)
			if err != nil {
				log.Printf("failed to find peers: %v", err)
				continue
			}

			for p := range peers {
				if p.ID == nf.host.ID() {
					continue
				}

				if err := nf.host.Connect(context.Background(), p); err != nil {
					log.Printf("failed to connect to peer: %v", err)
				} else {
					nf.peerInfoMux.Lock()
					nf.peerInfo[p.ID] = &PeerInfo{
						ID:        p.ID.Pretty(),
						Addresses: peer.AddrInfoToP2pAddrs(p),
					}
					nf.peerInfoMux.Unlock()
				}
			}
		}
	}()
}

// AdvertisePeer advertises the peer's presence and capabilities
func (nf *NetworkFormation) AdvertisePeer(serviceTag string, interval time.Duration) {
	go func() {
		for {
			_, err := nf.discovery.Advertise(context.Background(), serviceTag)
			if err != nil {
				log.Printf("failed to advertise peer: %v", err)
			}
			time.Sleep(interval)
		}
	}()
}

// MonitorLinkQuality monitors the link quality between peers
func (nf *NetworkFormation) MonitorLinkQuality(peerID peer.ID, interval time.Duration) {
	go func() {
		for {
			nf.peerInfoMux.RLock()
			peerInfo, exists := nf.peerInfo[peerID]
			nf.peerInfoMux.RUnlock()

			if !exists {
				time.Sleep(interval)
				continue
			}

			linkQuality := nf.evaluateLinkQuality(peerInfo)
			log.Printf("Peer %s - Latency: %v, PacketLoss: %.2f, SignalStrength: %.2f", peerID.Pretty(), linkQuality.Latency, linkQuality.PacketLoss, linkQuality.SignalStrength)

			time.Sleep(interval)
		}
	}()
}

// evaluateLinkQuality evaluates the link quality metrics between peers
func (nf *NetworkFormation) evaluateLinkQuality(peerInfo *PeerInfo) LinkQuality {
	start := time.Now()
	_, err := nf.client.R().Get(fmt.Sprintf("http://%s", peerInfo.Addresses[0]))
	latency := time.Since(start)

	packetLoss := 0.0
	if err != nil {
		packetLoss = 1.0
	}

	signalStrength := 100.0 // Placeholder value for signal strength

	return LinkQuality{
		Latency:        latency,
		PacketLoss:     packetLoss,
		SignalStrength: signalStrength,
	}
}

// LinkQuality represents the quality metrics of a communication link
type LinkQuality struct {
	Latency        time.Duration
	PacketLoss     float64
	SignalStrength float64
}

// DynamicNetworkFormation dynamically forms and manages the network
func DynamicNetworkFormation(listenPort int, bootstrapPeers []multiaddr.Multiaddr, serviceTag string, advertiseInterval time.Duration, monitorInterval time.Duration) error {
	nf, err := NewNetworkFormation(listenPort, bootstrapPeers)
	if err != nil {
		return err
	}

	nf.StartPeerDiscovery(serviceTag)
	nf.AdvertisePeer(serviceTag, advertiseInterval)

	for {
		nf.peerInfoMux.RLock()
		for peerID := range nf.peerInfo {
			go nf.MonitorLinkQuality(peerID, monitorInterval)
		}
		nf.peerInfoMux.RUnlock()
		time.Sleep(monitorInterval)
	}
}

// Additional functionalities for mesh networking

// BroadcastMessage sends a message to all connected peers
func (nf *NetworkFormation) BroadcastMessage(protocolID protocol.ID, message []byte) {
	nf.peerInfoMux.RLock()
	defer nf.peerInfoMux.RUnlock()

	for peerID := range nf.peerInfo {
		stream, err := nf.host.NewStream(context.Background(), peerID, protocolID)
		if err != nil {
			log.Printf("failed to open stream to peer %s: %v", peerID.Pretty(), err)
			continue
		}
		_, err = stream.Write(message)
		if err != nil {
			log.Printf("failed to write message to peer %s: %v", peerID.Pretty(), err)
		}
		stream.Close()
	}
}

// HandleIncomingMessages sets up a handler for incoming messages
func (nf *NetworkFormation) HandleIncomingMessages(protocolID protocol.ID, handler func(peer.ID, []byte)) {
	nf.host.SetStreamHandler(protocolID, func(stream network.Stream) {
		defer stream.Close()
		peerID := stream.Conn().RemotePeer()
		buf := make([]byte, 4096)
		n, err := stream.Read(buf)
		if err != nil {
			log.Printf("failed to read message from peer %s: %v", peerID.Pretty(), err)
			return
		}
		handler(peerID, buf[:n])
	})
}

func main() {
	// Configuration
	listenPort := 4001
	bootstrapPeers := []multiaddr.Multiaddr{
		multiaddr.StringCast("/ip4/127.0.0.1/tcp/4001/ipfs/QmT5NvUtoM5nX1Ecupp3eX4tb8PfHfgbKwZQ46iN96Mt1y"),
	}
	serviceTag := "synthron-service"
	advertiseInterval := 30 * time.Second
	monitorInterval := 10 * time.Second

	if err := DynamicNetworkFormation(listenPort, bootstrapPeers, serviceTag, advertiseInterval, monitorInterval); err != nil {
		log.Fatalf("failed to start dynamic network formation: %v", err)
	}
}
