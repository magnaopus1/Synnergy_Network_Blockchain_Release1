package mesh_networking

import (
	"context"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p-core/host"
	"github.com/libp2p/go-libp2p-core/peer"
	"github.com/libp2p/go-libp2p-core/protocol"
	"github.com/libp2p/go-libp2p-discovery"
	dht "github.com/libp2p/go-libp2p-kad-dht"
	"github.com/libp2p/go-libp2p-pubsub"
	"github.com/multiformats/go-multiaddr"
	"github.com/pion/webrtc/v3"
)

// PeerInfo represents the basic information of a peer
type PeerInfo struct {
	ID        string
	Addresses []string
}

// MobileMeshNetwork handles the mobile mesh network formation
type MobileMeshNetwork struct {
	host         host.Host
	dht          *dht.IpfsDHT
	discovery    *discovery.RoutingDiscovery
	peerInfo     map[peer.ID]*PeerInfo
	peerInfoMux  sync.RWMutex
	pubsub       *pubsub.PubSub
	signalServer string
}

// NewMobileMeshNetwork initializes the mobile mesh network
func NewMobileMeshNetwork(listenPort int, bootstrapPeers []multiaddr.Multiaddr, signalServer string) (*MobileMeshNetwork, error) {
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

	ps, err := pubsub.NewGossipSub(context.Background(), h)
	if err != nil {
		return nil, fmt.Errorf("failed to create pubsub: %v", err)
	}

	return &MobileMeshNetwork{
		host:         h,
		dht:          kademliaDHT,
		discovery:    routingDiscovery,
		peerInfo:     make(map[peer.ID]*PeerInfo),
		pubsub:       ps,
		signalServer: signalServer,
	}, nil
}

// StartPeerDiscovery starts the peer discovery process
func (mmn *MobileMeshNetwork) StartPeerDiscovery(serviceTag string) {
	discovery.Advertise(context.Background(), mmn.discovery, serviceTag)

	go func() {
		for {
			peers, err := discovery.FindPeers(context.Background(), mmn.discovery, serviceTag)
			if err != nil {
				log.Printf("failed to find peers: %v", err)
				continue
			}

			for p := range peers {
				if p.ID == mmn.host.ID() {
					continue
				}

				if err := mmn.host.Connect(context.Background(), p); err != nil {
					log.Printf("failed to connect to peer: %v", err)
				} else {
					mmn.peerInfoMux.Lock()
					mmn.peerInfo[p.ID] = &PeerInfo{
						ID:        p.ID.Pretty(),
						Addresses: peer.AddrInfoToP2pAddrs(p),
					}
					mmn.peerInfoMux.Unlock()
				}
			}
		}
	}()
}

// AdvertisePeer advertises the peer's presence and capabilities
func (mmn *MobileMeshNetwork) AdvertisePeer(serviceTag string, interval time.Duration) {
	go func() {
		for {
			_, err := mmn.discovery.Advertise(context.Background(), serviceTag)
			if err != nil {
				log.Printf("failed to advertise peer: %v", err)
			}
			time.Sleep(interval)
		}
	}()
}

// MonitorLinkQuality monitors the link quality between peers
func (mmn *MobileMeshNetwork) MonitorLinkQuality(peerID peer.ID, interval time.Duration) {
	go func() {
		for {
			mmn.peerInfoMux.RLock()
			peerInfo, exists := mmn.peerInfo[peerID]
			mmn.peerInfoMux.RUnlock()

			if !exists {
				time.Sleep(interval)
				continue
			}

			linkQuality := mmn.evaluateLinkQuality(peerInfo)
			log.Printf("Peer %s - Latency: %v, PacketLoss: %.2f, SignalStrength: %.2f", peerID.Pretty(), linkQuality.Latency, linkQuality.PacketLoss, linkQuality.SignalStrength)

			time.Sleep(interval)
		}
	}()
}

// evaluateLinkQuality evaluates the link quality metrics between peers
func (mmn *MobileMeshNetwork) evaluateLinkQuality(peerInfo *PeerInfo) LinkQuality {
	// Placeholder logic for evaluating link quality
	latency := 50 * time.Millisecond
	packetLoss := 0.0
	signalStrength := 100.0

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
func DynamicNetworkFormation(listenPort int, bootstrapPeers []multiaddr.Multiaddr, serviceTag string, advertiseInterval time.Duration, monitorInterval time.Duration, signalServer string) error {
	mmn, err := NewMobileMeshNetwork(listenPort, bootstrapPeers, signalServer)
	if err != nil {
		return err
	}

	mmn.StartPeerDiscovery(serviceTag)
	mmn.AdvertisePeer(serviceTag, advertiseInterval)

	for {
		mmn.peerInfoMux.RLock()
		for peerID := range mmn.peerInfo {
			go mmn.MonitorLinkQuality(peerID, monitorInterval)
		}
		mmn.peerInfoMux.RUnlock()
		time.Sleep(monitorInterval)
	}
}

// Additional functionalities for mesh networking

// BroadcastMessage sends a message to all connected peers
func (mmn *MobileMeshNetwork) BroadcastMessage(topic string, message []byte) {
	t, err := mmn.pubsub.Join(topic)
	if err != nil {
		log.Printf("failed to join topic %s: %v", topic, err)
		return
	}
	defer t.Close()

	err = t.Publish(context.Background(), message)
	if err != nil {
		log.Printf("failed to publish message to topic %s: %v", topic, err)
	}
}

// HandleIncomingMessages sets up a handler for incoming messages
func (mmn *MobileMeshNetwork) HandleIncomingMessages(topic string, handler func(peer.ID, []byte)) {
	t, err := mmn.pubsub.Join(topic)
	if err != nil {
		log.Printf("failed to join topic %s: %v", topic, err)
		return
	}
	sub, err := t.Subscribe()
	if err != nil {
		log.Printf("failed to subscribe to topic %s: %v", topic, err)
		return
	}

	go func() {
		for {
			msg, err := sub.Next(context.Background())
			if err != nil {
				log.Printf("failed to get next message in topic %s: %v", topic, err)
				continue
			}
			handler(msg.ReceivedFrom, msg.Data)
		}
	}()
}

// SetupWebRTC sets up WebRTC peer connection
func (mmn *MobileMeshNetwork) SetupWebRTC() (*webrtc.PeerConnection, error) {
	config := webrtc.Configuration{
		ICEServers: []webrtc.ICEServer{
			{
				URLs: []string{"stun:stun.l.google.com:19302"},
			},
		},
	}

	peerConnection, err := webrtc.NewPeerConnection(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create peer connection: %v", err)
	}

	dataChannel, err := peerConnection.CreateDataChannel("data", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create data channel: %v", err)
	}

	dataChannel.OnOpen(func() {
		log.Println("Data channel open")
	})

	dataChannel.OnMessage(func(msg webrtc.DataChannelMessage) {
		log.Printf("Message from DataChannel: %s", string(msg.Data))
	})

	return peerConnection, nil
}

// SignalWebRTC handles WebRTC signaling
func (mmn *MobileMeshNetwork) SignalWebRTC(peerConnection *webrtc.PeerConnection, signalServer string) error {
	// Placeholder logic for signaling
	return nil
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
	signalServer := "http://signal.example.com"

	if err := DynamicNetworkFormation(listenPort, bootstrapPeers, serviceTag, advertiseInterval, monitorInterval, signalServer); err != nil {
		log.Fatalf("failed to start dynamic network formation: %v", err)
	}
}
