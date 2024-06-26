package network

import (
	"context"
	"crypto/rand"
	"log"
	"time"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p-core/crypto"
	"github.com/libp2p/go-libp2p-core/host"
	"github.com/libp2p/go-libp2p-core/peer"
	"github.com/libp2p/go-libp2p-core/pnet"
	"github.com/libp2p/go-libp2p-core/protocol"
	"github.com/libp2p/go-libp2p-discovery"
	"github.com/libp2p/go-libp2p-kad-dht"
	"github.com/multiformats/go-multiaddr"
)

// PeerCommunication manages peer interactions in the Synnergy Network.
type PeerCommunication struct {
	Host host.Host
	DHT  *dht.IpfsDHT
}

// NewPeerCommunication initializes a new LibP2P host with DHT for peer discovery.
func NewPeerCommunication(ctx context.Context, listenAddr string, psk pnet.PSK) (*PeerCommunication, error) {
	privKey, _, err := crypto.GenerateEd25519Key(rand.Reader)
	if err != nil {
		return nil, err
	}

	addr, err := multiaddr.NewMultiaddr(listenAddr)
	if err != nil {
		return nil, err
	}

	h, err := libp2p.New(ctx,
		libp2p.ListenAddrs(addr),
		libp2p.Identity(privKey),
		libp2p.PrivateNetwork(psk),
		libp2p.NATPortMap(),
	)
	if err != nil {
		return nil, err
	}

	dhtInstance, err := dht.New(ctx, h)
	if err != nil {
		return nil, err
	}

	return &PeerCommunication{
		Host: h,
		DHT:  dhtInstance,
	}, nil
}

// SetupDiscovery sets up the DHT for peer discovery and starts routing.
func (pc *PeerCommunication) SetupDiscovery(ctx context.Context) error {
	if err := pc.DHT.Bootstrap(ctx); err != nil {
		return err
	}

	routingDiscovery := discovery.NewRoutingDiscovery(pc.DHT)
	discovery.Advertise(ctx, routingDiscovery, "synnergy-network")
	log.Println("Peer discovery initiated.")

	return nil
}

// ConnectToPeer attempts to connect to a specified peer address.
func (pc *PeerCommunication) ConnectToPeer(ctx context.Context, peerAddr string) error {
	addr, err := multiaddr.NewMultiaddr(peerAddr)
	if err != nil {
		return err
	}

	peerInfo, err := peer.AddrInfoFromP2pAddr(addr)
	if err != nil {
		return err
	}

	if err := pc.Host.Connect(ctx, *peerInfo); err != nil {
		return err
	}

	log.Printf("Connected to peer %s successfully.", peerInfo.ID)
	return nil
}

// HandleMessages listens for incoming messages and processes them based on protocol.
func (pc *PeerCommunication) HandleMessages() {
	pc.Host.SetStreamHandler(protocol.ID("synnergy-protocol"), func(stream network.Stream) {
		// Example processing logic here
		defer stream.Close()
		log.Printf("Received new stream from %s", stream.Conn().RemotePeer().Pretty())

		// Example data handling
		data := make([]byte, 1024)
		_, err := stream.Read(data)
		if err != nil {
			log.Println("Failed to read data from stream:", err)
			return
		}
		log.Printf("Received data: %s", string(data))
	})
}

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	psk, err := pnet.DecodeV1PSK([]byte("example-psk"))
	if err != nil {
		log.Fatal("Failed to decode PSK:", err)
	}

	pc, err := NewPeerCommunication(ctx, "/ip4/0.0.0.0/tcp/4001", psk)
	if err != nil {
		log.Fatal("Failed to create peer communication:", err)
	}

	if err := pc.SetupDiscovery(ctx); err != nil {
		log.Fatal("Failed to setup discovery:", err)
	}

	pc.HandleMessages() // Start handling incoming messages

	// Block forever
	select {}
}
