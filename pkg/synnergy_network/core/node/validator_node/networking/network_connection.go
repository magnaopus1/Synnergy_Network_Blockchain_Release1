package networking

import (
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/synnergy_network_blockchain/pkg/synnergy_network/common"
)

type NetworkConnection struct {
	NodeID               string
	Host                 string
	Port                 int
	MaxPeers             int
	DataReplicationType  string
	ConnectionPool       map[string]net.Conn
	mu                   sync.Mutex
	tlsConfig            *tls.Config
}

func (nc *NetworkConnection) Initialize(nodeID, host string, port, maxPeers int, dataReplicationType, tlsCertFile, tlsKeyFile string) {
	nc.NodeID = nodeID
	nc.Host = host
	nc.Port = port
	nc.MaxPeers = maxPeers
	nc.DataReplicationType = dataReplicationType
	nc.ConnectionPool = make(map[string]net.Conn)

	cert, err := tls.LoadX509KeyPair(tlsCertFile, tlsKeyFile)
	if err != nil {
		log.Fatalf("failed to load TLS certificates: %v", err)
	}

	nc.tlsConfig = &tls.Config{Certificates: []tls.Certificate{cert}}

	go nc.listenForConnections()
	go nc.connectToPeers()
}

func (nc *NetworkConnection) listenForConnections() {
	listener, err := tls.Listen("tcp", fmt.Sprintf("%s:%d", nc.Host, nc.Port), nc.tlsConfig)
	if err != nil {
		log.Fatalf("failed to start listener: %v", err)
	}
	defer listener.Close()

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("failed to accept connection: %v", err)
			continue
		}

		nc.mu.Lock()
		if len(nc.ConnectionPool) < nc.MaxPeers {
			nc.ConnectionPool[conn.RemoteAddr().String()] = conn
			go nc.handleConnection(conn)
		} else {
			conn.Close()
		}
		nc.mu.Unlock()
	}
}

func (nc *NetworkConnection) connectToPeers() {
	for {
		peers := common.GetPeerList()
		for _, peer := range peers {
			if len(nc.ConnectionPool) >= nc.MaxPeers {
				break
			}

			if _, exists := nc.ConnectionPool[peer]; exists {
				continue
			}

			conn, err := tls.Dial("tcp", peer, nc.tlsConfig)
			if err != nil {
				log.Printf("failed to connect to peer %s: %v", peer, err)
				continue
			}

			nc.mu.Lock()
			nc.ConnectionPool[peer] = conn
			nc.mu.Unlock()
			go nc.handleConnection(conn)
		}

		time.Sleep(10 * time.Second)
	}
}

func (nc *NetworkConnection) handleConnection(conn net.Conn) {
	defer func() {
		nc.mu.Lock()
		delete(nc.ConnectionPool, conn.RemoteAddr().String())
		nc.mu.Unlock()
		conn.Close()
	}()

	buffer := make([]byte, 4096)
	for {
		n, err := conn.Read(buffer)
		if err != nil {
			log.Printf("error reading from connection: %v", err)
			break
		}

		message := buffer[:n]
		go nc.processMessage(message)
	}
}

func (nc *NetworkConnection) processMessage(message []byte) {
	// Process the message based on its type
	// This could involve transaction validation, block propagation, etc.
	// For now, we will just log the message as a placeholder
	log.Printf("received message: %s", string(message))

	// Example of handling a specific message type:
	// if messageType == "block" {
	//     block := common.ParseBlock(message)
	//     common.ValidateBlock(block)
	//     common.BroadcastBlock(block)
	// }
}

func (nc *NetworkConnection) ReplicateData() {
	for {
		switch nc.DataReplicationType {
		case "light":
			// Implement light data replication logic
			log.Println("Performing light data replication")
		case "partial":
			// Implement partial data replication logic
			log.Println("Performing partial data replication")
		case "full":
			// Implement full data replication logic
			log.Println("Performing full data replication")
		case "comprehensive":
			// Implement comprehensive data replication logic
			log.Println("Performing comprehensive data replication")
		default:
			log.Printf("unknown data replication type: %s", nc.DataReplicationType)
		}

		time.Sleep(10 * time.Minute) // Adjust the replication frequency as needed
	}
}

func (nc *NetworkConnection) CloseConnections() {
	nc.mu.Lock()
	defer nc.mu.Unlock()

	for _, conn := range nc.ConnectionPool {
		conn.Close()
	}
	nc.ConnectionPool = make(map[string]net.Conn)
}

func main() {
	networkConnection := &NetworkConnection{}
	networkConnection.Initialize("unique-node-id", "0.0.0.0", 30303, 50, "full", "/path/to/tls_cert.pem", "/path/to/tls_key.pem")
	networkConnection.ReplicateData()
}
