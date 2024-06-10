package crosschain

import (
	"crypto/tls"
	"encoding/json"
	"net"
	"sync"
	"time"
)

// ChainRelay represents a node that facilitates the forwarding and verification of data between blockchains.
type ChainRelay struct {
	// Connections maps blockchain identifiers to their respective network connections.
	Connections map[string]net.Conn
	mutex       sync.Mutex
}

// NewChainRelay initializes a new Chain Relay with secure default settings.
func NewChainRelay() *ChainRelay {
	return &ChainRelay{
		Connections: make(map[string]net.Conn),
	}
}

// ConnectToBlockchain establishes a secure connection to another blockchain's node.
func (cr *ChainRelay) ConnectToBlockchain(chainID string, address string) error {
	cr.mutex.Lock()
	defer cr.mutex.Unlock()

	conn, err := tls.Dial("tcp", address, &tls.Config{
		InsecureSkipVerify: true, // Note: For development only; production should have a proper CA setup.
	})
	if err != nil {
		return err
	}
	cr.Connections[chainID] = conn
	return nil
}

// RelayData forwards data to the specified blockchain.
func (cr *ChainRelay) RelayData(chainID string, data interface{}) error {
	cr.mutex.Lock()
	defer cr.mutex.Unlock()

	conn, ok := cr.Connections[chainID]
	if !ok {
		return errors.New("no connection found for blockchain")
	}

	dataBytes, err := json.Marshal(data)
	if err != nil {
		return err
	}

	_, err = conn.Write(dataBytes)
	return err
}

// ReceiveData listens for incoming data from connected blockchains.
func (cr *ChainRelay) ReceiveData(chainID string, handler func(data []byte)) error {
	cr.mutex.Lock()
	conn, ok := cr.Connections[chainID]
	cr.mutex.Unlock()

	if !ok {
		return errors.New("no connection found for blockchain")
	}

	buffer := make([]byte, 4096)
	for {
		n, err := conn.Read(buffer)
		if err != nil {
			if err != net.ErrClosed {
				continue // Ignore closed network errors and continue listening.
			}
			return err
		}
		go handler(buffer[:n])
	}
}

// Example usage of the ChainRelay
func main() {
	relay := NewChainRelay()
	err := relay.ConnectToBlockchain("chainA", "192.168.1.1:8080")
	if err != nil {
		panic(err)
	}

	err = relay.RelayData("chainA", map[string]string{"message": "Hello, Blockchain A!"})
	if err != nil {
		panic(err)
	}

	// Setup to receive data and print it
	err = relay.ReceiveData("chainA", func(data []byte) {
		println(string(data))
	})
	if err != nil {
		panic(err)
	}
}
