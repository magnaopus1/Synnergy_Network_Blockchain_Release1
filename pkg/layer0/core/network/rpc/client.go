package rpc

import (
	"net/rpc"
	"crypto/tls"
	"log"
	"time"

	"github.com/synthron_blockchain_final/pkg/layer0/core/crypto"
)

// Client represents an RPC client in the Synnergy Network.
type Client struct {
	client *rpc.Client
	config *tls.Config
}

// NewClient creates a new RPC client with secure configuration.
func NewClient(serverAddress string) (*Client, error) {
	// Load TLS configuration with client certificates for secure communication.
	config, err := crypto.LoadTLSConfig()
	if err != nil {
		return nil, err
	}

	conn, err := tls.Dial("tcp", serverAddress, config)
	if err != nil {
		return nil, err
	}

	return &Client{
		client: rpc.NewClient(conn),
		config: config,
	}, nil
}

// Call performs a remote procedure call on a Synnergy node.
func (c *Client) Call(method string, args interface{}, reply interface{}) error {
	if c.client == nil {
		return errNoConnection
	}

	// Implementing asynchronous RPC with timeout
	doneChan := make(chan error, 1)
	go func() {
		err := c.client.Call(method, args, reply)
		doneChan <- err
	}()

	select {
	case err := <-doneChan:
		return err
	case <-time.After(30 * time.Second): // Timeout for the RPC call
		return errTimeout
	}
}

// Close terminates the RPC client connection.
func (c *Client) Close() error {
	if c.client != nil {
		return c.client.Close()
	}
	return nil
}

const (
	errNoConnection = Error("RPC client is not connected")
	errTimeout      = Error("RPC call timed out")
)

// Error defines a type for representing errors with string messages in RPC operations.
type Error string

func (e Error) Error() string {
	return string(e)
}
