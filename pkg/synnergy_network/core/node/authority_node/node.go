package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/btcsuite/btcd/btcec"
	"github.com/synthron/synthron_blockchain_final/pkg/layer0/node/common"
	"github.com/synthron/synthron_blockchain_final/pkg/layer0/node/consensus"
	"github.com/synthron/synthron_blockchain_final/pkg/layer0/node/p2p"
	"github.com/synthron/synthron_blockchain_final/pkg/layer0/node/types"
)

type AuthorityNode struct {
	privateKey     *btcec.PrivateKey
	address        common.Address
	peers          map[common.Address]*p2p.Peer
	blockchain     *types.Blockchain
	consensus      *consensus.Consensus
	server         *rpc.Server
	mutex          sync.Mutex
	networkID      string
	networkAddress string
}

func NewAuthorityNode(networkID string, networkAddress string) (*AuthorityNode, error) {
	privateKey, err := btcec.NewPrivateKey(btcec.S256())
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %v", err)
	}

	address := common.BytesToAddress(privateKey.PubKey().SerializeCompressed())
	node := &AuthorityNode{
		privateKey:     privateKey,
		address:        address,
		peers:          make(map[common.Address]*p2p.Peer),
		blockchain:     types.NewBlockchain(),
		consensus:      consensus.NewConsensus(),
		networkID:      networkID,
		networkAddress: networkAddress,
	}

	return node, nil
}

func (node *AuthorityNode) Start() error {
	listener, err := net.Listen("tcp", node.networkAddress)
	if err != nil {
		return fmt.Errorf("failed to start listener: %v", err)
	}
	defer listener.Close()

	log.Printf("Authority Node started. Listening on %s\n", node.networkAddress)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go node.handleSignals(cancel)

	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				log.Println("Shutting down Authority Node")
				return nil
			}
			log.Printf("failed to accept connection: %v\n", err)
			continue
		}

		go node.handleConnection(conn)
	}
}

func (node *AuthorityNode) handleSignals(cancel context.CancelFunc) {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
	cancel()
}

func (node *AuthorityNode) handleConnection(conn net.Conn) {
	defer conn.Close()
	// Implement P2P connection handling logic here
}

func (node *AuthorityNode) validateTransaction(tx *types.Transaction) error {
	// Implement transaction validation logic here
	return nil
}

func (node *AuthorityNode) createBlock() (*types.Block, error) {
	// Implement block creation logic here
	return &types.Block{}, nil
}

func (node *AuthorityNode) signData(data []byte) (string, error) {
	hash := sha256.Sum256(data)
	sig, err := btcec.SignCompact(btcec.S256(), node.privateKey, hash[:], true)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(sig), nil
}

func (node *AuthorityNode) verifySignature(data []byte, sig string, pubKey *btcec.PublicKey) (bool, error) {
	signature, err := hex.DecodeString(sig)
	if err != nil {
		return false, err
	}
	hash := sha256.Sum256(data)
	_, err = btcec.RecoverCompact(btcec.S256(), signature, hash[:])
	if err != nil {
		return false, err
	}
	return pubKey.Verify(hash[:], signature), nil
}

func main() {
	node, err := NewAuthorityNode("synthron-network", "localhost:8080")
	if err != nil {
		log.Fatalf("Failed to create Authority Node: %v", err)
	}

	err = node.Start()
	if err != nil {
		log.Fatalf("Failed to start Authority Node: %v", err)
	}
}
