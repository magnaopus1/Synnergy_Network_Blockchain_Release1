package validator_node

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/synthron_blockchain_final/pkg/layer0/utilities/logging"
	"github.com/synthron_blockchain_final/pkg/layer0/utilities/metrics"
	"github.com/synthron_blockchain_final/pkg/layer0/utilities/configuration"
	"math/big"
	"net"
	"sync"
	"time"

	"github.com/synthron_blockchain_final/pkg/layer0/consensus"
	"github.com/synthron_blockchain_final/pkg/layer0/crypto"
	"github.com/synthron_blockchain_final/pkg/layer0/network"
	"github.com/synthron_blockchain_final/pkg/layer0/state"
	"github.com/synthron_blockchain_final/pkg/layer0/transaction"
)

type ValidatorNode struct {
	privateKey      *ecdsa.PrivateKey
	publicKey       *ecdsa.PublicKey
	address         string
	stake           *big.Int
	consensus       consensus.Consensus
	state           *state.State
	network         *network.Network
	logger          logging.Logger
	metrics         metrics.Metrics
	config          configuration.Config
	mu              sync.Mutex
	connectedPeers  map[string]net.Conn
	quit            chan struct{}
}

func NewValidatorNode(configFilePath string) (*ValidatorNode, error) {
	config, err := configuration.LoadConfig(configFilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to load config: %v", err)
	}

	privateKey, err := crypto.GeneratePrivateKey()
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %v", err)
	}

	publicKey := &privateKey.PublicKey
	address := crypto.PublicKeyToAddress(publicKey)

	state, err := state.NewState(config.StateConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize state: %v", err)
	}

	network, err := network.NewNetwork(config.NetworkConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize network: %v", err)
	}

	logger := logging.NewLogger(config.LoggingConfig)
	metrics := metrics.NewMetrics(config.MetricsConfig)

	node := &ValidatorNode{
		privateKey:      privateKey,
		publicKey:       publicKey,
		address:         address,
		stake:           big.NewInt(0),
		consensus:       consensus.NewConsensus(config.ConsensusConfig),
		state:           state,
		network:         network,
		logger:          logger,
		metrics:         metrics,
		config:          config,
		connectedPeers:  make(map[string]net.Conn),
		quit:            make(chan struct{}),
	}

	return node, nil
}

func (vn *ValidatorNode) Start() {
	vn.logger.Info("Starting validator node...")
	go vn.connectToPeers()
	go vn.startConsensus()
	go vn.monitorNodeHealth()
	vn.logger.Info("Validator node started.")
}

func (vn *ValidatorNode) Stop() {
	vn.logger.Info("Stopping validator node...")
	close(vn.quit)
	for _, conn := range vn.connectedPeers {
		conn.Close()
	}
	vn.logger.Info("Validator node stopped.")
}

func (vn *ValidatorNode) connectToPeers() {
	peers := vn.config.NetworkConfig.Peers
	for _, peer := range peers {
		conn, err := vn.network.Connect(peer)
		if err != nil {
			vn.logger.Warn(fmt.Sprintf("Failed to connect to peer %s: %v", peer, err))
			continue
		}
		vn.mu.Lock()
		vn.connectedPeers[peer] = conn
		vn.mu.Unlock()
		go vn.handlePeerConnection(conn)
	}
}

func (vn *ValidatorNode) handlePeerConnection(conn net.Conn) {
	defer conn.Close()
	for {
		select {
		case <-vn.quit:
			return
		default:
			msg, err := vn.network.ReceiveMessage(conn)
			if err != nil {
				vn.logger.Warn(fmt.Sprintf("Failed to receive message: %v", err))
				return
			}
			vn.processMessage(msg)
		}
	}
}

func (vn *ValidatorNode) processMessage(msg network.Message) {
	switch msg.Type {
	case network.TransactionMessage:
		vn.handleTransactionMessage(msg)
	case network.BlockMessage:
		vn.handleBlockMessage(msg)
	case network.ConsensusMessage:
		vn.handleConsensusMessage(msg)
	default:
		vn.logger.Warn(fmt.Sprintf("Unknown message type: %s", msg.Type))
	}
}

func (vn *ValidatorNode) handleTransactionMessage(msg network.Message) {
	tx, err := transaction.DeserializeTransaction(msg.Payload)
	if err != nil {
		vn.logger.Warn(fmt.Sprintf("Failed to deserialize transaction: %v", err))
		return
	}
	if err := vn.consensus.ValidateTransaction(tx); err != nil {
		vn.logger.Warn(fmt.Sprintf("Invalid transaction: %v", err))
		return
	}
	vn.state.ApplyTransaction(tx)
	vn.logger.Info(fmt.Sprintf("Transaction applied: %s", tx.ID))
}

func (vn *ValidatorNode) handleBlockMessage(msg network.Message) {
	block, err := state.DeserializeBlock(msg.Payload)
	if err != nil {
		vn.logger.Warn(fmt.Sprintf("Failed to deserialize block: %v", err))
		return
	}
	if err := vn.consensus.ValidateBlock(block); err != nil {
		vn.logger.Warn(fmt.Sprintf("Invalid block: %v", err))
		return
	}
	vn.state.ApplyBlock(block)
	vn.logger.Info(fmt.Sprintf("Block applied: %s", block.ID))
}

func (vn *ValidatorNode) handleConsensusMessage(msg network.Message) {
	vn.consensus.HandleMessage(msg)
}

func (vn *ValidatorNode) startConsensus() {
	ticker := time.NewTicker(vn.config.ConsensusConfig.BlockTime)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			vn.createAndBroadcastBlock()
		case <-vn.quit:
			return
		}
	}
}

func (vn *ValidatorNode) createAndBroadcastBlock() {
	vn.mu.Lock()
	defer vn.mu.Unlock()
	txs := vn.state.GetPendingTransactions()
	block, err := vn.consensus.CreateBlock(vn.address, txs)
	if err != nil {
		vn.logger.Warn(fmt.Sprintf("Failed to create block: %v", err))
		return
	}
	vn.state.ApplyBlock(block)
	vn.logger.Info(fmt.Sprintf("Block created: %s", block.ID))
	vn.broadcastBlock(block)
}

func (vn *ValidatorNode) broadcastBlock(block *state.Block) {
	for _, conn := range vn.connectedPeers {
		msg := network.Message{
			Type:    network.BlockMessage,
			Payload: block.Serialize(),
		}
		if err := vn.network.SendMessage(conn, msg); err != nil {
			vn.logger.Warn(fmt.Sprintf("Failed to send block: %v", err))
		}
	}
}

func (vn *ValidatorNode) monitorNodeHealth() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			vn.performHealthCheck()
		case <-vn.quit:
			return
		}
	}
}

func (vn *ValidatorNode) performHealthCheck() {
	vn.logger.Info("Performing health check...")
	// Implement health check logic here
	vn.metrics.CollectNodeMetrics(vn.address)
	vn.logger.Info("Health check completed.")
}

func (vn *ValidatorNode) EncryptMessage(message []byte) ([]byte, error) {
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(vn.publicKey)
	if err != nil {
		return nil, err
	}
	block := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	}
	pemData := pem.EncodeToMemory(block)
	return crypto.EncryptWithPublicKey(message, pemData)
}

func (vn *ValidatorNode) DecryptMessage(ciphertext []byte) ([]byte, error) {
	privateKeyBytes := x509.MarshalECPrivateKey(vn.privateKey)
	block := &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: privateKeyBytes,
	}
	pemData := pem.EncodeToMemory(block)
	return crypto.DecryptWithPrivateKey(ciphertext, pemData)
}

func (vn *ValidatorNode) SignMessage(message []byte) (string, error) {
	hash := crypto.HashMessage(message)
	r, s, err := ecdsa.Sign(rand.Reader, vn.privateKey, hash)
	if err != nil {
		return "", err
	}
	signature := r.Bytes()
	signature = append(signature, s.Bytes()...)
	return hex.EncodeToString(signature), nil
}

func (vn *ValidatorNode) VerifyMessage(message []byte, signature string) (bool, error) {
	hash := crypto.HashMessage(message)
	sigBytes, err := hex.DecodeString(signature)
	if err != nil {
		return false, err
	}
	r := big.NewInt(0).SetBytes(sigBytes[:len(sigBytes)/2])
	s := big.NewInt(0).SetBytes(sigBytes[len(sigBytes)/2:])
	return ecdsa.Verify(vn.publicKey, hash, r, s), nil
}
