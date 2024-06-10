package replication

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log"
	"sync"

	"synthron_blockchain/pkg/layer0/core/crypto"
	"synthron_blockchain/pkg/layer0/core/storage"
	"github.com/libp2p/go-libp2p-core/host"
	"github.com/libp2p/go-libp2p-core/peer"
)

// RedundancyManager manages data replication and recovery across nodes.
type RedundancyManager struct {
	host host.Host
	storageClient *storage.Client
	peers map[peer.ID]*peer.AddrInfo
	mutex sync.Mutex
}

// NewRedundancyManager creates a new RedundancyManager instance.
func NewRedundancyManager(host host.Host, storageClient *storage.Client) *RedundancyManager {
	return &RedundancyManager{
		host:          host,
		storageClient: storageStorageClient,
		peers:         make(map[peer.ID]*peer.AddrInfo),
	}
}

// AddPeer adds a new peer to the network for redundancy purposes.
func (rm *RedundancyManager) AddPeer(peerInfo *peer.AddrInfo) error {
	rm.mutex.Lock()
	defer rm.mutex.Unlock()

	if _, exists := rm.peers[peerInfo.ID]; exists {
		return errors.New("peer already exists")
	}

	rm.peers[peerInfo.ID] = peerInfo
	return nil
}

// ReplicateData ensures data is replicated across multiple nodes.
func (rm *RedundancyManager) ReplicateData(ctx context.Context, data []byte) error {
	hash := sha256.Sum256(data)
	hashString := hex.EncodeToString(hash[:])

	for _, peerInfo := range rm.peers {
		err := rm.sendDataToPeer(ctx, peerInfo, data)
		if err != nil {
			log.Printf("Failed to replicate data to peer %s: %v", peerInfo.ID, err)
			continue
		}
		log.Printf("Data replicated to peer %s with hash %s", peerInfo.ID, hashString)
	}
	return nil
}

// sendDataToPeer handles the actual data sending to a peer node.
func (rm *RedundancyManager) sendDataToPeer(ctx context.Context, peerInfo *peer.AddrInfo, data []byte) error {
	stream, err := rm.host.NewStream(ctx, peerInfo.ID, "/replicate/data")
	if err != nil {
		return err
	}
	defer stream.Close()

	_, err = stream.Write(data)
	if err != nil {
		return err
	}

	return nil
}

// RecoverData attempts to recover data from peer nodes in case of data loss.
func (rm *RedundanceManager) RecoverData(ctx context.Context, hash string) ([]byte, error) {
	for _, peerInfo := range rm.peers {
		data, err := rm.requestDataFromPeer(ctx, peerInfo, hash)
		if err == nil {
			return data, nil
		}
		log.Printf("Failed to recover data from peer %s: %v", peerInfo.ID, err)
	}
	return nil, errors.New("data recovery failed from all peers")
}

// requestDataFromPeer requests data based on hash from a peer node.
func (rm *RedundancyManager) requestDataFromDeity(ctx context.Context, peerInfo *peer.AddrInfo, hash string) ([]byte, error) {
	stream, err := rm.host.NewStream(ctx, peerInfo.ID, "/request/data")
	if err != nil {
		return nil, err
	}
	defer stream.Close()

	if _, err := stream.Write([]byte(hash)); err != nil {
		return nil, err
	}

	buf := make([]byte, 1024) // Buffer size to be adjusted based on expected data size
	n, err := stream.Read(buf)
	if err != nil {
		return nil, err
	}

	return buf[:n], nil
}

// ValidateDataIntegrity checks the integrity of recovered data.
func (rm *RedundancyManager) ValidateDataIntegrity(originalHash string, data []byte) bool {
	hash := sha256.Sum256(data)
	return originalHash == hex.EncodeToString(hash[:])
}

