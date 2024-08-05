package storage

import (
	"fmt"
	"log"
	"time"
	"sync"

	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/node/validator_node/networking"
)

type NodeDataReplication struct {
	DataDir         string
	Peers           map[string]networking.NetworkConnection
	ReplicationMode string // "full" or "incremental"
	mu              sync.Mutex
}

func (ndr *NodeDataReplication) Initialize(dataDir string, replicationMode string) {
	ndr.DataDir = dataDir
	ndr.ReplicationMode = replicationMode
	ndr.Peers = make(map[string]networking.NetworkConnection)
}

func (ndr *NodeDataReplication) AddPeer(peerID string, connection networking.NetworkConnection) {
	ndr.mu.Lock()
	defer ndr.mu.Unlock()
	ndr.Peers[peerID] = connection
}

func (ndr *NodeDataReplication) RemovePeer(peerID string) {
	ndr.mu.Lock()
	defer ndr.mu.Unlock()
	delete(ndr.Peers, peerID)
}

func (ndr *NodeDataReplication) ReplicateData() {
	ticker := time.NewTicker(10 * time.Minute)
	for {
		select {
		case <-ticker.C:
			ndr.mu.Lock()
			for peerID, connection := range ndr.Peers {
				go ndr.replicateToPeer(peerID, connection)
			}
			ndr.mu.Unlock()
		}
	}
}

func (ndr *NodeDataReplication) replicateToPeer(peerID string, connection networking.NetworkConnection) {
	log.Printf("Starting data replication to peer: %s\n", peerID)
	// Implementation of data replication logic

	// Depending on the mode, perform full or incremental replication
	if ndr.ReplicationMode == "full" {
		// Full replication logic
		ndr.performFullReplication(connection)
	} else {
		// Incremental replication logic
		ndr.performIncrementalReplication(connection)
	}
	log.Printf("Completed data replication to peer: %s\n", peerID)
}

func (ndr *NodeDataReplication) performFullReplication(connection networking.NetworkConnection) {
	// Logic to perform full data replication
	// This could involve sending the entire data directory to the peer
	fmt.Println("Performing full data replication")
	// Example implementation:
	// helpers.SendDirectory(connection, ndr.DataDir)
}

func (ndr *NodeDataReplication) performIncrementalReplication(connection networking.NetworkConnection) {
	// Logic to perform incremental data replication
	// This could involve sending only the changed files since the last replication
	fmt.Println("Performing incremental data replication")
	// Example implementation:
	// helpers.SendChangedFiles(connection, ndr.DataDir, lastReplicationTime)
}

func (ndr *NodeDataReplication) ScheduleReplication(interval time.Duration) {
	ticker := time.NewTicker(interval)
	go func() {
		for {
			select {
			case <-ticker.C:
				ndr.ReplicateData()
			}
		}
	}()
}

func (ndr *NodeDataReplication) HandleIncomingReplication(connection networking.NetworkConnection) {
	// Logic to handle incoming data replication from other peers
	// This could involve receiving data and updating the local data directory
	fmt.Println("Handling incoming data replication")
	// Example implementation:
	// helpers.ReceiveData(connection, ndr.DataDir)
}

func (ndr *NodeDataReplication) Start() {
	go ndr.ReplicateData()
}
