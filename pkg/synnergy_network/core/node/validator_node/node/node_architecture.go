package node

import (
	"crypto/tls"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/synnergy_network_blockchain/pkg/synnergy_network/common"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/node/validator_node/consensus"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/node/validator_node/governance"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/node/validator_node/networking"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/node/validator_node/storage"
)

type ValidatorNode struct {
	ID                   string
	Name                 string
	Description          string
	StakeActive          bool
	ConsensusSwitch      bool
	Consensus            consensus.SynnergyConsensus
	DeactivatedConsensus1 string
	DeactivatedConsensus2 string
	Host                 string
	Port                 int
	MaxPeers             int
	DataReplicationType  string
	StakeAmount          int
	TLSConfig            *tls.Config
	ConnectionPool       map[string]networking.NetworkConnection
	Metrics              map[string]interface{}
	mu                   sync.Mutex
	BackupSchedule       string
	BackupRetentionDays  int
}

func (vn *ValidatorNode) Initialize(id, name, description, host string, port, maxPeers, stakeAmount int, dataReplicationType, tlsCertFile, tlsKeyFile string) {
	vn.ID = id
	vn.Name = name
	vn.Description = description
	vn.Host = host
	vn.Port = port
	vn.MaxPeers = maxPeers
	vn.StakeAmount = stakeAmount
	vn.DataReplicationType = dataReplicationType
	vn.ConnectionPool = make(map[string]networking.NetworkConnection)
	vn.Metrics = make(map[string]interface{})

	cert, err := tls.LoadX509KeyPair(tlsCertFile, tlsKeyFile)
	if err != nil {
		log.Fatalf("failed to load TLS certificates: %v", err)
	}

	vn.TLSConfig = &tls.Config{Certificates: []tls.Certificate{cert}}

	vn.setup()
}

func (vn *ValidatorNode) setup() {
	vn.configureNetwork()
	vn.configureConsensus()
	vn.configureGovernance()
	vn.configureStorage()
	vn.startHealthChecks()
	vn.startMetricsCollection()
}

func (vn *ValidatorNode) configureNetwork() {
	networkConnection := &networking.NetworkConnection{}
	networkConnection.Initialize(vn.ID, vn.Host, vn.Port, vn.MaxPeers, vn.DataReplicationType, vn.TLSConfig.Certificates[0].Certificate[0], vn.TLSConfig.Certificates[0].PrivateKey)
	vn.ConnectionPool[vn.ID] = *networkConnection
	go networkConnection.ReplicateData()
}

func (vn *ValidatorNode) configureConsensus() {
	consensus := &consensus.SynnergyConsensus{}
	consensus.Initialize(vn.ID, vn.StakeAmount)
	go consensus.RunConsensus()
}

func (vn *ValidatorNode) configureGovernance() {
	protocolUpdate := &governance.ProtocolUpdate{}
	protocolUpdate.Initialize(vn.ID, "http://localhost:8080/proposals", "http://localhost:8080/vote", "http://localhost:8080/update")
	go protocolUpdate.ParticipateInProtocolUpdates()

	voting := &governance.Voting{}
	voting.Initialize(vn.ID, 1.0, "http://localhost:8080/proposals", "http://localhost:8080/vote")
	go voting.ParticipateInVoting()
}

func (vn *ValidatorNode) configureStorage() {
	storageInstance := &storage.Storage{}
	storageInstance.Initialize("/var/synnergy/validator_node/data", "/var/synnergy/validator_node/logs", "/var/synnergy/validator_node/backup")
	go storageInstance.ManageDataReplication()
}

func (vn *ValidatorNode) startHealthChecks() {
	go func() {
		for {
			time.Sleep(5 * time.Minute)
			vn.performHealthCheck()
		}
	}()
}

func (vn *ValidatorNode) performHealthCheck() {
	vn.mu.Lock()
	defer vn.mu.Unlock()

	vn.Metrics["cpu_usage"] = common.GetCPUUsage()
	vn.Metrics["memory_usage"] = common.GetMemoryUsage()
	vn.Metrics["disk_usage"] = common.GetDiskUsage()
	vn.Metrics["network_latency"] = common.GetNetworkLatency()
	vn.Metrics["transactions_validated"] = common.GetTransactionsValidated()
	vn.Metrics["blocks_created"] = common.GetBlocksCreated()

	log.Printf("Health check completed: %+v", vn.Metrics)
}

func (vn *ValidatorNode) startMetricsCollection() {
	go func() {
		for {
			time.Sleep(10 * time.Second)
			vn.collectMetrics()
		}
	}()
}

func (vn *ValidatorNode) collectMetrics() {
	vn.mu.Lock()
	defer vn.mu.Unlock()

	vn.Metrics["timestamp"] = time.Now().Unix()
	vn.Metrics["cpu_usage"] = common.GetCPUUsage()
	vn.Metrics["memory_usage"] = common.GetMemoryUsage()
	vn.Metrics["disk_usage"] = common.GetDiskUsage()
	vn.Metrics["network_latency"] = common.GetNetworkLatency()
	vn.Metrics["transactions_validated"] = common.GetTransactionsValidated()
	vn.Metrics["blocks_created"] = common.GetBlocksCreated()

	// Send metrics to a centralized server or store locally
}

func (vn *ValidatorNode) handleIncomingConnections() {
	for {
		time.Sleep(10 * time.Second)
		// Implement logic to handle incoming connections from peers
		// and update the connection pool accordingly.
	}
}

func (vn *ValidatorNode) broadcastMessage(message []byte) {
	vn.mu.Lock()
	defer vn.mu.Unlock()

	for _, conn := range vn.ConnectionPool {
		conn.Send(message)
	}
}


