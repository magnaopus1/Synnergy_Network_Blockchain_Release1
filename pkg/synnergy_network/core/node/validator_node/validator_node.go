package validator_node

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/synnergy_network_blockchain/pkg/synnergy_network/common"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/node/validator_node/consensus"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/node/validator_node/governance"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/node/validator_node/networking"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/node/validator_node/storage"
)

type ValidatorNode struct {
	ID                  string
	Name                string
	Description         string
	StakeActive         bool
	ConsensusSwitch     bool
	Consensus           consensus.SynnergyConsensus
	DeactivatedConsensus1 string
	DeactivatedConsensus2 string
	Host                string
	Port                int
	MaxPeers            int
	DataReplicationType string
	StakeAmount         int
	TLSConfig           *tls.Config
	ConnectionPool      map[string]networking.NetworkConnection
	Metrics             map[string]interface{}
	mu                  sync.Mutex
	BackupSchedule      string
	BackupRetentionDays string
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
	vn.Consensus.Initialize(vn.ID, vn.StakeAmount)
	go vn.Consensus.RunConsensus()
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
	storage := &storage.Storage{}
	storage.Initialize("/var/synnergy/validator_node/data", "/var/synnergy/validator_node/logs", "/var/synnergy/validator_node/backup")
	go storage.ManageDataReplication()
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
	vn.Metrics["network_latency"] = common.GetNetworkLatency("google.com") // Example host
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
	vn.Metrics["network_latency"] = common.GetNetworkLatency("google.com") // Example host
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

func (vn *ValidatorNode) validateTransaction(transaction common.Transaction) error {
	// Implement transaction validation logic here
	// This could involve checking signatures, verifying transaction syntax, etc.
	return nil
}

func (vn *ValidatorNode) createBlock(transactions []common.Transaction) (common.Block, error) {
	// Implement block creation logic here
	// This could involve gathering transactions, creating a block header, etc.
	return common.Block{}, nil
}

func main() {
	reader := bufio.NewReader(os.Stdin)

	fmt.Println("Validator Node Setup")
	fmt.Println("----------------------")

	// Step 1: Provide a template of the config
	fmt.Println("Creating config template...")
	createConfigTemplate()

	// Step 2: Ask for the completed config
	fmt.Println("Please complete the config file at configs/validator_node/config.toml and press Enter to continue...")
	reader.ReadString('\n')

	// Step 3: Load the config
	config := loadConfig()

	// Step 4: Ask for the deploy network address or URL
	fmt.Print("Enter the deploy network address or URL: ")
	deployURL, _ := reader.ReadString('\n')
	deployURL = strings.TrimSpace(deployURL)

	// Step 5: Ask if you want to deploy
	fmt.Print("Do you want to deploy the node? (yes/no): ")
	deploy, _ := reader.ReadString('\n')
	deploy = strings.TrimSpace(deploy)

	if strings.ToLower(deploy) == "yes" {
		node := &ValidatorNode{}
		node.Initialize(config.ID, config.Name, config.Description, config.Host, config.Port, config.MaxPeers, config.StakeAmount, config.DataReplicationType, config.TLSCertFile, config.TLSKeyFile)
		fmt.Println("Validator node deployed successfully.")
	} else {
		fmt.Println("Node deployment aborted.")
	}
}

func createConfigTemplate() {
	template := `
# Validator Node Configuration
ID = "unique-node-id"
Name = "Validator Node"
Description = "Primary validator node for the Synnergy Network"
Host = "0.0.0.0"
Port = 30303
MaxPeers = 50
StakeAmount = 1000
DataReplicationType = "full"
TLSCertFile = "/path/to/tls_cert.pem"
TLSKeyFile = "/path/to/tls_key.pem"
`
	err := os.WriteFile("configs/validator_node/config.toml", []byte(template), 0644)
	if err != nil {
		log.Fatalf("Failed to create config template: %v", err)
	}
}

type Config struct {
	ID                  string
	Name                string
	Description         string
	Host                string
	Port                int
	MaxPeers            int
	StakeAmount         int
	DataReplicationType string
	TLSCertFile         string
	TLSKeyFile          string
}

func loadConfig() Config {
	file, err := os.Open("configs/validator_node/config.toml")
	if err != nil {
		log.Fatalf("Failed to open config file: %v", err)
	}
	defer file.Close()

	var config Config
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		switch key {
		case "ID":
			config.ID = value
		case "Name":
			config.Name = value
		case "Description":
			config.Description = value
		case "Host":
			config.Host = value
		case "Port":
			config.Port, _ = strconv.Atoi(value)
		case "MaxPeers":
			config.MaxPeers, _ = strconv.Atoi(value)
		case "StakeAmount":
			config.StakeAmount, _ = strconv.Atoi(value)
		case "DataReplicationType":
			config.DataReplicationType = value
		case "TLSCertFile":
			config.TLSCertFile = value
		case "TLSKeyFile":
			config.TLSKeyFile = value
		}
	}

	if err := scanner.Err(); err != nil {
		log.Fatalf("Error reading config file: %v", err)
	}

	return config
}
