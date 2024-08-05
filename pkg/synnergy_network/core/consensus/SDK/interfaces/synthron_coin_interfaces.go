package coin

// SynthronCoin defines the primary interface for the main native coin of the Synnergy Network blockchain.
type SynthronCoin interface {
	NewSynthronCoin() (*Coin, error)
	GetCoinDetails() (*CoinDetails, error)
	ValidateCoin() error
}

// CoinPerformanceMetrics defines the interface for managing performance metrics of Synthron Coin.
type CoinPerformanceMetrics interface {
	NewCoinPerformanceMetrics() (*PerformanceMetrics, error)
	UpdateMetrics(newBlock Block, validators []string, transactionVolume float64) error
	CalculateNewAverage(currentAverage time.Duration, newTime time.Duration) time.Duration
	CalculateNewAverageFee(currentAverage float64, transactions []Transaction) float64
	CalculateHashRate(block Block) float64
	GetMetrics() (map[string]interface{}, error)
	LogPerformanceMetrics(metrics map[string]interface{}) error
	CalculateHalving(currentBlock int) float64
	CalculateEmissionRate(currentBlock int) float64
	TokenBurningRate(transactionVolume float64, burnRate float64) float64
	AnalyzePerformanceTrends() (map[string]interface{}, error)
	ExportMetricsReport() ([]byte, error)
}

// CoinSecurityMeasures defines the interface for managing security measures of Synthron Coin.
type CoinSecurityMeasures interface {
	NewCoinSecurityMeasures() (*SecurityMeasures, error)
	PerformSecurityAudit() (*SecurityAuditReport, error)
	ImplementSecurityProtocol(protocol SecurityProtocol) error
	MonitorSecurityEvents() ([]SecurityEvent, error)
	RespondToSecurityThreat(threat SecurityThreat) error
	LogSecurityEvent(event SecurityEvent) error
	GetSecurityLogs() ([]SecurityEvent, error)
	EncryptSecurityData(data []byte, key string) ([]byte, error)
	DecryptSecurityData(encryptedData []byte, key string) ([]byte, error)
}

// CoinSupplyManagement defines the interface for managing the supply of Synthron Coin.
type CoinSupplyManagement interface {
	NewCoinSupplyManagement(initialSupply uint64, initialInflationRate float64) (*SupplyManagement, error)
	BurnCoins(amount uint64) error
	LockCoins(contractID string, amount uint64, duration time.Duration) error
	UnlockCoins(contractID string) error
	GetSupplyMetrics() (map[string]interface{}, error)
	AdjustInflationRate(newRate float64) error
	ValidateSupplyIntegrity() error
	LogSupplyEvent(event SupplyEvent) error
	GetSupplyLogs() ([]SupplyEvent, error)
	BackupSupplyData() ([]byte, error)
	RestoreSupplyData(data []byte) error
}

// CommunityGovernance defines the interface for managing community governance of Synthron Coin.
type CommunityGovernance interface {
	NewCommunityGovernance(proposalCreationThreshold float64) (*Governance, error)
	AddValidator(id string, staked float64, pubKey string) error
	RemoveValidator(id string) error
	SubmitProposal(proposal Proposal, validatorID string) error
	VoteProposal(proposalID string, validatorID string, vote bool) error
	TallyVotes(proposalID string) (bool, error)
	ExecuteProposal(proposal Proposal) error
	GetProposalByID(proposalID string) (Proposal, error)
	GenerateProposalID() string
	MonitorGovernance() error
	LogGovernanceMetrics(metrics map[string]interface{}) error
	GetGovernanceMetrics() (map[string]interface{}, error)
	EncryptGovernanceData(data []byte, key string) ([]byte, error)
	DecryptGovernanceData(encryptedData []byte, key string) ([]byte, error)
	ManageValidatorReputation(id string, action ReputationAction) error
	ResolveDisputes(dispute Dispute) (Resolution, error)
}

// SupplyAdjustmentManager defines the interface for managing supply adjustments of Synthron Coin.
type SupplyAdjustmentManager interface {
	NewSupplyAdjustmentManager(total, circulating float64, halvingInterval, startBlock int) (*SupplyAdjustment, error)
	HalveRewards(currentBlock int) error
	BurnCoins(amount float64) error
	AdjustSupplyMetrics() error
	LogSupplyAdjustmentEvent(event SupplyAdjustmentEvent) error
	GetSupplyAdjustmentLogs() ([]SupplyAdjustmentEvent, error)
}

// GenesisBlock defines the interface for managing the genesis block of Synthron Coin.
type GenesisBlock interface {
	InitializeWallets() (map[string]*Wallet, error)
	CreateGenesisBlock() (*Block, error)
	DistributeInitialCoins(genesis *Block, wallets map[string]*Wallet) error
	ValidateGenesisBlock(genesis *Block) error
	LogGenesisEvent(event GenesisEvent) error
	GetGenesisLogs() ([]GenesisEvent, error)
	BackupGenesisData() ([]byte, error)
	RestoreGenesisData(data []byte) error
}

// Governance defines the interface for managing governance of the Synnergy Network.
type Governance interface {
	InitializeGovernance() (*Governance, error)
	ConductAudit() (*AuditReport, error)
	ApplyAdjustments(adj ProtocolAdjustment) error
	VoteOnAdjustment(adj ProtocolAdjustment) bool
	ReviewGovernanceProcesses() error
	GenerateGovernanceReport() (*GovernanceReport, error)
	LogGovernanceEvent(event GovernanceEvent) error
	GetGovernanceLogs() ([]GovernanceEvent, error)
	BackupGovernanceData() ([]byte, error)
	RestoreGovernanceData(data []byte) error
}
