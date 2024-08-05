// CollateralAudit struct to hold audit details
type CollateralAudit struct {
    AuditID         string
    CollateralID    string
    AuditDate       time.Time
    Auditor         string
    AuditReport     string
    ComplianceStatus bool
    IssuesFound     []string
    Resolution      string
}

// CollateralLiquidation struct to hold liquidation details
type CollateralLiquidation struct {
    LiquidationID     string
    CollateralID      string
    LoanID            string
    LiquidationDate   time.Time
    Liquidator        string
    LiquidationStatus string
    LiquidationReport string
}

// CollateralLiquidation struct to hold liquidation details
type CollateralLiquidation struct {
    LiquidationID     string
    CollateralID      string
    LoanID            string
    LiquidationDate   time.Time
    Liquidator        string
    LiquidationStatus string
    LiquidationReport string
    RecoveryAmount    float64
}

// CollateralMonitoring struct to hold monitoring details
type CollateralMonitoring struct {
    MonitoringID   string
    CollateralID   string
    LoanID         string
    LastCheckDate  time.Time
    NextCheckDate  time.Time
    Status         string
    Value          float64
    RiskLevel      string
    Notifications  []string
}

// CollateralOption struct to hold collateral details
type CollateralOption struct {
    CollateralID   string
    LoanID         string
    CollateralType string
    Value          float64
    Status         string
    LastUpdated    time.Time
    Notifications  []string
}

// CollateralReport struct to hold collateral report details
type CollateralReport struct {
    ReportID       string
    CollateralID   string
    LoanID         string
    ReportDate     time.Time
    Reporter       string
    ReportContent  string
    ComplianceStatus bool
    IssuesFound    []string
    Recommendations string
    Status         string
}

// CollateralSecuring struct to hold collateral securing details
type CollateralSecuring struct {
    SecuringID     string
    CollateralID   string
    LoanID         string
    SecuringDate   time.Time
    SecuringStatus string
    SecuringReport string
    Notifications  []string
}

// Collateral represents the details of a collateral
type Collateral struct {
    CollateralID   string
    LoanID         string
    Type           CollateralType
    Value          float64
    Status         string
    LastUpdated    time.Time
    Notifications  []string
}

// CollateralType represents the type of collateral
type CollateralType string

// CollateralValuation struct to hold collateral valuation details
type CollateralValuation struct {
    ValuationID     string
    CollateralID    string
    LoanID          string
    ValuationDate   time.Time
    ValuationAmount float64
    ValuationStatus string
    ValuationReport string
}

// AuditLog represents a log entry for compliance audits.
type AuditLog struct {
    Timestamp time.Time `json:"timestamp"`
    NodeID    string    `json:"node_id"`
    Action    string    `json:"action"`
    Details   string    `json:"details"`
}

// ComplianceAuditor manages the auditing process for compliance within the LoanPool.
type ComplianceAuditor struct {
    logs map[string][]AuditLog
}

// ComplianceReport represents a compliance report for monitoring purposes.
type ComplianceReport struct {
    Timestamp      time.Time `json:"timestamp"`
    NodeID         string    `json:"node_id"`
    ComplianceType string    `json:"compliance_type"`
    Details        string    `json:"details"`
    Status         string    `json:"status"`
}

// ComplianceMonitoring manages the compliance monitoring process within the LoanPool.
type ComplianceMonitoring struct {
    reports map[string][]ComplianceReport
}

// TrainingModule represents a training module for compliance purposes.
type TrainingModule struct {
    ModuleID   string    `json:"module_id"`
    Title      string    `json:"title"`
    Content    string    `json:"content"`
    Duration   int       `json:"duration"` // Duration in minutes
    CreatedAt  time.Time `json:"created_at"`
    UpdatedAt  time.Time `json:"updated_at"`
}

// TrainingRecord represents a record of a user's completion of a training module.
type TrainingRecord struct {
    UserID     string    `json:"user_id"`
    ModuleID   string    `json:"module_id"`
    Completed  bool      `json:"completed"`
    Score      int       `json:"score"`
    CompletedAt time.Time `json:"completed_at"`
}

// ComplianceTraining manages compliance training modules and user training records.
type ComplianceTraining struct {
    modules map[string]TrainingModule
    records map[string][]TrainingRecord
}

// VerificationRequest represents a request for compliance verification.
type VerificationRequest struct {
    RequestID   string    `json:"request_id"`
    NodeID      string    `json:"node_id"`
    EntityID    string    `json:"entity_id"`
    RequestType string    `json:"request_type"`
    Timestamp   time.Time `json:"timestamp"`
    Status      string    `json:"status"`
    Details     string    `json:"details"`
}

// VerificationResponse represents a response to a compliance verification request.
type VerificationResponse struct {
    RequestID string `json:"request_id"`
    NodeID    string `json:"node_id"`
    Verified  bool   `json:"verified"`
    Message   string `json:"message"`
}

// ComplianceVerification manages the verification process within the LoanPool.
type ComplianceVerification struct {
    requests map[string]VerificationRequest
    responses map[string]VerificationResponse
}

// KYCAMLRequest represents a request for KYC/AML verification.
type KYCAMLRequest struct {
    RequestID  string    `json:"request_id"`
    UserID     string    `json:"user_id"`
    NodeID     string    `json:"node_id"`
    Timestamp  time.Time `json:"timestamp"`
    Status     string    `json:"status"`
    Details    string    `json:"details"`
}

// KYCAMLResponse represents a response to a KYC/AML verification request.
type KYCAMLResponse struct {
    RequestID string `json:"request_id"`
    UserID    string `json:"user_id"`
    Verified  bool   `json:"verified"`
    Message   string `json:"message"`
}

// KYCAMLIntegration manages KYC/AML verification processes.
type KYCAMLIntegration struct {
    requests  map[string]KYCAMLRequest
    responses map[string]KYCAMLResponse
}

// LegalComplianceRequest represents a request for legal compliance verification.
type LegalComplianceRequest struct {
    RequestID  string    `json:"request_id"`
    UserID     string    `json:"user_id"`
    NodeID     string    `json:"node_id"`
    Timestamp  time.Time `json:"timestamp"`
    Status     string    `json:"status"`
    Details    string    `json:"details"`
}

// LegalComplianceResponse represents a response to a legal compliance verification request.
type LegalComplianceResponse struct {
    RequestID string `json:"request_id"`
    UserID    string `json:"user_id"`
    Compliant bool   `json:"compliant"`
    Message   string `json:"message"`
}

// LegalCompliance manages legal compliance processes.
type LegalCompliance struct {
    requests  map[string]LegalComplianceRequest
    responses map[string]LegalComplianceResponse
}

// RegulatoryReport represents a regulatory report structure
type RegulatoryReport struct {
	ReportID    string    `json:"report_id"`
	ReportType  string    `json:"report_type"`
	Timestamp   time.Time `json:"timestamp"`
	Content     string    `json:"content"`
	SubmittedBy string    `json:"submitted_by"`
	Status      string    `json:"status"`
	Comments    string    `json:"comments"`
}

// RegulatoryReporting manages regulatory reporting processes
type RegulatoryReporting struct {
	reports map[string]RegulatoryReport
}

type AlternativeCreditData struct {
    UserID                string                 `json:"user_id"`
    SocialMediaActivity   map[string]interface{} `json:"social_media_activity"`
    UtilityPayments       map[string]float64     `json:"utility_payments"`
    RentalHistory         map[string]float64     `json:"rental_history"`
    BehavioralAnalytics   map[string]interface{} `json:"behavioral_analytics"`
    LastUpdated           time.Time              `json:"last_updated"`
}

// BehavioralAnalytics is a structure for managing behavioral analytics in credit scoring
type BehavioralAnalytics struct {
    UserID             string
    TransactionHistory []models.Transaction
    PaymentPatterns    []PaymentPattern
    RiskProfile        models.RiskProfile
}

// PaymentPattern represents a payment behavior pattern
type PaymentPattern struct {
    PatternType   string
    Description   string
    Occurrences   int
    LastObserved  time.Time
    RiskImpact    *big.Int
}

type CreditScore struct {
	UserID             string  `json:"user_id"`
	Score              float64 `json:"score"`
	LastUpdated        int64   `json:"last_updated"`
	TransactionHistory []Transaction `json:"transaction_history"`
	BehavioralData     BehavioralData `json:"behavioral_data"`
}

type Transaction struct {
	TxID     string  `json:"tx_id"`
	Amount   float64 `json:"amount"`
	Date     int64   `json:"date"`
	Status   string  `json:"status"`
}

type BehavioralData struct {
	SpendingPatterns   map[string]float64 `json:"spending_patterns"`
	PaymentPunctuality map[string]bool    `json:"payment_punctuality"`
	FinancialStability float64            `json:"financial_stability"`
}

// CreditReport represents a credit report for a user.
type CreditReport struct {
    UserID        string    `json:"user_id"`
    Score         int       `json:"score"`
    ReportDetails string    `json:"report_details"`
    Timestamp     time.Time `json:"timestamp"`
}

// SecureCreditReport represents a secure, encrypted credit report.
type SecureCreditReport struct {
    UserID    string `json:"user_id"`
    Encrypted []byte `json:"encrypted"`
}

// CreditData represents the data required for credit scoring.
type CreditData struct {
    TransactionHistory []Transaction
    BehavioralData     BehavioralData
    ExternalData       ExternalData
    Timestamp          time.Time
}

// Transaction represents a financial transaction.
type Transaction struct {
    Amount    float64
    Timestamp time.Time
    Type      string // e.g., "payment", "loan", "transfer"
}

// BehavioralData represents the behavioral analytics data.
type BehavioralData struct {
    PaymentPunctuality float64
    SpendingPatterns   map[string]float64 // e.g., category: amount
    IncomeStability    float64
}

// ExternalData represents external financial and alternative credit data.
type ExternalData struct {
    CreditReports []CreditReport
    SocialMedia   map[string]float64 // e.g., platform: activity score
    UtilityBills  map[string]float64 // e.g., service: amount
}

// BasicCreditScoreAlgorithm implements a basic credit scoring algorithm.
type BasicCreditScoreAlgorithm struct{}

// User represents a user's identity in the decentralized system.
type User struct {
    SynID        string `json:"syn_id"`
    PhoneNumber  string `json:"phone_number"`
    Email        string `json:"email"`
    UserID       string `json:"user_id"`
    NodeType     string `json:"node_type"` // Normal or Authority
    WalletID     string `json:"wallet_id"`
    PublicKey    string `json:"public_key"`
    RecoveryKey  string `json:"recovery_key"`
    CreatedAt    time.Time `json:"created_at"`
}

// IdentityManager manages user identities within the decentralized system.
type IdentityManager struct {
    users map[string]User
}

// CreditScore represents a user's on-chain credit score.
type CreditScore struct {
    UserID    string    `json:"user_id"`
    Score     int       `json:"score"`
    Timestamp time.Time `json:"timestamp"`
    DataHash  string    `json:"data_hash"`
}

// OnChainCreditScoring manages the on-chain credit scoring system.
type OnChainCreditScoring struct {
    scores map[string]CreditScore
}

// EncryptedScore represents an encrypted credit score.
type EncryptedScore struct {
    UserID   string `json:"user_id"`
    Data     []byte `json:"data"`
    Salt     []byte `json:"salt"`
    Nonce    []byte `json:"nonce"`
}

// PrivacyPreservingScoring manages the privacy-preserving credit scoring system.
type PrivacyPreservingScoring struct {
    scores map[string]EncryptedScore
}

// CustomizableLoanTerms represents the process for handling customizable loan terms within the Synnergy network.
type CustomizableLoanTerms struct {
	blockchain   *blockchain.Blockchain
	cryptoEngine crypto.CryptoEngine
}

// DynamicInterestRates manages the dynamic adjustment of interest rates within the Synnergy network.
type DynamicInterestRates struct {
	blockchain   *blockchain.Blockchain
	cryptoEngine crypto.CryptoEngine
}

// FlexibleRepaymentOptions manages flexible repayment plans within the Synnergy network.
type FlexibleRepaymentOptions struct {
	blockchain   *blockchain.Blockchain
	cryptoEngine crypto.CryptoEngine
}

// LoanTermsAudits handles the auditing of loan terms and processes within the Synnergy network.
type LoanTermsAudits struct {
	blockchain   *blockchain.Blockchain
	cryptoEngine crypto.CryptoEngine
}

// LoanTermsMonitoring manages the monitoring of loan terms and ensures compliance within the Synnergy network.
type LoanTermsMonitoring struct {
	blockchain   *blockchain.Blockchain
	cryptoEngine crypto.CryptoEngine
}

// LoanTermsReporting manages the reporting of loan terms and their status within the Synnergy network.
type LoanTermsReporting struct {
	blockchain   *blockchain.Blockchain
	cryptoEngine crypto.CryptoEngine
}

// PersonalizedRecommendations provides personalized loan recommendations within the Synnergy network.
type PersonalizedRecommendations struct {
	blockchain   *blockchain.Blockchain
	cryptoEngine crypto.CryptoEngine
}

// ScenarioAnalysis handles the analysis of various loan scenarios to help borrowers make informed decisions.
type ScenarioAnalysis struct {
	blockchain   *blockchain.Blockchain
	cryptoEngine crypto.CryptoEngine
}

// LoanCore represents the core structure for managing loans.
type LoanCore struct {
	loans map[string]Loan
	mu    sync.Mutex
}

// Loan represents a single loan.
type Loan struct {
	ID            string
	BorrowerID    string
	Amount        float64
	InterestRate  float64
	StartDate     time.Time
	EndDate       time.Time
	RepaymentPlan []Repayment
	Status        string
	Collateral    Collateral
}

// Collateral represents the collateral for a loan.
type Collateral struct {
	Type  string
	Value float64
}

// Repayment represents a single repayment.
type Repayment struct {
	Date   time.Time
	Amount float64
}

// LoanDisbursement represents the structure for managing loan disbursements.
type LoanDisbursement struct {
	Disbursements map[string]Disbursement
	mu            sync.Mutex
}

// Disbursement represents a single loan disbursement.
type Disbursement struct {
	ID          string
	LoanID      string
	BorrowerID  string
	Amount      float64
	Status      string
	CreatedAt   time.Time
	ProcessedAt time.Time
}

// LoanMonitoring represents the structure for monitoring a loan.
type LoanMonitoring struct {
	LoanID        string       `json:"loan_id"`
	BorrowerID    string       `json:"borrower_id"`
	Status        LoanStatus   `json:"status"`
	LastUpdated   time.Time    `json:"last_updated"`
	NextDueDate   time.Time    `json:"next_due_date"`
	PaymentHistory []Payment   `json:"payment_history"`
	Collateral    Collateral   `json:"collateral"`
	Notifications []Notification `json:"notifications"`
}

type Loan struct {
    ID            string
    Borrower      string
    Amount        float64
    InterestRate  float64
    Term          int // in months
    StartDate     time.Time
    EndDate       time.Time
    Status        LoanStatus
    RepaymentPlan []Repayment
    Collateral    []Collateral
}

type Repayment struct {
    DueDate  time.Time
    Amount   float64
    Paid     bool
    PaidDate *time.Time
}

type Collateral struct {
    ID          string
    Type        string
    Value       float64
    Owner       string
    IsSecured   bool
    SecuredDate *time.Time
}

type LoanMonitor struct {
    Loans []Loan
}

type LoanStatus string

// LoanReplicationService handles the replication of loans within the LoanPool.
type LoanReplicationService struct {
	BlockchainClient blockchain.Client
	CryptoService    crypto.Service
}

// LoanRescheduling contains information about loan rescheduling
type LoanRescheduling struct {
    LoanID            string
    OriginalSchedule  RepaymentSchedule
    NewSchedule       RepaymentSchedule
    RescheduleDate    time.Time
    Reason            string
    Approved          bool
    ApprovalTimestamp time.Time
}

// RepaymentSchedule defines the structure for repayment plans
type RepaymentSchedule struct {
    PaymentDates   []time.Time
    PaymentAmounts []*big.Int
}

type LoanSettlement struct {
	LoanID           string
	BorrowerID       string
	LenderID         string
	Amount           float64
	InterestRate     float64
	Duration         time.Duration
	StartDate        time.Time
	EndDate          time.Time
	RepaymentSchedule map[time.Time]float64
	Collateral       []collateral_management.Collateral
}

// LoanStatus defines possible statuses for a loan.
type LoanStatus string

// Loan represents a loan in the system.
type Loan struct {
	ID                string
	BorrowerID        string
	Amount            float64
	InterestRate      float64
	Term              int // in months
	Status            LoanStatus
	ApprovalDate      *time.Time
	DisbursementDate  *time.Time
	RepaymentSchedule []Repayment
	Collateral        string
}

// Repayment represents a repayment transaction.
type Repayment struct {
	ID        string
	LoanID    string
	Amount    float64
	Date      time.Time
	IsPartial bool
}

// AutomatedLoanManagement manages the lifecycle of loans.
type AutomatedLoanManagement struct {
	loans      map[string]*Loan
	repayments map[string][]Repayment
	mu         sync.Mutex
}

// LoanCalculationService provides methods for calculating loan parameters.
type LoanCalculationService struct {
	mu sync.Mutex
}

// NotificationType defines the type of notification.
type NotificationType string


// Notification represents a notification to be sent to the user.
type Notification struct {
	ID          string
	UserID      string
	Type        NotificationType
	Message     string
	Timestamp   time.Time
	IsRead      bool
	Channel     string // e.g., email, SMS, in-app
}

// UserPreferences represents the notification preferences for a user.
type UserPreferences struct {
	UserID           string
	PreferredChannel string // e.g., email, SMS, in-app
	AlertFrequency   string // e.g., immediate, daily digest, weekly summary
	NotificationTypes map[NotificationType]bool
}

// NotificationService manages sending notifications to users.
type NotificationService struct {
	mu              sync.Mutex
	notifications   map[string][]Notification
	userPreferences map[string]UserPreferences
}

// AuditRecord represents a record of an audit event.
type AuditRecord struct {
	ID          string
	Timestamp   time.Time
	Action      string
	PerformedBy string
	Details     string
}

// Auditor represents an entity that performs audits.
type Auditor struct {
	ID   string
	Name string
	Role string
}

// LoanServiceAudits manages the auditing of loan services.
type LoanServiceAudits struct {
	auditRecords []AuditRecord
	auditors     map[string]Auditor
	mu           sync.Mutex
}

// LoanServiceMonitoring handles the monitoring of loan services, including performance tracking, anomaly detection, and real-time alerts.
type LoanServiceMonitoring struct {
	loanPerformance map[string]LoanPerformance
	anomalies       map[string]Anomaly
	alerts          map[string][]Alert
	mu              sync.Mutex
}

// LoanPerformance represents the performance metrics of a loan.
type LoanPerformance struct {
	LoanID               string
	BorrowerID           string
	TotalRepayments      float64
	MissedRepayments     int
	LastRepaymentDate    time.Time
	NextRepaymentDate    time.Time
	ExpectedRepayments   float64
	PerformanceIndicator float64
}

// Anomaly represents detected anomalies in the loan service.
type Anomaly struct {
	ID          string
	LoanID      string
	Description string
	DetectedAt  time.Time
	Resolved    bool
}

// Alert represents real-time alerts sent to users.
type Alert struct {
	ID        string
	UserID    string
	Message   string
	Timestamp time.Time
	Read      bool
}

// LoanServiceReporting manages the generation and distribution of reports related to loan services.
type LoanServiceReporting struct {
	reportData []ReportData
	mu         sync.Mutex
}

// ReportData represents the data structure for a single report entry.
type ReportData struct {
	ID            string
	Timestamp     time.Time
	ReportType    string
	GeneratedBy   string
	Details       string
	FilePath      string
}

// EducationGrant represents an education grant within the LoanPool module.
type EducationGrant struct {
	ID           string
	ApplicantID  string
	Amount       float64
	Purpose      string
	Status       string
	SubmissionDate time.Time
	ApprovalDate  *time.Time
	DisbursementDate *time.Time
	Reports      []ProgressReport
}

// ProgressReport represents a report on the progress of the grant usage.
type ProgressReport struct {
	ID        string
	GrantID   string
	ReportDate time.Time
	Content   string
}

// EducationGrantManager manages the lifecycle of education grants.
type EducationGrantManager struct {
	grants     map[string]*EducationGrant
	reports    map[string][]ProgressReport
	mu         sync.Mutex
}

// GrantLoan represents a grant loan type within the LoanPool
type GrantLoan struct {
    GrantID         string
    ProposalID      string
    Amount          float64
    Recipient       string
    Status          string
    DisbursementDate time.Time
    ReportingDue    time.Time
    Reports         []string
}

// LoanRelease represents the structure for handling loan release processes
type LoanRelease struct {
    LoanID           string
    BorrowerID       string
    Amount           float64
    DisbursementDate time.Time
    RepaymentPlan    RepaymentPlan
    Status           string
    CollateralID     string
}

// RepaymentPlan represents the structure of the repayment plan
type RepaymentPlan struct {
    Schedule  []RepaymentSchedule
    TotalPaid float64
}

// RepaymentSchedule represents individual repayment schedule
type RepaymentSchedule struct {
    DueDate  time.Time
    Amount   float64
    Paid     bool
    PaidDate time.Time
}

// LoanPool represents the structure for managing the loan pool
type LoanPool struct {
    PoolID           string
    Loans            map[string]*Loan
    Governance       Governance
    Securitization   Securitization
    Notifications    NotificationSystem
}

// Loan represents the common structure for different types of loans
type Loan struct {
    LoanID           string
    BorrowerID       string
    Amount           float64
    DisbursementDate time.Time
    RepaymentPlan    RepaymentPlan
    Status           string
    CollateralID     string
}

// RepaymentPlan represents the structure of the repayment plan
type RepaymentPlan struct {
    Schedule  []RepaymentSchedule
    TotalPaid float64
}

// RepaymentSchedule represents individual repayment schedule
type RepaymentSchedule struct {
    DueDate  time.Time
    Amount   float64
    Paid     bool
    PaidDate time.Time
}

// Governance represents the governance structure of the LoanPool
type Governance struct {
    Proposals map[string]Proposal
}

// Proposal represents a proposal submitted for governance
type Proposal struct {
    ProposalID   string
    Description  string
    Submitter    string
    VotesFor     int
    VotesAgainst int
    Status       string
}

// Securitization represents the structure for loan securitization
type Securitization struct {
    TokenizedLoans map[string]TokenizedLoan
}

// TokenizedLoan represents a tokenized loan
type TokenizedLoan struct {
    TokenID   string
    LoanID    string
    Fraction  float64
    Owner     string
    MarketValue float64
}

// NotificationSystem represents the structure for managing notifications
type NotificationSystem struct {
    Subscribers map[string][]Notification
}

// Notification represents an individual notification
type Notification struct {
    NotificationID string
    Type           string
    Message        string
    Timestamp      time.Time
}

// PovertyLoan represents the structure for poverty alleviation loans
type PovertyLoan struct {
	LoanID           string
	BorrowerID       string
	Amount           float64
	DisbursementDate time.Time
	Status           string
	Grant            bool
}

// PovertyFund represents the fund allocated for poverty alleviation
type PovertyFund struct {
	FundID          string
	TotalAllocation float64
	RemainingAmount float64
}

// Proposal represents a loan or grant proposal
type Proposal struct {
	ProposalID       string
	ProposerID       string
	Type             string // loan or grant
	Amount           float64
	SubmittedDate    time.Time
	Status           string
	Votes            int
	RequiredVotes    int
	ApprovalDate     time.Time
}

// ProposalManagement manages proposals within the LoanPool
type ProposalManagement struct {
	Proposals []Proposal
}

// SecuredLoan represents a loan that is backed by collateral
type SecuredLoan struct {
	LoanID         string
	BorrowerID     string
	Amount         float64
	Collateral     string
	CollateralType string
	InterestRate   float64
	StartDate      time.Time
	EndDate        time.Time
	Status         string
	Repayments     []Repayment
}

// Repayment represents a repayment transaction for a loan
type Repayment struct {
	RepaymentID string
	Amount      float64
	Date        time.Time
	Status      string
}

// SecuredLoanManagement manages secured loans
type SecuredLoanManagement struct {
	Loans []SecuredLoan
}

// SmallBusinessGrant represents a small business grant within the LoanPool module.
type SmallBusinessGrant struct {
	ID             string
	ApplicantID    string
	BusinessName   string
	Amount         float64
	Purpose        string
	Status         string
	SubmissionDate time.Time
	ApprovalDate   *time.Time
	DisbursementDate *time.Time
	Reports        []ProgressReport
}

// ProgressReport represents a report on the progress of the grant usage.
type ProgressReport struct {
	ID         string
	GrantID    string
	ReportDate time.Time
	Content    string
}

// SmallBusinessGrantManager manages the lifecycle of small business grants.
type SmallBusinessGrantManager struct {
	grants  map[string]*SmallBusinessGrant
	reports map[string][]ProgressReport
	mu      sync.Mutex
}

// EcosystemGrantType represents a grant for ecosystem innovation projects.
type EcosystemGrantType struct {
	ID          string
	Applicant   identity.User
	Proposal    Proposal
	Amount      *big.Int
	Status      GrantStatus
	CreatedAt   time.Time
	UpdatedAt   time.Time
	ApprovedBy  []identity.Node
	mutex       sync.Mutex
}

// Proposal represents the details of a grant proposal.
type Proposal struct {
	Title       string
	Description string
	Justification string
	RequestedAmount *big.Int
	SubmitterID string
	Votes       map[string]bool
}

// GrantStatus represents the status of a grant.
type GrantStatus string

// UnsecuredLoanType represents an unsecured loan in the system.
type UnsecuredLoanType struct {
	ID             string
	Borrower       identity.User
	Proposal       Proposal
	Amount         *big.Int
	InterestRate   float64
	RepaymentTerms RepaymentTerms
	Status         LoanStatus
	CreatedAt      time.Time
	UpdatedAt      time.Time
	ApprovedBy     []identity.Node
	mutex          sync.Mutex
}

// Proposal represents the details of a loan proposal.
type Proposal struct {
	Title           string
	Description     string
	Justification   string
	RequestedAmount *big.Int
	SubmitterID     string
	Votes           map[string]bool
}

// RepaymentTerms represents the terms for loan repayment.
type RepaymentTerms struct {
	Duration      time.Duration
	PaymentAmount *big.Int
	PaymentDue    time.Time
}

// LoanStatus represents the status of a loan.
type LoanStatus string

// ApprovalWorkflow represents the workflow for loan approvals
type ApprovalWorkflow struct {
	ID            string
	ProposalID    string
	SubmittedBy   identity.User
	Status        string
	CreatedAt     time.Time
	UpdatedAt     time.Time
	Votes         map[string]bool // nodeID -> vote
	RequiredVotes int
}



// User represents a user in the system
type User struct {
	ID    string
	Name  string
	Email string
}

// Proposal represents a loan proposal in the system
type Proposal struct {
	ID            string
	Title         string
	Description   string
	Amount        float64
	ProposerID    string
	Status        string
	SubmissionDate time.Time
	Votes         map[string]bool // NodeID to vote (true for approve, false for reject)
	Approvals     int
	Rejections    int
}

// Node represents a governance node
type Node struct {
	ID       string
	IsAuthority bool
	Weight   int
}

// PovertyProcess defines the structure for the poverty alleviation process.
type PovertyProcess struct {
	PovertyFund          float64
	ProposalList         []PovertyProposal
	ApprovedProposals    []PovertyProposal
	PendingProposals     []PovertyProposal
	RejectedProposals    []PovertyProposal
}

// PovertyProposal defines the structure of a proposal for poverty alleviation grants.
type PovertyProposal struct {
	ProposalID       string
	Applicant        identity.User
	AmountRequested  float64
	Purpose          string
	SubmissionDate   time.Time
	Status           string
	VotingResults    map[string]bool
}

type Proposal struct {
    ID             string
    Title          string
    Description    string
    SubmittedBy    string
    SubmissionDate time.Time
    Status         string
    Votes          map[string]bool
}

type ApprovalWorkflow struct {
    Proposals       map[string]Proposal
    VotingSystem    voting.VotingSystem
    NotificationSys notifications.NotificationSystem
    Blockchain      blockchain.Blockchain
    Security        security.SecurityManager
    Users           users.UserManager
}

// ReviewMechanisms struct to hold review mechanisms data
type ReviewMechanisms struct {
	ProposalID   string    `json:"proposal_id"`
	ReviewerID   string    `json:"reviewer_id"`
	Comments     string    `json:"comments"`
	Status       string    `json:"status"`
	Timestamp    time.Time `json:"timestamp"`
}

// SecuredLoanProcess represents the process for managing secured loans.
type SecuredLoanProcess struct {
	loanID            string
	borrowerID        string
	collateral        loanpool.Collateral
	loanAmount        float64
	repaymentSchedule loan_management.RepaymentSchedule
	status            loanpool.LoanStatus
}

// SynnergyEcosystemProcess represents the process for handling ecosystem innovation within the Synnergy network.
type SynnergyEcosystemProcess struct {
	blockchain   *blockchain.Blockchain
	cryptoEngine crypto.CryptoEngine
}

// UnsecuredLoanProcess represents the process for handling unsecured loans within the Synnergy network.
type UnsecuredLoanProcess struct {
	blockchain   *blockchain.Blockchain
	cryptoEngine crypto.CryptoEngine
}

// AuthorityNodeGovernance manages the operations and governance functions of various authority nodes within the Synnergy Network.
type AuthorityNodeGovernance struct {
	blockchain   *blockchain.Blockchain
	cryptoEngine crypto.CryptoEngine
}

// NodeType represents the different types of authority nodes.
type AuthorityNodeType string

// DecentralizedDisputeResolution handles the resolution of disputes within the Synnergy Network using decentralized mechanisms.
type DecentralizedDisputeResolution struct {
	blockchain   *blockchain.Blockchain
	cryptoEngine crypto.CryptoEngine
}

// Dispute represents a dispute within the Synnergy Network.
type Dispute struct {
	ID            string
	ComplainantID string
	DefendantID   string
	Description   string
	Status        string
	Votes         []Vote
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

// Vote represents a vote on a dispute.
type Vote struct {
	NodeID   string
	Decision string
	Timestamp time.Time
}

// GovernanceAudit represents the auditing processes for governance activities within the Synnergy Network.
type GovernanceAudit struct {
	blockchain *blockchain.Blockchain
}

// AuditLog represents a log entry for governance activities.
type AuditLog struct {
	ID        string
	Timestamp time.Time
	Action    string
	NodeID    string
	Details   string
}

// GovernanceDashboard provides a real-time interface for tracking and managing governance activities.
type GovernanceDashboard struct {
	blockchain *blockchain.Blockchain
}

// DashboardItem represents a single item on the governance dashboard.
type DashboardItem struct {
	ID          string
	Type        string
	Description string
	Status      string
	Timestamp   time.Time
}

// GovernanceMonitoring provides a comprehensive system for monitoring governance activities in the Synnergy Network.
type GovernanceMonitoring struct {
	blockchain *blockchain.Blockchain
}

// MonitoringItem represents a single item to be monitored in the governance system.
type MonitoringItem struct {
	ID          string
	Type        string
	Description string
	Status      string
	Timestamp   time.Time
}

// ReportType defines types of reports generated in the system
type ReportType string

// GovernanceReport represents a governance report
type GovernanceReport struct {
    ID          string    `json:"id"`
    ReportType  ReportType `json:"report_type"`
    CreatedAt   time.Time `json:"created_at"`
    Data        string    `json:"data"`
    NodeID      string    `json:"node_id"`
    Verified    bool      `json:"verified"`
    VerifierID  string    `json:"verifier_id"`
    Signature   string    `json:"signature"`
}

// ProposalStatus represents the status of a proposal
type ProposalStatus int

// Proposal represents a governance proposal
type Proposal struct {
    ID          string
    Title       string
    Description string
    Proposer    string
    Timestamp   time.Time
    Status      ProposalStatus
    Votes       map[string]bool // key: voter ID, value: vote (true for yes, false for no)
    YesVotes    int
    NoVotes     int
}

type Proposal struct {
    ID            string
    Title         string
    Description   string
    Status        string
    CreatedAt     time.Time
    VotingDeadline time.Time
    Votes         map[string]int
    Voters        map[string]bool
}

type Voter struct {
    ID       string
    NodeType string
    Stake    int
}

type VotingSystem struct {
    Proposals      map[string]*Proposal
    Voters         map[string]*Voter
    mu             sync.Mutex
    quorumRequired int
}

// Notification represents a notification message
type Notification struct {
    UserID      string
    Type        string
    Message     string
    Timestamp   time.Time
}

// NotificationSystem represents the notification system
type NotificationSystem struct {
    storage         storage.Storage
    encryption      encryption.Encryption
    notificationSvc notifications.Service
}

// Notification represents a user notification
type Notification struct {
    ID          string    `json:"id"`
    UserID      string    `json:"user_id"`
    Type        string    `json:"type"`
    Message     string    `json:"message"`
    Timestamp   time.Time `json:"timestamp"`
    IsRead      bool      `json:"is_read"`
}

// UserPreferences represents user notification preferences
type UserPreferences struct {
    UserID         string `json:"user_id"`
    EmailEnabled   bool   `json:"email_enabled"`
    SMSEnabled     bool   `json:"sms_enabled"`
    InAppEnabled   bool   `json:"in_app_enabled"`
    Frequency      string `json:"frequency"`
    SecurityAlerts bool   `json:"security_alerts"`
}

// NotificationService handles notification monitoring and delivery
type NotificationService struct {
    notifications    map[string]Notification
    userPreferences  map[string]UserPreferences
    aesKey           []byte
}

// NotificationPreferences stores the user's preferences for notifications.
type NotificationPreferences struct {
	UserID                   string
	ReceiveEmail             bool
	ReceiveSMS               bool
	ReceiveInApp             bool
	Email                    string
	PhoneNumber              string
	PreferredLanguage        string
	NotificationFrequency    string
	NotificationTypes        []string
	EncryptedCommunicationKey string
	mu                       sync.Mutex
}

// NotificationReport represents a report of notifications for auditing and analysis.
type NotificationReport struct {
	ID           string
	UserID       string
	Timestamp    time.Time
	NotificationType string
	Status       string
	Content      string
}

// NotificationReporting manages the creation and storage of notification reports.
type NotificationReporting struct {
	reports map[string]NotificationReport
	mu      sync.Mutex
}

// NotificationAnalytics provides analytics and insights on notification data.
type NotificationAnalytics struct {
	reporting *NotificationReporting
}

// NotificationSecurity manages the encryption and decryption of notifications.
type NotificationSecurity struct {
	mu sync.Mutex
}

// NotificationPreferences holds user preferences securely.
type NotificationPreferences struct {
	UserID                string
	ReceiveEmail          bool
	ReceiveSMS            bool
	ReceiveInApp          bool
	Email                 string
	PhoneNumber           string
	PreferredLanguage     string
	NotificationFrequency string
	NotificationTypes     []string
	EncryptedKey          string
}

// RealTimeAlerts manages the real-time alert notifications.
type RealTimeAlerts struct {
	subscribers map[string]Subscriber
	mu          sync.Mutex
}

// Subscriber represents a user subscribed to real-time alerts.
type Subscriber struct {
	UserID          string
	Email           string
	PhoneNumber     string
	InAppID         string
	PreferredMethod string // "email", "sms", "inapp"
}

// AlertData represents the data structure of an alert.
type AlertData struct {
	UserID  string
	Type    string
	Message string
	Time    time.Time
}

// EventHandler manages event-based alerts.
type EventHandler struct {
	realTimeAlerts *RealTimeAlerts
}

// AffordabilityChecks struct to hold necessary data for affordability check process
type AffordabilityChecks struct {
	UserID            string
	LoanAmount        float64
	LoanTermMonths    int
	UserIncome        float64
	UserDebts         float64
	UserExpenses      float64
	Dependents        int
	DependentExpenses float64
	AdvisoryLimit     float64
}

// AI models and machine learning tools
type RiskAnalysisAI struct {
	model models.AIModel
}

// AIDrivenRiskAnalysis is the structure for AI-driven risk analysis of loan applications.
type AIDrivenRiskAnalysis struct {
	UserID              string
	UserIncome          float64
	UserDebts           float64
	UserExpenses        float64
	Dependents          int
	DependentExpenses   float64
	PreviousLoanHistory []LoanHistory
	CreditScore         int
	RiskScore           float64
	MaxLoanAmount       float64
}

// LoanHistory represents the user's previous loan records.
type LoanHistory struct {
	LoanID     string
	Amount     float64
	Repaid     bool
	RepaymentDate time.Time
	Defaulted  bool
}

// RiskAudit represents the audit structure for risk assessment
type RiskAudit struct {
	ID           string
	LoanID       string
	AuditDate    time.Time
	Auditor      string
	Findings     string
	Recommendations string
	Status       string
	Verified     bool
}

// RiskAuditor handles risk auditing operations
type RiskAuditor struct {
	audits []RiskAudit
}

// RiskEvaluation struct represents the structure for risk evaluation.
type RiskEvaluation struct {
	loanAmount       float64
	interestRate     float64
	loanTerm         int
	borrowerIncome   float64
	borrowerDebts    float64
	borrowerExpenses float64
	dependents       int
	dependentExpenses float64
	creditScore      int
	collateralValue  float64
	collateralType   string
	createdAt        time.Time
	updatedAt        time.Time
}

// AIDrivenRiskAnalysis performs AI-driven risk analysis on loan applications.
type AIDrivenRiskAnalysis struct {
	aiModel utils.AIModel
}

// RiskReport contains information about the risk assessment report.
type RiskReport struct {
	ID                string    `json:"id"`
	BorrowerID        string    `json:"borrower_id"`
	LoanID            string    `json:"loan_id"`
	ReportDetails     string    `json:"report_details"`
	RiskScore         float64   `json:"risk_score"`
	GeneratedAt       time.Time `json:"generated_at"`
}

// RiskReportingService handles the generation and management of risk reports.
type RiskReportingService struct {
	Storage          storage.Storage
	NotificationSvc  notifications.NotificationService
	EncryptionKey    string
}

// FraudDetectionService manages the detection and prevention of fraud in the loan pool.
type FraudDetectionService struct {
	mutex   sync.Mutex
	enabled bool
}

// SecurityAuditService manages security audits within the LoanPool module.
type SecurityAuditService struct {
	mutex   sync.Mutex
	enabled bool
}

// SecurityMonitoringService manages the continuous monitoring of the system for security threats.
type SecurityMonitoringService struct {
	mutex   sync.Mutex
	enabled bool
}

// SecurityReport contains the details of the security report.
type SecurityReport struct {
	Timestamp        time.Time `json:"timestamp"`
	NodeID           string    `json:"node_id"`
	IncidentType     string    `json:"incident_type"`
	IncidentDetails  string    `json:"incident_details"`
	ImpactAssessment string    `json:"impact_assessment"`
	ResolutionStatus string    `json:"resolution_status"`
	ReportedBy       string    `json:"reported_by"`
}

// SecurityReportingService manages the creation and dissemination of security reports.
type SecurityReportingService struct {
	storage storage.Storage
}

// SmartContractSecurityService manages the security aspects of smart contracts in the Synnergy Network.
type SmartContractSecurityService struct {
	storage storage.Storage
}

// SmartContractAudit represents the details of a smart contract audit.
type SmartContractAudit struct {
	Timestamp       time.Time `json:"timestamp"`
	ContractAddress string    `json:"contract_address"`
	IssuesFound     []string  `json:"issues_found"`
	Severity        string    `json:"severity"`
	Resolved        bool      `json:"resolved"`
}

// BusinessPersonalGrantFund represents a grant for business or personal initiatives.
type BusinessPersonalGrantFund struct {
	ID           string
	Applicant    identity.User
	Proposal     Proposal
	Amount       *big.Int
	Status       GrantStatus
	CreatedAt    time.Time
	UpdatedAt    time.Time
	ApprovedBy   []identity.Node
	Progress     ProgressReport
	mutex        sync.Mutex
}

// Proposal represents the details of a grant proposal.
type Proposal struct {
	Title           string
	Description     string
	Justification   string
	RequestedAmount *big.Int
	SubmitterID     string
	Votes           map[string]bool
}

// ProgressReport represents the progress report of the funded project.
type ProgressReport struct {
	MilestonesAchieved []string
	FundsUtilized      *big.Int
	LastUpdated        time.Time
}

// GrantStatus represents the status of a grant.
type GrantStatus string

// EcosystemInnovationFundGrant represents a grant for ecosystem innovation projects.
type EcosystemInnovationFundGrant struct {
	ID           string
	Applicant    identity.User
	Proposal     Proposal
	Amount       *big.Int
	Status       GrantStatus
	CreatedAt    time.Time
	UpdatedAt    time.Time
	ApprovedBy   []identity.Node
	Progress     ProgressReport
	mutex        sync.Mutex
}

// Proposal represents the details of a grant proposal.
type Proposal struct {
	Title           string
	Description     string
	Justification   string
	RequestedAmount *big.Int
	SubmitterID     string
	Votes           map[string]bool
}

// ProgressReport represents the progress report of the funded project.
type ProgressReport struct {
	MilestonesAchieved []string
	FundsUtilized      *big.Int
	LastUpdated        time.Time
}

// GrantStatus represents the status of a grant.
type GrantStatus string

// EducationFund represents a fund for educational initiatives.
type EducationFund struct {
	ID           string
	Applicant    identity.User
	Proposal     Proposal
	Amount       *big.Int
	Status       GrantStatus
	CreatedAt    time.Time
	UpdatedAt    time.Time
	ApprovedBy   []identity.Node
	Progress     ProgressReport
	mutex        sync.Mutex
}

// Proposal represents the details of a fund proposal.
type Proposal struct {
	Title           string
	Description     string
	Justification   string
	RequestedAmount *big.Int
	SubmitterID     string
	Votes           map[string]bool
}

// ProgressReport represents the progress report of the funded project.
type ProgressReport struct {
	MilestonesAchieved []string
	FundsUtilized      *big.Int
	LastUpdated        time.Time
}

// GrantStatus represents the status of a grant.
type GrantStatus string

// HealthcareSupportFund represents a fund for healthcare support initiatives.
type HealthcareSupportFund struct {
	ID           string
	Applicant    identity.User
	Proposal     Proposal
	Amount       *big.Int
	Status       GrantStatus
	CreatedAt    time.Time
	UpdatedAt    time.Time
	ApprovedBy   []identity.Node
	Progress     ProgressReport
	mutex        sync.Mutex
}

// Proposal represents the details of a fund proposal.
type Proposal struct {
	Title           string
	Description     string
	Justification   string
	RequestedAmount *big.Int
	SubmitterID     string
	Votes           map[string]bool
}

// ProgressReport represents the progress report of the funded project.
type ProgressReport struct {
	MilestonesAchieved []string
	FundsUtilized      *big.Int
	LastUpdated        time.Time
}

// GrantStatus represents the status of a grant.
type GrantStatus string

// PovertyFund represents a fund for poverty alleviation initiatives.
type PovertyFund struct {
	ID           string
	Applicant    identity.User
	Proposal     Proposal
	Amount       *big.Int
	Status       GrantStatus
	CreatedAt    time.Time
	UpdatedAt    time.Time
	ApprovedBy   []identity.Node
	Progress     ProgressReport
	mutex        sync.Mutex
}

// Proposal represents the details of a fund proposal.
type Proposal struct {
	Title           string
	Description     string
	Justification   string
	RequestedAmount *big.Int
	SubmitterID     string
	Votes           map[string]bool
}

// ProgressReport represents the progress report of the funded project.
type ProgressReport struct {
	MilestonesAchieved []string
	FundsUtilized      *big.Int
	LastUpdated        time.Time
}

// GrantStatus represents the status of a grant.
type GrantStatus string

// SecuredLoan represents a loan that is backed by collateral.
type SecuredLoan struct {
	ID           string
	Applicant    identity.User
	Proposal     Proposal
	Amount       *big.Int
	Collateral   Collateral
	Status       LoanStatus
	CreatedAt    time.Time
	UpdatedAt    time.Time
	ApprovedBy   []identity.Node
	Progress     ProgressReport
	mutex        sync.Mutex
}

// Proposal represents the details of a loan proposal.
type Proposal struct {
	Title           string
	Description     string
	Justification   string
	RequestedAmount *big.Int
	SubmitterID     string
	Votes           map[string]bool
}

// Collateral represents the collateral details for a secured loan.
type Collateral struct {
	Type   string
	Value  *big.Int
	Status string
}

// ProgressReport represents the progress report of the loan repayment.
type ProgressReport struct {
	MilestonesAchieved []string
	FundsUtilized      *big.Int
	LastUpdated        time.Time
}

// LoanStatus represents the status of a loan.
type LoanStatus string

// SmallBusinessSupportFund represents a fund for small and medium-sized enterprises (SMEs) support.
type SmallBusinessSupportFund struct {
	ID           string
	Applicant    identity.User
	Proposal     Proposal
	Amount       *big.Int
	Status       GrantStatus
	CreatedAt    time.Time
	UpdatedAt    time.Time
	ApprovedBy   []identity.Node
	Progress     ProgressReport
	mutex        sync.Mutex
}

// Proposal represents the details of a fund proposal.
type Proposal struct {
	Title           string
	Description     string
	Justification   string
	RequestedAmount *big.Int
	SubmitterID     string
	Votes           map[string]bool
}

// ProgressReport represents the progress report of the funded project.
type ProgressReport struct {
	MilestonesAchieved []string
	FundsUtilized      *big.Int
	LastUpdated        time.Time
}

// GrantStatus represents the status of a grant.
type GrantStatus string

// UnsecuredLoan represents a loan that does not require collateral.
type UnsecuredLoan struct {
	ID           string
	Applicant    identity.User
	Proposal     Proposal
	Amount       *big.Int
	Status       LoanStatus
	CreatedAt    time.Time
	UpdatedAt    time.Time
	ApprovedBy   []identity.Node
	Progress     ProgressReport
	mutex        sync.Mutex
}

// Proposal represents the details of a loan proposal.
type Proposal struct {
	Title           string
	Description     string
	Justification   string
	RequestedAmount *big.Int
	SubmitterID     string
	Votes           map[string]bool
}

// ProgressReport represents the progress report of the loan repayment.
type ProgressReport struct {
	MilestonesAchieved []string
	FundsUtilized      *big.Int
	LastUpdated        time.Time
}

// LoanStatus represents the status of a loan.
type LoanStatus string

