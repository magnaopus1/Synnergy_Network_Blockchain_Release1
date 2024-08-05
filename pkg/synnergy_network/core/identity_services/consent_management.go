package consent_management

import (
	"errors"
	"time"
	"github.com/google/uuid"
)


// NewAutomatedConsentEnforcer creates a new AutomatedConsentEnforcer instance
func NewAutomatedConsentEnforcer() *AutomatedConsentEnforcer {
	return &AutomatedConsentEnforcer{
		Consents:     make(map[uuid.UUID]ConsentRecord),
		Policies:     make(map[uuid.UUID]ConsentPolicy),
		UserConsents: make(map[uuid.UUID][]uuid.UUID),
	}
}

// GrantConsent grants user consent for a specific data ID and consent type
func (ace *AutomatedConsentEnforcer) GrantConsent(userID, dataID uuid.UUID, consentType string, duration time.Duration) (*ConsentRecord, error) {
	consentID := uuid.New()
	consent := ConsentRecord{
		UserID:        userID,
		DataID:        dataID,
		ConsentType:   consentType,
		GrantedAt:     time.Now(),
		ExpiresAt:     nil,
		ConsentStatus: true,
	}

	if duration > 0 {
		expiryTime := time.Now().Add(duration)
		consent.ExpiresAt = &expiryTime
	}

	ace.Consents[consentID] = consent
	ace.UserConsents[userID] = append(ace.UserConsents[userID], consentID)
	return &consent, nil
}

// RevokeConsent revokes a user's consent for a specific data ID and consent type
func (ace *AutomatedConsentEnforcer) RevokeConsent(userID, dataID uuid.UUID, consentType string) error {
	for id, consent := range ace.Consents {
		if consent.UserID == userID && consent.DataID == dataID && consent.ConsentType == consentType {
			consent.ConsentStatus = false
			ace.Consents[id] = consent
			return nil
		}
	}
	return errors.New("consent not found")
}

// CheckConsent verifies if a user has granted consent for a specific data ID and consent type
func (ace *AutomatedConsentEnforcer) CheckConsent(userID, dataID uuid.UUID, consentType string) (bool, error) {
	for _, consentID := range ace.UserConsents[userID] {
		consent := ace.Consents[consentID]
		if consent.DataID == dataID && consent.ConsentType == consentType && consent.ConsentStatus {
			if consent.ExpiresAt != nil && time.Now().After(*consent.ExpiresAt) {
				return false, errors.New("consent expired")
			}
			return true, nil
		}
	}
	return false, errors.New("consent not granted")
}

// CreatePolicy creates a new consent policy
func (ace *AutomatedConsentEnforcer) CreatePolicy(description string, requiredConsents []string) (*ConsentPolicy, error) {
	policyID := uuid.New()
	policy := ConsentPolicy{
		PolicyID:        policyID,
		Description:     description,
		RequiredConsents: requiredConsents,
	}

	ace.Policies[policyID] = policy
	return &policy, nil
}

// EnforcePolicy enforces a policy by checking all required consents
func (ace *AutomatedConsentEnforcer) EnforcePolicy(policyID, userID, dataID uuid.UUID) (bool, error) {
	policy, exists := ace.Policies[policyID]
	if !exists {
		return false, errors.New("policy not found")
	}

	for _, consentType := range policy.RequiredConsents {
		consentGranted, err := ace.CheckConsent(userID, dataID, consentType)
		if err != nil || !consentGranted {
			return false, errors.New("required consent not granted")
		}
	}
	return true, nil
}

// ListUserConsents lists all consents granted by a user
func (ace *AutomatedConsentEnforcer) ListUserConsents(userID uuid.UUID) ([]ConsentRecord, error) {
	consentIDs, exists := ace.UserConsents[userID]
	if !exists {
		return nil, errors.New("no consents found for user")
	}

	var consents []ConsentRecord
	for _, consentID := range consentIDs {
		consents = append(consents, ace.Consents[consentID])
	}
	return consents, nil
}

// RevokeExpiredConsents revokes consents that have expired
func (ace *AutomatedConsentEnforcer) RevokeExpiredConsents() {
	for id, consent := range ace.Consents {
		if consent.ExpiresAt != nil && time.Now().After(*consent.ExpiresAt) {
			consent.ConsentStatus = false
			ace.Consents[id] = consent
		}
	}
}

// NewComplianceManager creates a new ComplianceManager instance
func NewComplianceManager() *ComplianceManager {
	return &ComplianceManager{
		Rules:   make(map[uuid.UUID]ComplianceRule),
		Statuses: make(map[uuid.UUID]ComplianceStatus),
	}
}

// AddRule adds a new compliance rule to the manager
func (cm *ComplianceManager) AddRule(description string, check func(data interface{}) bool) (*ComplianceRule, error) {
	ruleID := uuid.New()
	rule := ComplianceRule{
		RuleID:      ruleID,
		Description: description,
		Check:       check,
	}
	cm.Rules[ruleID] = rule
	return &rule, nil
}

// RemoveRule removes a compliance rule from the manager
func (cm *ComplianceManager) RemoveRule(ruleID uuid.UUID) error {
	if _, exists := cm.Rules[ruleID]; !exists {
		return errors.New("rule not found")
	}
	delete(cm.Rules, ruleID)
	return nil
}

// CheckCompliance checks data against all compliance rules and records the results
func (cm *ComplianceManager) CheckCompliance(userID, dataID uuid.UUID, data interface{}) ([]ComplianceStatus, error) {
	var statuses []ComplianceStatus

	for _, rule := range cm.Rules {
		statusID := uuid.New()
		isCompliant := rule.Check(data)
		status := ComplianceStatus{
			StatusID:       statusID,
			UserID:         userID,
			DataID:         dataID,
			ComplianceType: rule.Description,
			CheckedAt:      time.Now(),
			Status:         isCompliant,
			Details:        "",
		}
		if !isCompliant {
			status.Details = "Data did not comply with rule: " + rule.Description
		}
		cm.Statuses[statusID] = status
		statuses = append(statuses, status)
	}

	return statuses, nil
}

// GetComplianceStatus retrieves the compliance status by ID
func (cm *ComplianceManager) GetComplianceStatus(statusID uuid.UUID) (*ComplianceStatus, error) {
	status, exists := cm.Statuses[statusID]
	if !exists {
		return nil, errors.New("compliance status not found")
	}
	return &status, nil
}

// ListUserComplianceStatuses lists all compliance statuses for a user
func (cm *ComplianceManager) ListUserComplianceStatuses(userID uuid.UUID) ([]ComplianceStatus, error) {
	var statuses []ComplianceStatus
	for _, status := range cm.Statuses {
		if status.UserID == userID {
			statuses = append(statuses, status)
		}
	}
	return statuses, nil
}

// HashData hashes data for integrity verification using SHA-256
func HashData(data []byte) [32]byte {
	return sha256.Sum256(data)
}

// VerifyDataIntegrity verifies the integrity of data against a given hash
func VerifyDataIntegrity(data []byte, expectedHash [32]byte) bool {
	return HashData(data) == expectedHash
}

// CompliancePolicyManager manages compliance policies and their enforcement
type CompliancePolicyManager struct {
	Policies map[uuid.UUID]CompliancePolicy
}

// CompliancePolicy represents a compliance policy with a set of rules
type CompliancePolicy struct {
	PolicyID uuid.UUID
	Name     string
	Rules    []uuid.UUID
}

// NewCompliancePolicyManager creates a new CompliancePolicyManager instance
func NewCompliancePolicyManager() *CompliancePolicyManager {
	return &CompliancePolicyManager{
		Policies: make(map[uuid.UUID]CompliancePolicy),
	}
}

// CreatePolicy creates a new compliance policy
func (cpm *CompliancePolicyManager) CreatePolicy(name string, ruleIDs []uuid.UUID) (*CompliancePolicy, error) {
	policyID := uuid.New()
	policy := CompliancePolicy{
		PolicyID: policyID,
		Name:     name,
		Rules:    ruleIDs,
	}
	cpm.Policies[policyID] = policy
	return &policy, nil
}

// RemovePolicy removes a compliance policy
func (cpm *CompliancePolicyManager) RemovePolicy(policyID uuid.UUID) error {
	if _, exists := cpm.Policies[policyID]; !exists {
		return errors.New("policy not found")
	}
	delete(cpm.Policies, policyID)
	return nil
}

// EnforcePolicy enforces a compliance policy on data
func (cpm *CompliancePolicyManager) EnforcePolicy(policyID, userID, dataID uuid.UUID, data interface{}, cm *ComplianceManager) ([]ComplianceStatus, error) {
	policy, exists := cpm.Policies[policyID]
	if !exists {
		return nil, errors.New("policy not found")
	}

	var statuses []ComplianceStatus
	for _, ruleID := range policy.Rules {
		rule, exists := cm.Rules[ruleID]
		if !exists {
			continue
		}
		statusID := uuid.New()
		isCompliant := rule.Check(data)
		status := ComplianceStatus{
			StatusID:       statusID,
			UserID:         userID,
			DataID:         dataID,
			ComplianceType: rule.Description,
			CheckedAt:      time.Now(),
			Status:         isCompliant,
			Details:        "",
		}
		if !isCompliant {
			status.Details = "Data did not comply with rule: " + rule.Description
		}
		cm.Statuses[statusID] = status
		statuses = append(statuses, status)
	}

	return statuses, nil
}

// ComplianceAuditManager manages compliance audits
type ComplianceAuditManager struct {
	Audits map[uuid.UUID]ComplianceAudit
}

// ComplianceAudit represents a compliance audit
type ComplianceAudit struct {
	AuditID      uuid.UUID
	PolicyID     uuid.UUID
	UserID       uuid.UUID
	DataID       uuid.UUID
	AuditResults []ComplianceStatus
	AuditedAt    time.Time
}

// NewComplianceAuditManager creates a new ComplianceAuditManager instance
func NewComplianceAuditManager() *ComplianceAuditManager {
	return &ComplianceAuditManager{
		Audits: make(map[uuid.UUID]ComplianceAudit),
	}
}

// ConductAudit conducts a compliance audit based on a policy
func (cam *ComplianceAuditManager) ConductAudit(policyID, userID, dataID uuid.UUID, data interface{}, cm *ComplianceManager, cpm *CompliancePolicyManager) (*ComplianceAudit, error) {
	auditID := uuid.New()
	statuses, err := cpm.EnforcePolicy(policyID, userID, dataID, data, cm)
	if err != nil {
		return nil, err
	}

	audit := ComplianceAudit{
		AuditID:      auditID,
		PolicyID:     policyID,
		UserID:       userID,
		DataID:       dataID,
		AuditResults: statuses,
		AuditedAt:    time.Now(),
	}
	cam.Audits[auditID] = audit
	return &audit, nil
}

// GetAudit retrieves an audit by ID
func (cam *ComplianceAuditManager) GetAudit(auditID uuid.UUID) (*ComplianceAudit, error) {
	audit, exists := cam.Audits[auditID]
	if !exists {
		return nil, errors.New("audit not found")
	}
	return &audit, nil
}

// ListAudits lists all audits for a specific user
func (cam *ComplianceAuditManager) ListAudits(userID uuid.UUID) ([]ComplianceAudit, error) {
	var audits []ComplianceAudit
	for _, audit := range cam.Audits {
		if audit.UserID == userID {
			audits = append(audits, audit)
		}
	}
	return audits, nil
}

// NewConsentLedger creates a new ConsentLedger instance
func NewConsentLedger() *ConsentLedger {
	return &ConsentLedger{
		records: make(map[uuid.UUID]ConsentRecord),
	}
}

// GrantConsent adds a new consent record to the ledger
func (cl *ConsentLedger) GrantConsent(userID, dataID uuid.UUID, consentType string, duration time.Duration) (*ConsentRecord, error) {
	id := uuid.New()
	now := time.Now()
	record := ConsentRecord{
		ID:            id,
		UserID:        userID,
		DataID:        dataID,
		ConsentType:   consentType,
		GrantedAt:     now,
		ConsentStatus: true,
	}
	if duration > 0 {
		expiry := now.Add(duration)
		record.ExpiresAt = &expiry
	}
	record.Hash = record.calculateHash()
	cl.records[id] = record
	return &record, nil
}

// RevokeConsent revokes an existing consent record
func (cl *ConsentLedger) RevokeConsent(id uuid.UUID) error {
	record, exists := cl.records[id]
	if !exists {
		return errors.New("consent record not found")
	}
	record.ConsentStatus = false
	record.Hash = record.calculateHash()
	cl.records[id] = record
	return nil
}

// CheckConsent checks if a consent is valid
func (cl *ConsentLedger) CheckConsent(userID, dataID uuid.UUID, consentType string) (bool, error) {
	for _, record := range cl.records {
		if record.UserID == userID && record.DataID == dataID && record.ConsentType == consentType && record.ConsentStatus {
			if record.ExpiresAt != nil && time.Now().After(*record.ExpiresAt) {
				return false, errors.New("consent expired")
			}
			return true, nil
		}
	}
	return false, errors.New("consent not granted")
}

// ListConsents lists all consents for a user
func (cl *ConsentLedger) ListConsents(userID uuid.UUID) ([]ConsentRecord, error) {
	var consents []ConsentRecord
	for _, record := range cl.records {
		if record.UserID == userID {
			consents = append(consents, record)
		}
	}
	return consents, nil
}

// RevokeExpiredConsents revokes all expired consents
func (cl *ConsentLedger) RevokeExpiredConsents() {
	for id, record := range cl.records {
		if record.ExpiresAt != nil && time.Now().After(*record.ExpiresAt) {
			record.ConsentStatus = false
			record.Hash = record.calculateHash()
			cl.records[id] = record
		}
	}
}

// calculateHash generates a hash for the consent record
func (cr *ConsentRecord) calculateHash() string {
	data, _ := json.Marshal(cr)
	hash := sha256.Sum256(data)
	return string(hash[:])
}

// VerifyIntegrity checks the integrity of a consent record
func (cr *ConsentRecord) VerifyIntegrity() bool {
	return cr.Hash == cr.calculateHash()
}

// FindRecordByID retrieves a consent record by its ID
func (cl *ConsentLedger) FindRecordByID(id uuid.UUID) (*ConsentRecord, error) {
	record, exists := cl.records[id]
	if !exists {
		return nil, errors.New("consent record not found")
	}
	return &record, nil
}

// UpdateConsent updates an existing consent record
func (cl *ConsentLedger) UpdateConsent(id uuid.UUID, newType string, newDuration time.Duration) (*ConsentRecord, error) {
	record, exists := cl.records[id]
	if !exists {
		return nil, errors.New("consent record not found")
	}
	record.ConsentType = newType
	if newDuration > 0 {
		expiry := time.Now().Add(newDuration)
		record.ExpiresAt = &expiry
	} else {
		record.ExpiresAt = nil
	}
	record.Hash = record.calculateHash()
	cl.records[id] = record
	return &record, nil
}

// AuditConsentRecords audits all consent records for integrity and validity
func (cl *ConsentLedger) AuditConsentRecords() ([]ConsentRecord, error) {
	var invalidRecords []ConsentRecord
	for _, record := range cl.records {
		if !record.VerifyIntegrity() || (record.ExpiresAt != nil && time.Now().After(*record.ExpiresAt)) {
			invalidRecords = append(invalidRecords, record)
		}
	}
	return invalidRecords, nil
}

// NewConsentPolicyManager creates a new ConsentPolicyManager
func NewConsentPolicyManager() *ConsentPolicyManager {
	return &ConsentPolicyManager{
		policies: make(map[uuid.UUID]ConsentPolicy),
	}
}

// CreatePolicy creates a new consent policy
func (cpm *ConsentPolicyManager) CreatePolicy(name, description string, rules []PolicyRule) (*ConsentPolicy, error) {
	policyID := uuid.New()
	now := time.Now()
	policy := ConsentPolicy{
		PolicyID:    policyID,
		Name:        name,
		Description: description,
		Rules:       rules,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	policy.Hash = calculateHash(policy)
	cpm.policies[policyID] = policy
	return &policy, nil
}

// UpdatePolicy updates an existing consent policy
func (cpm *ConsentPolicyManager) UpdatePolicy(policyID uuid.UUID, name, description string, rules []PolicyRule) (*ConsentPolicy, error) {
	policy, exists := cpm.policies[policyID]
	if !exists {
		return nil, errors.New("policy not found")
	}
	policy.Name = name
	policy.Description = description
	policy.Rules = rules
	policy.UpdatedAt = time.Now()
	policy.Hash = calculateHash(policy)
	cpm.policies[policyID] = policy
	return &policy, nil
}

// GetPolicy retrieves a consent policy by ID
func (cpm *ConsentPolicyManager) GetPolicy(policyID uuid.UUID) (*ConsentPolicy, error) {
	policy, exists := cpm.policies[policyID]
	if !exists {
		return nil, errors.New("policy not found")
	}
	return &policy, nil
}

// DeletePolicy deletes a consent policy
func (cpm *ConsentPolicyManager) DeletePolicy(policyID uuid.UUID) error {
	if _, exists := cpm.policies[policyID]; !exists {
		return errors.New("policy not found")
	}
	delete(cpm.policies, policyID)
	return nil
}

// ListPolicies lists all consent policies
func (cpm *ConsentPolicyManager) ListPolicies() []ConsentPolicy {
	var policies []ConsentPolicy
	for _, policy := range cpm.policies {
		policies = append(policies, policy)
	}
	return policies
}

// EvaluatePolicy evaluates a consent policy against given attributes
func (cpm *ConsentPolicyManager) EvaluatePolicy(policyID uuid.UUID, attributes map[string]interface{}) (bool, error) {
	policy, exists := cpm.policies[policyID]
	if !exists {
		return false, errors.New("policy not found")
	}
	for _, rule := range policy.Rules {
		value, exists := attributes[rule.Attribute]
		if !exists {
			return false, nil
		}
		if !evaluateRule(rule, value) {
			return false, nil
		}
	}
	return true, nil
}

// calculateHash calculates the hash of a consent policy
func calculateHash(policy ConsentPolicy) string {
	data, _ := json.Marshal(policy)
	hash := sha256.Sum256(data)
	return string(hash[:])
}

// evaluateRule evaluates a single policy rule against a value
func evaluateRule(rule PolicyRule, value interface{}) bool {
	switch rule.Operator {
	case "==":
		return value == rule.Value
	case "!=":
		return value != rule.Value
	case "<":
		return value.(float64) < rule.Value.(float64)
	case ">":
		return value.(float64) > rule.Value.(float64)
	case "<=":
		return value.(float64) <= rule.Value.(float64)
	case ">=":
		return value.(float64) >= rule.Value.(float64)
	default:
		return false
	}
}

// HashData hashes data for integrity verification using SHA-256
func HashData(data []byte) [32]byte {
	return sha256.Sum256(data)
}

// VerifyDataIntegrity verifies the integrity of data against a given hash
func VerifyDataIntegrity(data []byte, expectedHash [32]byte) bool {
	return HashData(data) == expectedHash
}

// NewConsentTransactionManager creates a new ConsentTransactionManager instance
func NewConsentTransactionManager() *ConsentTransactionManager {
	return &ConsentTransactionManager{
		transactions: make(map[uuid.UUID]ConsentTransaction),
	}
}

// CreateTransaction creates a new consent transaction
func (ctm *ConsentTransactionManager) CreateTransaction(userID, dataID uuid.UUID, consentType, action string, privateKey []byte) (*ConsentTransaction, error) {
	if action != "grant" && action != "revoke" {
		return nil, errors.New("invalid action type")
	}

	id := uuid.New()
	now := time.Now()
	transaction := ConsentTransaction{
		ID:          id,
		UserID:      userID,
		DataID:      dataID,
		ConsentType: consentType,
		Action:      action,
		Timestamp:   now,
	}
	transaction.Hash = transaction.calculateHash()
	signature, err := cryptography.SignData([]byte(transaction.Hash), privateKey)
	if err != nil {
		return nil, err
	}
	transaction.Signature = signature
	ctm.transactions[id] = transaction
	return &transaction, nil
}

// VerifyTransaction verifies the authenticity and integrity of a consent transaction
func (ctm *ConsentTransactionManager) VerifyTransaction(id uuid.UUID, publicKey []byte) (bool, error) {
	transaction, exists := ctm.transactions[id]
	if !exists {
		return false, errors.New("transaction not found")
	}

	if !transaction.verifyIntegrity() {
		return false, errors.New("transaction integrity verification failed")
	}

	valid, err := cryptography.VerifySignature([]byte(transaction.Hash), transaction.Signature, publicKey)
	if err != nil || !valid {
		return false, errors.New("signature verification failed")
	}

	return true, nil
}

// ListTransactions lists all consent transactions for a user
func (ctm *ConsentTransactionManager) ListTransactions(userID uuid.UUID) ([]ConsentTransaction, error) {
	var userTransactions []ConsentTransaction
	for _, transaction := range ctm.transactions {
		if transaction.UserID == userID {
			userTransactions = append(userTransactions, transaction)
		}
	}
	return userTransactions, nil
}

// RevokeExpiredTransactions revokes all expired consent transactions
func (ctm *ConsentTransactionManager) RevokeExpiredTransactions() {
	now := time.Now()
	for id, transaction := range ctm.transactions {
		if transaction.Action == "grant" && transaction.Timestamp.Before(now) {
			ctm.transactions[id] = ConsentTransaction{
				ID:          transaction.ID,
				UserID:      transaction.UserID,
				DataID:      transaction.DataID,
				ConsentType: transaction.ConsentType,
				Action:      "revoke",
				Timestamp:   now,
				Signature:   transaction.Signature,
				Hash:        transaction.calculateHash(),
			}
		}
	}
}

// calculateHash generates a hash for the consent transaction
func (ct *ConsentTransaction) calculateHash() string {
	data, _ := json.Marshal(ct)
	hash := sha256.Sum256(data)
	return string(hash[:])
}

// verifyIntegrity checks the integrity of a consent transaction
func (ct *ConsentTransaction) verifyIntegrity() bool {
	return ct.Hash == ct.calculateHash()
}

// cryptography package would have SignData and VerifySignature functions

// SignData signs the given data with the provided private key
func SignData(data []byte, privateKey []byte) (string, error) {
	// Implementation of data signing using privateKey
	// Returning signature as string
}

// VerifySignature verifies the given data's signature using the provided public key
func VerifySignature(data []byte, signature string, publicKey []byte) (bool, error) {
	// Implementation of signature verification using publicKey
	// Returning true if signature is valid, otherwise false
}

// NewDynamicConsentManager creates a new DynamicConsentManager instance
func NewDynamicConsentManager() *DynamicConsentManager {
	return &DynamicConsentManager{
		consents: make(map[uuid.UUID]DynamicConsent),
	}
}

// CreateConsent creates a new dynamic consent record
func (dcm *DynamicConsentManager) CreateConsent(userID, dataID uuid.UUID, consentType string, conditions []ConsentCondition) (*DynamicConsent, error) {
	id := uuid.New()
	now := time.Now()
	consent := DynamicConsent{
		ID:           id,
		UserID:       userID,
		DataID:       dataID,
		ConsentType:  consentType,
		Conditions:   conditions,
		Status:       "active",
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	consent.Hash = calculateHash(consent)
	dcm.consents[id] = consent
	return &consent, nil
}

// UpdateConsent updates an existing dynamic consent record
func (dcm *DynamicConsentManager) UpdateConsent(consentID uuid.UUID, conditions []ConsentCondition) (*DynamicConsent, error) {
	consent, exists := dcm.consents[consentID]
	if !exists {
		return nil, errors.New("consent not found")
	}
	consent.Conditions = conditions
	consent.UpdatedAt = time.Now()
	consent.Hash = calculateHash(consent)
	dcm.consents[consentID] = consent
	return &consent, nil
}

// RevokeConsent revokes an existing dynamic consent record
func (dcm *DynamicConsentManager) RevokeConsent(consentID uuid.UUID) error {
	consent, exists := dcm.consents[consentID]
	if !exists {
		return errors.New("consent not found")
	}
	consent.Status = "revoked"
	consent.UpdatedAt = time.Now()
	consent.Hash = calculateHash(consent)
	dcm.consents[consentID] = consent
	return nil
}

// GetConsent retrieves a dynamic consent record by ID
func (dcm *DynamicConsentManager) GetConsent(consentID uuid.UUID) (*DynamicConsent, error) {
	consent, exists := dcm.consents[consentID]
	if !exists {
		return nil, errors.New("consent not found")
	}
	return &consent, nil
}

// ListConsents lists all dynamic consents for a user
func (dcm *DynamicConsentManager) ListConsents(userID uuid.UUID) ([]DynamicConsent, error) {
	var userConsents []DynamicConsent
	for _, consent := range dcm.consents {
		if consent.UserID == userID {
			userConsents = append(userConsents, consent)
		}
	}
	return userConsents, nil
}

// EvaluateConsent evaluates a dynamic consent record against given attributes
func (dcm *DynamicConsentManager) EvaluateConsent(consentID uuid.UUID, attributes map[string]interface{}) (bool, error) {
	consent, exists := dcm.consents[consentID]
	if !exists {
		return false, errors.New("consent not found")
	}
	if consent.Status != "active" {
		return false, errors.New("consent is not active")
	}
	for _, condition := range consent.Conditions {
		value, exists := attributes[condition.Attribute]
		if !exists {
			return false, nil
		}
		if !evaluateCondition(condition, value) {
			return false, nil
		}
	}
	return true, nil
}

// calculateHash generates a hash for the dynamic consent record
func calculateHash(consent DynamicConsent) string {
	data, _ := json.Marshal(consent)
	hash := sha256.Sum256(data)
	return string(hash[:])
}

// evaluateCondition evaluates a single condition within a dynamic consent record
func evaluateCondition(condition ConsentCondition, value interface{}) bool {
	switch condition.Operator {
	case "==":
		return value == condition.Value
	case "!=":
		return value != condition.Value
	case "<":
		return value.(float64) < condition.Value.(float64)
	case ">":
		return value.(float64) > condition.Value.(float64)
	case "<=":
		return value.(float64) <= condition.Value.(float64)
	case ">=":
		return value.(float64) >= condition.Value.(float64)
	default:
		return false
	}
}

// HashData hashes data for integrity verification using SHA-256
func HashData(data []byte) [32]byte {
	return sha256.Sum256(data)
}

// VerifyDataIntegrity verifies the integrity of data against a given hash
func VerifyDataIntegrity(data []byte, expectedHash [32]byte) bool {
	return HashData(data) == expectedHash
}

// cryptography package would have SignData and VerifySignature functions

// SignData signs the given data with the provided private key
func SignData(data []byte, privateKey []byte) (string, error) {
	// Implementation of data signing using privateKey
	// Returning signature as string
}

// VerifySignature verifies the given data's signature using the provided public key
func VerifySignature(data []byte, signature string, publicKey []byte) (bool, error) {
	// Implementation of signature verification using publicKey
	// Returning true if signature is valid, otherwise false
}


// NewImmutableTrailManager creates a new ImmutableTrailManager instance
func NewImmutableTrailManager(storage storage.Storage) *ImmutableTrailManager {
	return &ImmutableTrailManager{
		entries: []ImmutableTrailEntry{},
		storage: storage,
	}
}

// RecordActivity records a new consent activity in the immutable trail
func (itm *ImmutableTrailManager) RecordActivity(userID uuid.UUID, activity string) (*ImmutableTrailEntry, error) {
	id := uuid.New()
	now := time.Now()

	entry := ImmutableTrailEntry{
		ID:          id,
		UserID:      userID,
		Activity:    activity,
		Timestamp:   now,
		PreviousHash: itm.lastEntryHash,
	}

	entry.Hash = itm.calculateHash(entry)
	itm.entries = append(itm.entries, entry)
	itm.lastEntryHash = entry.Hash

	// Store entry in persistent storage
	err := itm.storage.StoreEntry(entry)
	if err != nil {
		return nil, err
	}

	return &entry, nil
}

// GetTrail retrieves the entire immutable trail for auditing purposes
func (itm *ImmutableTrailManager) GetTrail() ([]ImmutableTrailEntry, error) {
	entries, err := itm.storage.RetrieveEntries()
	if err != nil {
		return nil, err
	}

	itm.entries = entries
	if len(entries) > 0 {
		itm.lastEntryHash = entries[len(entries)-1].Hash
	}

	return entries, nil
}

// VerifyTrail verifies the integrity of the immutable trail
func (itm *ImmutableTrailManager) VerifyTrail() (bool, error) {
	entries, err := itm.GetTrail()
	if err != nil {
		return false, err
	}

	for i, entry := range entries {
		if i > 0 && entry.PreviousHash != entries[i-1].Hash {
			return false, errors.New("immutable trail verification failed: hash mismatch")
		}
		if itm.calculateHash(entry) != entry.Hash {
			return false, errors.New("immutable trail verification failed: invalid hash")
		}
	}

	return true, nil
}

// calculateHash generates a hash for the immutable trail entry
func (itm *ImmutableTrailManager) calculateHash(entry ImmutableTrailEntry) string {
	data, _ := json.Marshal(entry)
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

// cryptography package would have SignData and VerifySignature functions

// SignData signs the given data with the provided private key
func SignData(data []byte, privateKey []byte) (string, error) {
	// Implementation of data signing using privateKey
	// Returning signature as string
}

// VerifySignature verifies the given data's signature using the provided public key
func VerifySignature(data []byte, signature string, publicKey []byte) (bool, error) {
	// Implementation of signature verification using publicKey
	// Returning true if signature is valid, otherwise false
}

// storage package would have StoreEntry and RetrieveEntries functions

// StoreEntry stores the given trail entry in persistent storage
func (s *Storage) StoreEntry(entry ImmutableTrailEntry) error {
	// Implementation of storing entry in persistent storage
}

// RetrieveEntries retrieves all trail entries from persistent storage
func (s *Storage) RetrieveEntries() ([]ImmutableTrailEntry, error) {
	// Implementation of retrieving entries from persistent storage
}

