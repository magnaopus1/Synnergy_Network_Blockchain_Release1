package compliance

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"strings"
	"time"
)

// RiskManagementStrategy defines the strategy for managing various risks associated with digital gilts.
type RiskManagementStrategy struct {
	ID              string    `json:"id"`
	Name            string    `json:"name"`
	Description     string    `json:"description"`
	Implementation  string    `json:"implementation"`
	LastUpdated     time.Time `json:"last_updated"`
	EvaluationScore float64   `json:"evaluation_score"`
}

// RiskType represents the type of risk being managed.
type RiskType string

const (
	OperationalRisk   RiskType = "Operational"
	CyberSecurityRisk RiskType = "CyberSecurity"
	ComplianceRisk    RiskType = "Compliance"
	LiquidityRisk     RiskType = "Liquidity"
	MarketRisk        RiskType = "Market"
	CreditRisk        RiskType = "Credit"
)

// RiskAssessment represents the assessment of a specific risk.
type RiskAssessment struct {
	RiskID         string    `json:"risk_id"`
	RiskType       RiskType  `json:"risk_type"`
	Impact         string    `json:"impact"`
	Likelihood     string    `json:"likelihood"`
	MitigationPlan string    `json:"mitigation_plan"`
	AssessedOn     time.Time `json:"assessed_on"`
	Reviewer       string    `json:"reviewer"`
}

// RiskManagementSystem manages risk assessments and mitigation strategies.
type RiskManagementSystem struct {
	strategies   map[string]RiskManagementStrategy
	assessments  map[string]RiskAssessment
	systemHash   string
}

// NewRiskManagementSystem initializes a new risk management system.
func NewRiskManagementSystem() *RiskManagementSystem {
	return &RiskManagementSystem{
		strategies:  make(map[string]RiskManagementStrategy),
		assessments: make(map[string]RiskAssessment),
		systemHash:  "",
	}
}

// AddRiskManagementStrategy adds a new risk management strategy.
func (rms *RiskManagementSystem) AddRiskManagementStrategy(name, description, implementation string, score float64) string {
	id := generateStrategyID(name, description, implementation)
	strategy := RiskManagementStrategy{
		ID:              id,
		Name:            name,
		Description:     description,
		Implementation:  implementation,
		LastUpdated:     time.Now(),
		EvaluationScore: score,
	}
	rms.strategies[id] = strategy
	rms.updateSystemHash()
	return id
}

// UpdateRiskManagementStrategy updates an existing risk management strategy.
func (rms *RiskManagementSystem) UpdateRiskManagementStrategy(id, name, description, implementation string, score float64) error {
	strategy, exists := rms.strategies[id]
	if !exists {
		return fmt.Errorf("strategy with ID %s not found", id)
	}

	strategy.Name = name
	strategy.Description = description
	strategy.Implementation = implementation
	strategy.LastUpdated = time.Now()
	strategy.EvaluationScore = score

	rms.strategies[id] = strategy
	rms.updateSystemHash()
	return nil
}

// RemoveRiskManagementStrategy removes a risk management strategy.
func (rms *RiskManagementSystem) RemoveRiskManagementStrategy(id string) error {
	_, exists := rms.strategies[id]
	if !exists {
		return fmt.Errorf("strategy with ID %s not found", id)
	}

	delete(rms.strategies, id)
	rms.updateSystemHash()
	return nil
}

// AddRiskAssessment adds a new risk assessment.
func (rms *RiskManagementSystem) AddRiskAssessment(riskType RiskType, impact, likelihood, mitigationPlan, reviewer string) string {
	id := generateRiskAssessmentID(riskType, impact, likelihood)
	assessment := RiskAssessment{
		RiskID:         id,
		RiskType:       riskType,
		Impact:         impact,
		Likelihood:     likelihood,
		MitigationPlan: mitigationPlan,
		AssessedOn:     time.Now(),
		Reviewer:       reviewer,
	}
	rms.assessments[id] = assessment
	rms.updateSystemHash()
	return id
}

// GetRiskAssessment retrieves a risk assessment by ID.
func (rms *RiskManagementSystem) GetRiskAssessment(id string) (*RiskAssessment, error) {
	assessment, exists := rms.assessments[id]
	if !exists {
		return nil, fmt.Errorf("assessment with ID %s not found", id)
	}
	return &assessment, nil
}

// UpdateRiskAssessment updates an existing risk assessment.
func (rms *RiskManagementSystem) UpdateRiskAssessment(id, impact, likelihood, mitigationPlan, reviewer string) error {
	assessment, exists := rms.assessments[id]
	if !exists {
		return fmt.Errorf("assessment with ID %s not found", id)
	}

	assessment.Impact = impact
	assessment.Likelihood = likelihood
	assessment.MitigationPlan = mitigationPlan
	assessment.AssessedOn = time.Now()
	assessment.Reviewer = reviewer

	rms.assessments[id] = assessment
	rms.updateSystemHash()
	return nil
}

// RemoveRiskAssessment removes a risk assessment.
func (rms *RiskManagementSystem) RemoveRiskAssessment(id string) error {
	_, exists := rms.assessments[id]
	if !exists {
		return fmt.Errorf("assessment with ID %s not found", id)
	}

	delete(rms.assessments, id)
	rms.updateSystemHash()
	return nil
}

// updateSystemHash updates the hash representing the state of the risk management system.
func (rms *RiskManagementSystem) updateSystemHash() {
	data := strings.Builder{}
	for _, strategy := range rms.strategies {
		data.WriteString(strategy.ID + strategy.Name + strategy.Description + strategy.Implementation)
	}
	for _, assessment := range rms.assessments {
		data.WriteString(assessment.RiskID + string(assessment.RiskType) + assessment.Impact + assessment.Likelihood)
	}
	hash := sha256.New()
	hash.Write([]byte(data.String()))
	rms.systemHash = hex.EncodeToString(hash.Sum(nil))
}

// SystemHash returns the current system hash.
func (rms *RiskManagementSystem) SystemHash() string {
	return rms.systemHash
}

// generateStrategyID generates a unique ID for a strategy.
func generateStrategyID(name, description, implementation string) string {
	return generateHash(name + description + implementation)
}

// generateRiskAssessmentID generates a unique ID for a risk assessment.
func generateRiskAssessmentID(riskType RiskType, impact, likelihood string) string {
	return generateHash(string(riskType) + impact + likelihood)
}

// generateHash creates a SHA-256 hash of the input data.
func generateHash(data string) string {
	hash := sha256.New()
	hash.Write([]byte(data))
	return hex.EncodeToString(hash.Sum(nil))
}
