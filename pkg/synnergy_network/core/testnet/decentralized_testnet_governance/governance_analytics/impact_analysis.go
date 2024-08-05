package governance_analytics

import (
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

// ImpactAnalysis represents the structure for analyzing the impact of governance decisions.
type ImpactAnalysis struct {
	DecisionID   string                 `json:"decision_id"`
	Timestamp    time.Time              `json:"timestamp"`
	ImpactReport map[string]interface{} `json:"impact_report"`
}

// GovernanceDecision represents a governance decision record.
type GovernanceDecision struct {
	ID          string    `json:"id"`
	Title       string    `json:"title"`
	Description string    `json:"description"`
	Timestamp   time.Time `json:"timestamp"`
	Votes       map[string]bool `json:"votes"` // voter_id: approved or not
}

// AnalysisEngine is responsible for performing impact analysis.
type AnalysisEngine struct {
	decisions       map[string]GovernanceDecision
	impactReports   map[string]ImpactAnalysis
	mutex           sync.RWMutex
}

// NewAnalysisEngine creates a new instance of AnalysisEngine.
func NewAnalysisEngine() *AnalysisEngine {
	return &AnalysisEngine{
		decisions:     make(map[string]GovernanceDecision),
		impactReports: make(map[string]ImpactAnalysis),
	}
}

// RecordDecision records a new governance decision.
func (ae *AnalysisEngine) RecordDecision(decision GovernanceDecision) {
	ae.mutex.Lock()
	defer ae.mutex.Unlock()
	ae.decisions[decision.ID] = decision
}

// GenerateImpactAnalysis generates an impact analysis report for a specific decision.
func (ae *AnalysisEngine) GenerateImpactAnalysis(decisionID string) (*ImpactAnalysis, error) {
	ae.mutex.RLock()
	decision, exists := ae.decisions[decisionID]
	ae.mutex.RUnlock()
	if !exists {
		return nil, fmt.Errorf("decision with ID %s not found", decisionID)
	}

	// Simulated impact analysis logic
	impactReport := map[string]interface{}{
		"economic_impact":  "Positive",
		"technical_impact": "Neutral",
		"community_impact": "Positive",
	}

	impactAnalysis := ImpactAnalysis{
		DecisionID:   decision.ID,
		Timestamp:    time.Now(),
		ImpactReport: impactReport,
	}

	ae.mutex.Lock()
	ae.impactReports[decisionID] = impactAnalysis
	ae.mutex.Unlock()

	return &impactAnalysis, nil
}

// GetImpactAnalysis retrieves an impact analysis report for a specific decision.
func (ae *AnalysisEngine) GetImpactAnalysis(decisionID string) (*ImpactAnalysis, error) {
	ae.mutex.RLock()
	defer ae.mutex.RUnlock()
	impactAnalysis, exists := ae.impactReports[decisionID]
	if !exists {
		return nil, fmt.Errorf("impact analysis for decision ID %s not found", decisionID)
	}
	return &impactAnalysis, nil
}

// ListImpactReports lists all generated impact analysis reports.
func (ae *AnalysisEngine) ListImpactReports() ([]ImpactAnalysis, error) {
	ae.mutex.RLock()
	defer ae.mutex.RUnlock()
	reports := make([]ImpactAnalysis, 0, len(ae.impactReports))
	for _, report := range ae.impactReports {
		reports = append(reports, report)
	}
	return reports, nil
}

// MarshalJSON custom marshaller to handle mutex.
func (ae *AnalysisEngine) MarshalJSON() ([]byte, error) {
	ae.mutex.RLock()
	defer ae.mutex.RUnlock()
	type Alias AnalysisEngine
	return json.Marshal(&struct {
		Decisions     map[string]GovernanceDecision `json:"decisions"`
		ImpactReports map[string]ImpactAnalysis     `json:"impact_reports"`
		*Alias
	}{
		Decisions:     ae.decisions,
		ImpactReports: ae.impactReports,
		Alias:         (*Alias)(ae),
	})
}

// UnmarshalJSON custom unmarshaller to handle mutex.
func (ae *AnalysisEngine) UnmarshalJSON(data []byte) error {
	ae.mutex.Lock()
	defer ae.mutex.Unlock()
	type Alias AnalysisEngine
	aux := &struct {
		Decisions     map[string]GovernanceDecision `json:"decisions"`
		ImpactReports map[string]ImpactAnalysis     `json:"impact_reports"`
		*Alias
	}{
		Alias: (*Alias)(ae),
	}
	if err := json.Unmarshal(data, aux); err != nil {
		return err
	}
	ae.decisions = aux.Decisions
	ae.impactReports = aux.ImpactReports
	return nil
}
