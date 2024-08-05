package monitoring_and_management

import (
	"fmt"
	"sync"
	"time"
)

// Dashboard represents a monitoring dashboard for cross-chain interoperability
type Dashboard struct {
	DashboardID      string    // Unique identifier for the dashboard
	Name             string    // Name of the dashboard
	Description      string    // Description of the dashboard
	CreatedAt        time.Time // Timestamp of when the dashboard was created
	LastUpdated      time.Time // Timestamp of the last update to the dashboard
	Interoperability map[string]*InteroperabilityMetrics
}

// InteroperabilityMetrics holds the metrics for cross-chain interoperability
type InteroperabilityMetrics struct {
	ChainA          string
	ChainB          string
	ActiveNodes     int
	TransactionRate float64
	ErrorRate       float64
	LastError       string
}

// DashboardManager manages multiple dashboards
type DashboardManager struct {
	dashboards map[string]*Dashboard
	mu         sync.Mutex
}

// NewDashboardManager creates a new DashboardManager
func NewDashboardManager() *DashboardManager {
	return &DashboardManager{
		dashboards: make(map[string]*Dashboard),
	}
}

// CreateDashboard creates a new monitoring dashboard
func (dm *DashboardManager) CreateDashboard(name, description string) (string, error) {
	dm.mu.Lock()
	defer dm.mu.Unlock()

	dashboardID := generateDashboardID()
	dashboard := &Dashboard{
		DashboardID:      dashboardID,
		Name:             name,
		Description:      description,
		CreatedAt:        time.Now(),
		LastUpdated:      time.Now(),
		Interoperability: make(map[string]*InteroperabilityMetrics),
	}

	dm.dashboards[dashboardID] = dashboard

	return dashboardID, nil
}

// UpdateMetrics updates the interoperability metrics for a specific dashboard
func (dm *DashboardManager) UpdateMetrics(dashboardID, chainA, chainB string, activeNodes int, transactionRate, errorRate float64, lastError string) error {
	dm.mu.Lock()
	defer dm.mu.Unlock()

	dashboard, exists := dm.dashboards[dashboardID]
	if !exists {
		return fmt.Errorf("dashboard not found")
	}

	metricsID := generateMetricsID(chainA, chainB)
	metrics := &InteroperabilityMetrics{
		ChainA:          chainA,
		ChainB:          chainB,
		ActiveNodes:     activeNodes,
		TransactionRate: transactionRate,
		ErrorRate:       errorRate,
		LastError:       lastError,
	}

	dashboard.Interoperability[metricsID] = metrics
	dashboard.LastUpdated = time.Now()

	return nil
}

// GetDashboard retrieves a dashboard by its ID
func (dm *DashboardManager) GetDashboard(dashboardID string) (*Dashboard, error) {
	dm.mu.Lock()
	defer dm.mu.Unlock()

	dashboard, exists := dm.dashboards[dashboardID]
	if !exists {
		return nil, fmt.Errorf("dashboard not found")
	}

	return dashboard, nil
}

// ListDashboards lists all available dashboards
func (dm *DashboardManager) ListDashboards() []*Dashboard {
	dm.mu.Lock()
	defer dm.mu.Unlock()

	dashboards := make([]*Dashboard, 0, len(dm.dashboards))
	for _, dashboard := range dm.dashboards {
		dashboards = append(dashboards, dashboard)
	}

	return dashboards
}

// RemoveDashboard removes a dashboard by its ID
func (dm *DashboardManager) RemoveDashboard(dashboardID string) error {
	dm.mu.Lock()
	defer dm.mu.Unlock()

	if _, exists := dm.dashboards[dashboardID]; !exists {
		return fmt.Errorf("dashboard not found")
	}

	delete(dm.dashboards, dashboardID)

	return nil
}

// generateDashboardID generates a unique dashboard ID
func generateDashboardID() string {
	data := fmt.Sprintf("%s", time.Now().String())
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

// generateMetricsID generates a unique metrics ID for interoperability metrics
func generateMetricsID(chainA, chainB string) string {
	data := chainA + chainB + time.Now().String()
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

// MonitorInteroperability continuously monitors interoperability metrics and updates the dashboard
func (dm *DashboardManager) MonitorInteroperability(dashboardID, chainA, chainB string) {
	for {
		time.Sleep(10 * time.Second)

		// Simulate gathering metrics data
		activeNodes := 100                      // Example value
		transactionRate := 50.0                 // Example value
		errorRate := 0.01                       // Example value
		lastError := "No recent errors"         // Example value

		err := dm.UpdateMetrics(dashboardID, chainA, chainB, activeNodes, transactionRate, errorRate, lastError)
		if err != nil {
			fmt.Printf("Error updating metrics: %s\n", err)
		} else {
			fmt.Printf("Metrics updated for dashboard %s: ChainA: %s, ChainB: %s, ActiveNodes: %d, TransactionRate: %.2f, ErrorRate: %.2f, LastError: %s\n",
				dashboardID, chainA, chainB, activeNodes, transactionRate, errorRate, lastError)
		}
	}
}
