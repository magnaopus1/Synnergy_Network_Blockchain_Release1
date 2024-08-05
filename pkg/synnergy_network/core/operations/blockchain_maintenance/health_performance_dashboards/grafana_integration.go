package health_performance_dashboards

import (
	"fmt"
	"sync"
	"time"
	"encoding/json"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"net/http"
	"log"
	"github.com/grafana-tools/sdk"
)

// Dashboard represents a customizable dashboard for health performance metrics
type Dashboard struct {
	ID            string
	Name          string
	Widgets       []Widget
	CreationTime  time.Time
	LastUpdated   time.Time
	Owner         string
	RoleBasedAccessControl map[string][]string
	mu            sync.Mutex
}

// Widget represents a widget in the dashboard
type Widget struct {
	ID        string
	Type      string
	Title     string
	Query     string
	Threshold float64
}

// DashboardManager manages all dashboards
type DashboardManager struct {
	Dashboards map[string]*Dashboard
	mu         sync.Mutex
}

// NewDashboardManager creates a new DashboardManager
func NewDashboardManager() *DashboardManager {
	return &DashboardManager{
		Dashboards: make(map[string]*Dashboard),
	}
}

// CreateDashboard creates a new dashboard
func (dm *DashboardManager) CreateDashboard(name, owner string, roleBasedAccessControl map[string][]string) (*Dashboard, error) {
	dm.mu.Lock()
	defer dm.mu.Unlock()

	id := generateID()
	dashboard := &Dashboard{
		ID:            id,
		Name:          name,
		CreationTime:  time.Now(),
		LastUpdated:   time.Now(),
		Owner:         owner,
		RoleBasedAccessControl: roleBasedAccessControl,
	}

	dm.Dashboards[id] = dashboard
	return dashboard, nil
}

// AddWidget adds a widget to the dashboard
func (dm *DashboardManager) AddWidget(dashboardID, widgetType, title, query string, threshold float64) (*Widget, error) {
	dm.mu.Lock()
	defer dm.mu.Unlock()

	dashboard, exists := dm.Dashboards[dashboardID]
	if !exists {
		return nil, fmt.Errorf("dashboard not found")
	}

	widgetID := generateID()
	widget := Widget{
		ID:        widgetID,
		Type:      widgetType,
		Title:     title,
		Query:     query,
		Threshold: threshold,
	}

	dashboard.mu.Lock()
	dashboard.Widgets = append(dashboard.Widgets, widget)
	dashboard.LastUpdated = time.Now()
	dashboard.mu.Unlock()

	return &widget, nil
}

// RemoveWidget removes a widget from the dashboard
func (dm *DashboardManager) RemoveWidget(dashboardID, widgetID string) error {
	dm.mu.Lock()
	defer dm.mu.Unlock()

	dashboard, exists := dm.Dashboards[dashboardID]
	if !exists {
		return fmt.Errorf("dashboard not found")
	}

	dashboard.mu.Lock()
	defer dashboard.mu.Unlock()

	for i, widget := range dashboard.Widgets {
		if widget.ID == widgetID {
			dashboard.Widgets = append(dashboard.Widgets[:i], dashboard.Widgets[i+1:]...)
			dashboard.LastUpdated = time.Now()
			return nil
		}
	}

	return fmt.Errorf("widget not found")
}

// GetDashboard returns a dashboard by ID
func (dm *DashboardManager) GetDashboard(dashboardID string) (*Dashboard, error) {
	dm.mu.Lock()
	defer dm.mu.Unlock()

	dashboard, exists := dm.Dashboards[dashboardID]
	if !exists {
		return nil, fmt.Errorf("dashboard not found")
	}

	return dashboard, nil
}

// UpdateRoleBasedAccessControl updates the role-based access control of a dashboard
func (dm *DashboardManager) UpdateRoleBasedAccessControl(dashboardID string, roleBasedAccessControl map[string][]string) error {
	dm.mu.Lock()
	defer dm.mu.Unlock()

	dashboard, exists := dm.Dashboards[dashboardID]
	if !exists {
		return fmt.Errorf("dashboard not found")
	}

	dashboard.mu.Lock()
	defer dashboard.mu.Unlock()

	dashboard.RoleBasedAccessControl = roleBasedAccessControl
	dashboard.LastUpdated = time.Now()

	return nil
}

// Integration with Prometheus
func prometheusHandler() {
	http.Handle("/metrics", promhttp.Handler())
	log.Fatal(http.ListenAndServe(":2112", nil))
}

// Integration with Grafana
func grafanaHandler(client *sdk.Client, dashboardID string) error {
	board, _, err := client.GetDashboardByUID(context.Background(), dashboardID)
	if err != nil {
		return err
	}

	fmt.Printf("Dashboard: %+v\n", board)
	return nil
}

// Generate a unique ID (mock implementation)
func generateID() string {
	return fmt.Sprintf("%d", time.Now().UnixNano())
}

