package health_performance_dashboards

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/synnergy_network/pkg/synnergy_network/utils"
	"github.com/synnergy_network/pkg/synnergy_network/utils/encryption_utils"
)

// Dashboard defines the structure for a customizable dashboard
type Dashboard struct {
	ID            string
	Name          string
	OwnerID       string
	Widgets       []Widget
	LastUpdated   time.Time
	EncryptionKey string
}

// Widget defines the structure for a widget in the dashboard
type Widget struct {
	ID         string
	Type       string
	Parameters map[string]string
}

// DashboardManager manages the creation, updating, and deletion of dashboards
type DashboardManager struct {
	dashboards map[string]Dashboard
	mu         sync.Mutex
}

// NewDashboardManager creates a new instance of DashboardManager
func NewDashboardManager() *DashboardManager {
	return &DashboardManager{
		dashboards: make(map[string]Dashboard),
	}
}

// CreateDashboard creates a new dashboard for a user
func (dm *DashboardManager) CreateDashboard(name, ownerID string) (string, error) {
	dm.mu.Lock()
	defer dm.mu.Unlock()

	id := utils.GenerateID()
	encryptionKey, err := encryption_utils.GenerateEncryptionKey()
	if err != nil {
		return "", fmt.Errorf("failed to generate encryption key: %v", err)
	}

	dashboard := Dashboard{
		ID:            id,
		Name:          name,
		OwnerID:       ownerID,
		Widgets:       []Widget{},
		LastUpdated:   time.Now(),
		EncryptionKey: encryptionKey,
	}
	dm.dashboards[id] = dashboard
	return id, nil
}

// AddWidget adds a new widget to an existing dashboard
func (dm *DashboardManager) AddWidget(dashboardID, widgetType string, parameters map[string]string) (string, error) {
	dm.mu.Lock()
	defer dm.mu.Unlock()

	dashboard, exists := dm.dashboards[dashboardID]
	if !exists {
		return "", errors.New("dashboard not found")
	}

	widgetID := utils.GenerateID()
	widget := Widget{
		ID:         widgetID,
		Type:       widgetType,
		Parameters: parameters,
	}

	dashboard.Widgets = append(dashboard.Widgets, widget)
	dashboard.LastUpdated = time.Now()
	dm.dashboards[dashboardID] = dashboard
	return widgetID, nil
}

// UpdateWidget updates an existing widget in a dashboard
func (dm *DashboardManager) UpdateWidget(dashboardID, widgetID string, newParameters map[string]string) error {
	dm.mu.Lock()
	defer dm.mu.Unlock()

	dashboard, exists := dm.dashboards[dashboardID]
	if !exists {
		return errors.New("dashboard not found")
	}

	for i, widget := range dashboard.Widgets {
		if widget.ID == widgetID {
			dashboard.Widgets[i].Parameters = newParameters
			dashboard.LastUpdated = time.Now()
			dm.dashboards[dashboardID] = dashboard
			return nil
		}
	}
	return errors.New("widget not found")
}

// DeleteWidget removes a widget from a dashboard
func (dm *DashboardManager) DeleteWidget(dashboardID, widgetID string) error {
	dm.mu.Lock()
	defer dm.mu.Unlock()

	dashboard, exists := dm.dashboards[dashboardID]
	if !exists {
		return errors.New("dashboard not found")
	}

	for i, widget := range dashboard.Widgets {
		if widget.ID == widgetID {
			dashboard.Widgets = append(dashboard.Widgets[:i], dashboard.Widgets[i+1:]...)
			dashboard.LastUpdated = time.Now()
			dm.dashboards[dashboardID] = dashboard
			return nil
		}
	}
	return errors.New("widget not found")
}

// GetDashboard retrieves a dashboard by its ID
func (dm *DashboardManager) GetDashboard(dashboardID string) (Dashboard, error) {
	dm.mu.Lock()
	defer dm.mu.Unlock()

	dashboard, exists := dm.dashboards[dashboardID]
	if !exists {
		return Dashboard{}, errors.New("dashboard not found")
	}
	return dashboard, nil
}

// ListDashboardsByOwner retrieves all dashboards owned by a specific user
func (dm *DashboardManager) ListDashboardsByOwner(ownerID string) ([]Dashboard, error) {
	dm.mu.Lock()
	defer dm.mu.Unlock()

	var dashboards []Dashboard
	for _, dashboard := range dm.dashboards {
		if dashboard.OwnerID == ownerID {
			dashboards = append(dashboards, dashboard)
		}
	}
	return dashboards, nil
}

// EncryptDashboard encrypts the dashboard data using the provided encryption key
func (dm *DashboardManager) EncryptDashboard(dashboardID string) error {
	dm.mu.Lock()
	defer dm.mu.Unlock()

	dashboard, exists := dm.dashboards[dashboardID]
	if !exists {
		return errors.New("dashboard not found")
	}

	encryptedWidgets, err := encryption_utils.EncryptData(dashboard.Widgets, dashboard.EncryptionKey)
	if err != nil {
		return fmt.Errorf("failed to encrypt dashboard widgets: %v", err)
	}

	dashboard.Widgets = encryptedWidgets
	dm.dashboards[dashboardID] = dashboard
	return nil
}

// DecryptDashboard decrypts the dashboard data using the provided encryption key
func (dm *DashboardManager) DecryptDashboard(dashboardID string) error {
	dm.mu.Lock()
	defer dm.mu.Unlock()

	dashboard, exists := dm.dashboards[dashboardID]
	if !exists {
		return errors.New("dashboard not found")
	}

	decryptedWidgets, err := encryption_utils.DecryptData(dashboard.Widgets, dashboard.EncryptionKey)
	if err != nil {
		return fmt.Errorf("failed to decrypt dashboard widgets: %v", err)
	}

	dashboard.Widgets = decryptedWidgets
	dm.dashboards[dashboardID] = dashboard
	return nil
}

// RemoveDashboard deletes a dashboard
func (dm *DashboardManager) RemoveDashboard(dashboardID string) error {
	dm.mu.Lock()
	defer dm.mu.Unlock()

	if _, exists := dm.dashboards[dashboardID]; !exists {
		return errors.New("dashboard not found")
	}

	delete(dm.dashboards, dashboardID)
	return nil
}
