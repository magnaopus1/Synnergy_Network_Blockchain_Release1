package health_performance_dashboards

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"sync"
	"time"

	"github.com/synnergy_network/pkg/synnergy_network/utils"
	"github.com/synnergy_network/pkg/synnergy_network/utils/encryption_utils"
)

// DashboardExport defines the structure for exporting a dashboard
type DashboardExport struct {
	ID          string
	Name        string
	OwnerID     string
	Widgets     []Widget
	LastUpdated time.Time
}

// DashboardShare defines the structure for sharing a dashboard
type DashboardShare struct {
	ID            string
	DashboardID   string
	SharedWith    string
	SharedAt      time.Time
	EncryptionKey string
}

// DashboardExportManager handles the exporting and sharing of dashboards
type DashboardExportManager struct {
	dashboards map[string]Dashboard
	shares     map[string]DashboardShare
	mu         sync.Mutex
}

// NewDashboardExportManager creates a new instance of DashboardExportManager
func NewDashboardExportManager() *DashboardExportManager {
	return &DashboardExportManager{
		dashboards: make(map[string]Dashboard),
		shares:     make(map[string]DashboardShare),
	}
}

// ExportDashboard exports a dashboard to a file
func (dem *DashboardExportManager) ExportDashboard(dashboardID string, filePath string) error {
	dem.mu.Lock()
	defer dem.mu.Unlock()

	dashboard, exists := dem.dashboards[dashboardID]
	if !exists {
		return errors.New("dashboard not found")
	}

	exportData := DashboardExport{
		ID:          dashboard.ID,
		Name:        dashboard.Name,
		OwnerID:     dashboard.OwnerID,
		Widgets:     dashboard.Widgets,
		LastUpdated: dashboard.LastUpdated,
	}

	data, err := json.Marshal(exportData)
	if err != nil {
		return fmt.Errorf("failed to marshal dashboard data: %v", err)
	}

	err = ioutil.WriteFile(filePath, data, 0644)
	if err != nil {
		return fmt.Errorf("failed to write dashboard data to file: %v", err)
	}

	return nil
}

// ImportDashboard imports a dashboard from a file
func (dem *DashboardExportManager) ImportDashboard(filePath string) (string, error) {
	dem.mu.Lock()
	defer dem.mu.Unlock()

	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		return "", fmt.Errorf("failed to read dashboard data from file: %v", err)
	}

	var importData DashboardExport
	err = json.Unmarshal(data, &importData)
	if err != nil {
		return "", fmt.Errorf("failed to unmarshal dashboard data: %v", err)
	}

	dashboard := Dashboard{
		ID:          importData.ID,
		Name:        importData.Name,
		OwnerID:     importData.OwnerID,
		Widgets:     importData.Widgets,
		LastUpdated: importData.LastUpdated,
	}

	dem.dashboards[dashboard.ID] = dashboard
	return dashboard.ID, nil
}

// ShareDashboard shares a dashboard with another user
func (dem *DashboardExportManager) ShareDashboard(dashboardID, sharedWith string) (string, error) {
	dem.mu.Lock()
	defer dem.mu.Unlock()

	dashboard, exists := dem.dashboards[dashboardID]
	if !exists {
		return "", errors.New("dashboard not found")
	}

	shareID := utils.GenerateID()
	encryptionKey, err := encryption_utils.GenerateEncryptionKey()
	if err != nil {
		return "", fmt.Errorf("failed to generate encryption key: %v", err)
	}

	share := DashboardShare{
		ID:            shareID,
		DashboardID:   dashboard.ID,
		SharedWith:    sharedWith,
		SharedAt:      time.Now(),
		EncryptionKey: encryptionKey,
	}

	dem.shares[shareID] = share
	return shareID, nil
}

// GetSharedDashboards retrieves all dashboards shared with a specific user
func (dem *DashboardExportManager) GetSharedDashboards(userID string) ([]DashboardShare, error) {
	dem.mu.Lock()
	defer dem.mu.Unlock()

	var sharedDashboards []DashboardShare
	for _, share := range dem.shares {
		if share.SharedWith == userID {
			sharedDashboards = append(sharedDashboards, share)
		}
	}
	return sharedDashboards, nil
}

// RevokeShare revokes access to a shared dashboard
func (dem *DashboardExportManager) RevokeShare(shareID string) error {
	dem.mu.Lock()
	defer dem.mu.Unlock()

	if _, exists := dem.shares[shareID]; !exists {
		return errors.New("share not found")
	}

	delete(dem.shares, shareID)
	return nil
}

// EncryptDashboardData encrypts the dashboard data for sharing
func (dem *DashboardExportManager) EncryptDashboardData(dashboardID string) (string, error) {
	dem.mu.Lock()
	defer dem.mu.Unlock()

	dashboard, exists := dem.dashboards[dashboardID]
	if !exists {
		return "", errors.New("dashboard not found")
	}

	encryptedData, err := encryption_utils.EncryptData(dashboard.Widgets, dashboard.EncryptionKey)
	if err != nil {
		return "", fmt.Errorf("failed to encrypt dashboard data: %v", err)
	}

	return encryptedData, nil
}

// DecryptDashboardData decrypts the shared dashboard data
func (dem *DashboardExportManager) DecryptDashboardData(shareID string) ([]Widget, error) {
	dem.mu.Lock()
	defer dem.mu.Unlock()

	share, exists := dem.shares[shareID]
	if !exists {
		return nil, errors.New("share not found")
	}

	dashboard, exists := dem.dashboards[share.DashboardID]
	if !exists {
		return nil, errors.New("dashboard not found")
	}

	decryptedData, err := encryption_utils.DecryptData(dashboard.Widgets, share.EncryptionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt dashboard data: %v", err)
	}

	return decryptedData, nil
}
