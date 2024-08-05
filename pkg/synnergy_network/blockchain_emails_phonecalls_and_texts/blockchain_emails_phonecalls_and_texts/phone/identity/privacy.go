package identity

import (
	"errors"
)

type PrivacySettings struct {
	UserID             string
	AllowCallsFrom     []string
	BlockCallsFrom     []string
	AllowMessagesFrom  []string
	BlockMessagesFrom  []string
	AllowEmailsFrom    []string
	BlockEmailsFrom    []string
}

type PrivacyManager struct {
	PrivacyData map[string]*PrivacySettings
}

func NewPrivacyManager() *PrivacyManager {
	return &PrivacyManager{
		PrivacyData: make(map[string]*PrivacySettings),
	}
}

func (pm *PrivacyManager) UpdatePrivacySettings(userID string, settings *PrivacySettings) {
	pm.PrivacyData[userID] = settings
}

func (pm *PrivacyManager) GetPrivacySettings(userID string) (*PrivacySettings, error) {
	settings, exists := pm.PrivacyData[userID]
	if !exists {
		return nil, errors.New("privacy settings not found")
	}
	return settings, nil
}

func (pm *PrivacyManager) DeletePrivacySettings(userID string) {
	delete(pm.PrivacyData, userID)
}
