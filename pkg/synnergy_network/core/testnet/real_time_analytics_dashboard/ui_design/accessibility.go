package ui_design

import (
	"errors"
	"log"
)

// AccessibilitySettings defines the configuration for accessibility features.
type AccessibilitySettings struct {
	EnableHighContrastMode bool
	EnableScreenReader     bool
	EnableKeyboardNav      bool
	FontSize               int
}

// AccessibilityManager handles the state and updates of accessibility settings.
type AccessibilityManager struct {
	settings AccessibilitySettings
}

// NewAccessibilityManager creates a new AccessibilityManager with default settings.
func NewAccessibilityManager() *AccessibilityManager {
	return &AccessibilityManager{
		settings: AccessibilitySettings{
			EnableHighContrastMode: false,
			EnableScreenReader:     false,
			EnableKeyboardNav:      true,
			FontSize:               14,
		},
	}
}

// UpdateSettings updates the accessibility settings.
func (am *AccessibilityManager) UpdateSettings(newSettings AccessibilitySettings) error {
	if newSettings.FontSize < 10 || newSettings.FontSize > 30 {
		return errors.New("font size must be between 10 and 30")
	}
	am.settings = newSettings
	log.Printf("Accessibility settings updated: %+v\n", am.settings)
	return nil
}

// GetSettings returns the current accessibility settings.
func (am *AccessibilityManager) GetSettings() AccessibilitySettings {
	return am.settings
}

// EnableHighContrast enables high contrast mode.
func (am *AccessibilityManager) EnableHighContrast() {
	am.settings.EnableHighContrastMode = true
	log.Println("High contrast mode enabled.")
}

// DisableHighContrast disables high contrast mode.
func (am *AccessibilityManager) DisableHighContrast() {
	am.settings.EnableHighContrastMode = false
	log.Println("High contrast mode disabled.")
}

// EnableScreenReaderSupport enables screen reader support.
func (am *AccessibilityManager) EnableScreenReaderSupport() {
	am.settings.EnableScreenReader = true
	log.Println("Screen reader support enabled.")
}

// DisableScreenReaderSupport disables screen reader support.
func (am *AccessibilityManager) DisableScreenReaderSupport() {
	am.settings.EnableScreenReader = false
	log.Println("Screen reader support disabled.")
}

// EnableKeyboardNavigation enables keyboard navigation.
func (am *AccessibilityManager) EnableKeyboardNavigation() {
	am.settings.EnableKeyboardNav = true
	log.Println("Keyboard navigation enabled.")
}

// DisableKeyboardNavigation disables keyboard navigation.
func (am *AccessibilityManager) DisableKeyboardNavigation() {
	am.settings.EnableKeyboardNav = false
	log.Println("Keyboard navigation disabled.")
}

// SetFontSize sets the font size for the dashboard.
func (am *AccessibilityManager) SetFontSize(size int) error {
	if size < 10 || size > 30 {
		return errors.New("font size must be between 10 and 30")
	}
	am.settings.FontSize = size
	log.Printf("Font size set to %d.\n", size)
	return nil
}

// ValidateSettings checks if the current settings are valid.
func (am *AccessibilityManager) ValidateSettings() error {
	if am.settings.FontSize < 10 || am.settings.FontSize > 30 {
		return errors.New("invalid font size setting")
	}
	return nil
}

// LoadDefaultSettings loads the default accessibility settings.
func (am *AccessibilityManager) LoadDefaultSettings() {
	am.settings = AccessibilitySettings{
		EnableHighContrastMode: false,
		EnableScreenReader:     false,
		EnableKeyboardNav:      true,
		FontSize:               14,
	}
	log.Println("Default accessibility settings loaded.")
}

// ApplySettings applies the current settings to the dashboard UI.
func (am *AccessibilityManager) ApplySettings() error {
	if err := am.ValidateSettings(); err != nil {
		return err
	}
	// Logic to apply settings to the UI would go here.
	log.Println("Accessibility settings applied to the dashboard UI.")
	return nil
}
