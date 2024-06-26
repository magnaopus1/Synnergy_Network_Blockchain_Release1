package display

import (
	"encoding/json"
	"errors"
	"fmt"
	"image/color"
	"io/ioutil"
	"os"
)

// Theme represents a customizable theme for the wallet display.
type Theme struct {
	Name        string      `json:"name"`
	Primary     color.RGBA  `json:"primary"`
	Secondary   color.RGBA  `json:"secondary"`
	Background  color.RGBA  `json:"background"`
	Foreground  color.RGBA  `json:"foreground"`
	FontStyle   string      `json:"fontStyle"`
	FontSize    int         `json:"fontSize"`
	BorderStyle string      `json:"borderStyle"`
	BorderWidth int         `json:"borderWidth"`
}

// ThemeManager handles loading, saving, and applying themes.
type ThemeManager struct {
	currentTheme Theme
	themes       map[string]Theme
}

// NewThemeManager creates a new instance of ThemeManager.
func NewThemeManager() *ThemeManager {
	return &ThemeManager{
		themes: make(map[string]Theme),
	}
}

// LoadThemes loads themes from a JSON file.
func (tm *ThemeManager) LoadThemes(filename string) error {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return err
	}

	err = json.Unmarshal(data, &tm.themes)
	if err != nil {
		return err
	}

	if len(tm.themes) == 0 {
		return errors.New("no themes loaded from the file")
	}

	// Set the first theme as the current theme
	for _, theme := range tm.themes {
		tm.currentTheme = theme
		break
	}

	return nil
}

// SaveThemes saves themes to a JSON file.
func (tm *ThemeManager) SaveThemes(filename string) error {
	data, err := json.MarshalIndent(tm.themes, "", "  ")
	if err != nil {
		return err
	}

	return ioutil.WriteFile(filename, data, 0600)
}

// AddTheme adds a new theme to the manager.
func (tm *ThemeManager) AddTheme(theme Theme) {
	tm.themes[theme.Name] = theme
}

// RemoveTheme removes a theme from the manager.
func (tm *ThemeManager) RemoveTheme(themeName string) error {
	if _, exists := tm.themes[themeName]; !exists {
		return errors.New("theme not found")
	}

	delete(tm.themes, themeName)
	return nil
}

// ApplyTheme applies a theme by name.
func (tm *ThemeManager) ApplyTheme(themeName string) error {
	theme, exists := tm.themes[themeName]
	if !exists {
		return errors.New("theme not found")
	}

	tm.currentTheme = theme
	return nil
}

// GetCurrentTheme returns the current theme.
func (tm *ThemeManager) GetCurrentTheme() Theme {
	return tm.currentTheme
}

// CustomizeTheme customizes the current theme with new properties.
func (tm *ThemeManager) CustomizeTheme(name string, primary, secondary, background, foreground color.RGBA, fontStyle string, fontSize int, borderStyle string, borderWidth int) error {
	if _, exists := tm.themes[name]; !exists {
		return errors.New("theme not found")
	}

	tm.themes[name] = Theme{
		Name:        name,
		Primary:     primary,
		Secondary:   secondary,
		Background:  background,
		Foreground:  foreground,
		FontStyle:   fontStyle,
		FontSize:    fontSize,
		BorderStyle: borderStyle,
		BorderWidth: borderWidth,
	}
	return nil
}

// DisplayThemes lists all available themes.
func (tm *ThemeManager) DisplayThemes() {
	for name, theme := range tm.themes {
		fmt.Printf("Theme: %s\nPrimary: %v\nSecondary: %v\nBackground: %v\nForeground: %v\nFont Style: %s\nFont Size: %d\nBorder Style: %s\nBorder Width: %d\n\n",
			name, theme.Primary, theme.Secondary, theme.Background, theme.Foreground, theme.FontStyle, theme.FontSize, theme.BorderStyle, theme.BorderWidth)
	}
}

// SaveCurrentTheme saves the current theme to a file.
func (tm *ThemeManager) SaveCurrentTheme(filename string) error {
	data, err := json.MarshalIndent(tm.currentTheme, "", "  ")
	if err != nil {
		return err
	}

	return ioutil.WriteFile(filename, data, 0600)
}

// LoadCurrentTheme loads the current theme from a file.
func (tm *ThemeManager) LoadCurrentTheme(filename string) error {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return err
	}

	var theme Theme
	err = json.Unmarshal(data, &theme)
	if err != nil {
		return err
	}

	tm.currentTheme = theme
	return nil
}

// InitDefaultThemes initializes the ThemeManager with default themes.
func (tm *ThemeManager) InitDefaultThemes() {
	defaultTheme := Theme{
		Name:        "Default",
		Primary:     color.RGBA{R: 0, G: 122, B: 255, A: 255},
		Secondary:   color.RGBA{R: 255, G: 255, B: 255, A: 255},
		Background:  color.RGBA{R: 240, G: 240, B: 240, A: 255},
		Foreground:  color.RGBA{R: 0, G: 0, B: 0, A: 255},
		FontStyle:   "Arial",
		FontSize:    14,
		BorderStyle: "solid",
		BorderWidth: 1,
	}

	darkTheme := Theme{
		Name:        "Dark",
		Primary:     color.RGBA{R: 255, G: 165, B: 0, A: 255},
		Secondary:   color.RGBA{R: 0, G: 0, B: 0, A: 255},
		Background:  color.RGBA{R: 30, G: 30, B: 30, A: 255},
		Foreground:  color.RGBA{R: 255, G: 255, B: 255, A: 255},
		FontStyle:   "Courier New",
		FontSize:    16,
		BorderStyle: "dashed",
		BorderWidth: 2,
	}

	tm.AddTheme(defaultTheme)
	tm.AddTheme(darkTheme)
	tm.currentTheme = defaultTheme
}

// LoadOrInitThemes loads themes from a file or initializes default themes if the file doesn't exist.
func (tm *ThemeManager) LoadOrInitThemes(filename string) error {
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		tm.InitDefaultThemes()
		return tm.SaveThemes(filename)
	}

	return tm.LoadThemes(filename)
}
