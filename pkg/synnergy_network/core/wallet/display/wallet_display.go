package display

import (
	"errors"
	"fmt"
	"image/color"
	"log"
	"os"
	"strings"
	"sync"

	"github.com/fyne-io/fyne/v2"
	"github.com/fyne-io/fyne/v2/app"
	"github.com/fyne-io/fyne/v2/container"
	"github.com/fyne-io/fyne/v2/widget"
)

// WalletDisplay manages the display of the wallet interface.
type WalletDisplay struct {
	app        fyne.App
	window     fyne.Window
	dashboard  *fyne.Container
	themeMgr   *ThemeManager
	widgets    map[string]fyne.CanvasObject
	widgetLock sync.Mutex
}

// NewWalletDisplay creates a new WalletDisplay instance.
func NewWalletDisplay() *WalletDisplay {
	walletApp := app.New()
	w := walletApp.NewWindow("Synnergy Wallet")

	wd := &WalletDisplay{
		app:      walletApp,
		window:   w,
		dashboard: container.NewVBox(),
		themeMgr: NewThemeManager(),
		widgets:  make(map[string]fyne.CanvasObject),
	}

	// Initialize default themes or load from file
	err := wd.themeMgr.LoadOrInitThemes("themes.json")
	if err != nil {
		log.Fatalf("Failed to load or initialize themes: %v", err)
	}

	// Apply default theme
	wd.applyCurrentTheme()

	// Set up dashboard layout
	wd.window.SetContent(container.NewBorder(nil, nil, nil, nil, wd.dashboard))
	wd.window.Resize(fyne.NewSize(800, 600))

	return wd
}

// Run starts the wallet display application.
func (wd *WalletDisplay) Run() {
	wd.window.ShowAndRun()
}

// AddWidget adds a new widget to the dashboard.
func (wd *WalletDisplay) AddWidget(name string, widget fyne.CanvasObject) {
	wd.widgetLock.Lock()
	defer wd.widgetLock.Unlock()

	if _, exists := wd.widgets[name]; exists {
		return
	}

	wd.widgets[name] = widget
	wd.dashboard.Add(widget)
}

// RemoveWidget removes a widget from the dashboard.
func (wd *WalletDisplay) RemoveWidget(name string) error {
	wd.widgetLock.Lock()
	defer wd.widgetLock.Unlock()

	w, exists := wd.widgets[name]
	if !exists {
		return errors.New("widget not found")
	}

	wd.dashboard.Remove(w)
	delete(wd.widgets, name)
	return nil
}

// CustomizeDashboard allows the user to customize the layout of the dashboard.
func (wd *WalletDisplay) CustomizeDashboard() {
	// Example implementation of a customization dialog
	dialog := widget.NewEntry()
	dialog.SetPlaceHolder("Enter widget name to add")
	addButton := widget.NewButton("Add Widget", func() {
		name := dialog.Text
		if name != "" {
			wd.AddWidget(name, widget.NewLabel(fmt.Sprintf("Widget: %s", name)))
		}
	})
	wd.window.SetContent(container.NewVBox(dialog, addButton, wd.dashboard))
}

// ApplyTheme applies a specified theme.
func (wd *WalletDisplay) ApplyTheme(themeName string) error {
	err := wd.themeMgr.ApplyTheme(themeName)
	if err != nil {
		return err
	}
	wd.applyCurrentTheme()
	return nil
}

// applyCurrentTheme applies the current theme settings to the application.
func (wd *WalletDisplay) applyCurrentTheme() {
	theme := wd.themeMgr.GetCurrentTheme()

	// Example of applying primary color as background
	wd.window.Canvas().SetContent(container.NewMax(
		canvas.NewRectangle(theme.Background),
		wd.dashboard,
	))
}

// SaveTheme saves the current theme to a file.
func (wd *WalletDisplay) SaveTheme(filename string) error {
	return wd.themeMgr.SaveCurrentTheme(filename)
}

// LoadTheme loads the current theme from a file.
func (wd *WalletDisplay) LoadTheme(filename string) error {
	err := wd.themeMgr.LoadCurrentTheme(filename)
	if err != nil {
		return err
	}
	wd.applyCurrentTheme()
	return nil
}

// InitializeWidgets initializes default widgets on the dashboard.
func (wd *WalletDisplay) InitializeWidgets() {
	balanceWidget := widget.NewLabel("Balance: 0 SYN")
	transactionWidget := widget.NewLabel("Recent Transactions")
	notificationWidget := widget.NewLabel("Notifications")

	wd.AddWidget("balance", balanceWidget)
	wd.AddWidget("transactions", transactionWidget)
	wd.AddWidget("notifications", notificationWidget)
}

// CustomizeTheme customizes the current theme with new properties.
func (wd *WalletDisplay) CustomizeTheme(name string, primary, secondary, background, foreground color.RGBA, fontStyle string, fontSize int, borderStyle string, borderWidth int) error {
	return wd.themeMgr.CustomizeTheme(name, primary, secondary, background, foreground, fontStyle, fontSize, borderStyle, borderWidth)
}

// DisplayAvailableThemes displays all available themes.
func (wd *WalletDisplay) DisplayAvailableThemes() {
	wd.themeMgr.DisplayThemes()
}

func main() {
	// Create and run the wallet display
	walletDisplay := NewWalletDisplay()
	walletDisplay.InitializeWidgets()
	walletDisplay.Run()
}
