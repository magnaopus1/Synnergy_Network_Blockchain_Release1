package display

import (
	"context"
	"encoding/json"
	"net/http"
	"sync"

	"github.com/goar3/goar"
	"github.com/synnergy-network/core/wallet/utils"
	"synnergy-network/blockchain"
	"synnergy-network/blockchain/crypto"
)

// ARData represents the data structure for AR display information
type ARData struct {
	WalletID      string  `json:"wallet_id"`
	Balance       float64 `json:"balance"`
	RecentTx      []Transaction `json:"recent_tx"`
	Notifications []string `json:"notifications"`
}

// Transaction simplifies transaction data for AR display
type Transaction struct {
	TxID    string `json:"tx_id"`
	Amount  float64 `json:"amount"`
	To      string `json:"to"`
	From    string `json:"from"`
	IsDebit bool   `json:"is_debit"`
}

var (
	arDisplayService *goar.ARDisplayService
	arMutex          sync.Mutex
)

func init() {
	var err error
	arDisplayService, err = goar.NewARDisplayService("http://ar-display-host:port")
	if err != nil {
		panic(err)
	}
}

// HandleWalletARDisplay responds to HTTP requests to render wallet AR displays
func HandleWalletARDisplay(w http.ResponseWriter, r *http.Request) {
	walletID := r.URL.Query().Get("wallet_id")
	if walletID == "" {
		http.Error(w, "Wallet ID is required", http.StatusBadRequest)
		return
	}

	arMutex.Lock()
	defer arMutex.Unlock()

	data, err := fetchARData(walletID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	response, err := json.Marshal(data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(response)
}

// fetchARData retrieves data for AR display from blockchain and wallet systems
func fetchARData(walletID string) (*ARData, error) {
	ctx := context.Background()
	balance, err := blockchain.GetBalance(ctx, walletID)
	if err != nil {
		return nil, err
	}

	recentTx, err := blockchain.GetRecentTransactions(ctx, walletID)
	if err != nil {
		return nil, err
	}

	notifications, err := utils.FetchNotifications(ctx, walletID)
	if err != nil {
		return nil, err
	}

	arData := &ARData{
		WalletID:      walletID,
		Balance:       balance,
		RecentTx:      transformTransactions(recentTx),
		Notifications: notifications,
	}

	return arData, nil
}

// transformTransactions converts raw transaction data to a more AR-friendly format
func transformTransactions(transactions []crypto.Transaction) []Transaction {
	txData := make([]Transaction, len(transactions))
	for i, tx := range transactions {
		txData[i] = Transaction{
			TxID:    tx.TxID,
			Amount:  tx.Amount,
			To:      tx.To,
			From:    tx.From,
			IsDebit: tx.IsDebit,
		}
	}
	return txData
}
package display

import (
	"encoding/json"
	"errors"
	"fmt"
	"image/color"
	"io/ioutil"
	"os"
	"sync"

	"synnergy-network/blockchain/utils"
	"synnergy-network/core/security"
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
	themeMutex  sync.Mutex
	themes      map[string]Theme
	storagePath string
}

// NewThemeManager creates a new instance of ThemeManager.
func NewThemeManager(storagePath string) *ThemeManager {
	return &ThemeManager{
		themes:      make(map[string]Theme),
		storagePath: storagePath,
	}
}

// LoadThemes loads themes from a JSON file.
func (tm *ThemeManager) LoadThemes() error {
	tm.themeMutex.Lock()
	defer tm.themeMutex.Unlock()

	data, err := ioutil.ReadFile(tm.storagePath)
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

	return nil
}

// SaveThemes saves themes to a JSON file.
func (tm *ThemeManager) SaveThemes() error {
	tm.themeMutex.Lock()
	defer tm.themeMutex.Unlock()

	data, err := json.MarshalIndent(tm.themes, "", "  ")
	if err != nil {
		return err
	}

	return ioutil.WriteFile(tm.storagePath, data, 0600)
}

// AddTheme adds a new theme to the manager.
func (tm *ThemeManager) AddTheme(theme Theme) {
	tm.themeMutex.Lock()
	defer tm.themeMutex.Unlock()

	tm.themes[theme.Name] = theme
}

// ApplyTheme applies a theme by name.
func (tm *ThemeManager) ApplyTheme(themeName string) error {
	tm.themeMutex.Lock()
	defer tm.themeMutex.Unlock()

	theme, exists := tm.themes[themeName]
	if !exists {
		return errors.New("theme not found")
	}

	// Additional logic to change the user interface based on the theme could be implemented here
	fmt.Printf("Applied Theme: %+v\n", theme)
	return nil
}

// GetCurrentTheme returns the current theme.
func (tm *ThemeManager) GetCurrentTheme(themeName string) (Theme, bool) {
	tm.themeMutex.Lock()
	defer tm.themeMutex.Unlock()

	theme, exists := tm.themes[themeName]
	return theme, exists
}

// CustomizeTheme updates existing theme settings.
func (tm *ThemeManager) CustomizeTheme(name string, updates Theme) error {
	tm.themeMutex.Lock()
	defer tm.themeMutex.Unlock()

	if _, exists := tm.themes[name]; !exists {
		return errors.New("theme not found")
	}

	// Ensuring all updates only change non-zero values in theme
	currentTheme := tm.themes[name]
	if updates.Primary != (color.RGBA{}) {
		currentTheme.Primary = updates.Primary
	}
	if updates.Secondary != (color.RGBA{}) {
		currentTheme.Secondary = updates.Secondary
	}
	if updates.Background != (color.RGBA{}) {
		currentTheme.Background = updates.Background
	}
	if updates.Foreground != (color.RGBA{}) {
		currentTheme.Foreground = updates.Foreground
	}
	if updates.FontStyle != "" {
		currentTheme.FontStyle = updates.FontStyle
	}
	if updates.FontSize != 0 {
		currentTheme.FontSize = updates.FontSize
	}
	if updates.BorderStyle != "" {
		currentTheme.BorderStyle = updates.BorderStyle
	}
	if updates.BorderWidth != 0 {
		currentTheme.BorderWidth = updates.BorderWidth
	}

	tm.themes[name] = currentTheme
	return nil
}
package display

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"synnergy-network/blockchain/utils"
	"synnergy-network/core/security"
	"synnergy-network/core/wallet/display/voice"
)

// VoiceCommandInterface struct defines the structure for voice command settings and state.
type VoiceCommandInterface struct {
	Enabled bool   `json:"enabled"`
	Locale  string `json:"locale"`
}

var (
	// Store current settings in memory for quick access.
	currentSettings VoiceCommandInterface
)

// InitVoiceInterface initializes the voice command system with default settings.
func InitVoiceInterface() error {
	// Default settings
	currentSettings = VoiceCommandInterface{
		Enabled: false,
		Locale:  "en-US",
	}

	// Load settings from persistent storage, if available.
	if err := loadSettings(); err != nil {
		return err
	}
	return nil
}

// loadSettings retrieves settings from a secure storage mechanism.
func loadSettings() error {
	data, err := utils.LoadSecureData("voice_command_settings.json")
	if err != nil {
		return err
	}

	if err := json.Unmarshal(data, &currentSettings); err != nil {
		return err
	}
	return nil
}

// saveSettings stores the current settings securely.
func saveSettings() error {
	data, err := json.Marshal(currentSettings)
	if err != nil {
		return err
	}

	return utils.SaveSecureData("voice_command_settings.json", data)
}

// UpdateSettings updates the voice command settings.
func UpdateSettings(enabled bool, locale string) error {
	currentSettings.Enabled = enabled
	currentSettings.Locale = locale

	return saveSettings()
}

// ProcessCommand processes a voice command and performs associated actions.
func ProcessCommand(command string) (string, error) {
	if !currentSettings.Enabled {
		return "", errors.New("voice command interface is disabled")
	}

	command = strings.ToLower(command)
	switch command {
	case "check balance":
		return voice.CheckBalance(), nil
	case "send payment":
		return voice.InitiatePayment(), nil
	default:
		return "", errors.New("unknown command")
	}
}

// VoiceCommandHandler handles HTTP requests for managing voice commands.
func VoiceCommandHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		response, err := json.Marshal(currentSettings)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(response)

	case "POST":
		var settings VoiceCommandInterface
		if err := json.NewDecoder(r.Body).Decode(&settings); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		if err := UpdateSettings(settings.Enabled, settings.Locale); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}
package display

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"sync"

	"github.com/fyne-io/fyne/v2"
	"github.com/fyne-io/fyne/v2/app"
	"github.com/fyne-io/fyne/v2/canvas"
	"github.com/fyne-io/fyne/v2/container"
	"github.com/fyne-io/fyne/v2/widget"
	"synnergy-network/blockchain/utils"
	"synnergy-network/core/security"
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
package display

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sync"

	"synnergy-network/blockchain/address"
	"synnergy-network/blockchain/utils"
	"synnergy-network/core/security"
	"synnergy-network/wallet/storage"
)

// WalletNamingService manages the association of human-readable aliases with blockchain addresses.
type WalletNamingService struct {
	store   storage.KVStore
	mutex   sync.RWMutex
	aliases map[string]string // maps aliases to wallet addresses
}

// NewWalletNamingService creates a new instance of WalletNamingService.
func NewWalletNamingService(storePath string) (*WalletNamingService, error) {
	store, err := storage.NewKVStore(storePath)
	if err != nil {
		return nil, err
	}

	service := &WalletNamingService{
		store:   store,
		aliases: make(map[string]string),
	}
	if err := service.loadAliases(); err != nil {
		return nil, err
	}
	return service, nil
}

// RegisterAlias registers a new alias for a wallet address, ensuring that the alias is unique and valid.
func (wns *WalletNamingService) RegisterAlias(alias, address string) error {
	wns.mutex.Lock()
	defer wns.mutex.Unlock()

	if _, exists := wns.aliases[alias]; exists {
		return errors.New("alias already in use")
	}

	if !address.IsValidAddress(address) {
		return errors.New("invalid wallet address")
	}

	wns.aliases[alias] = address
	wns.store.Set(alias, address)
	return nil
}

// ResolveAlias resolves an alias to a wallet address.
func (wns *WalletNamingService) ResolveAlias(alias string) (string, error) {
	wns.mutex.RLock()
	defer wns.mutex.RUnlock()

	address, exists := wns.aliases[alias]
	if !exists {
		return "", errors.New("alias not found")
	}
	return address, nil
}

// RemoveAlias removes an existing alias.
func (wns *WalletNamingService) RemoveAlias(alias string) error {
	wns.mutex.Lock()
	defer wns.mutex.Unlock()

	if _, exists := wns.aliases[alias]; !exists {
		return errors.New("alias not found")
	}

	delete(wns.aliases, alias)
	wns.store.Delete(alias)
	return nil
}

// loadAliases loads all aliases from the storage.
func (wns *WalletNamingService) loadAliases() error {
	entries, err := wns.store.GetAll()
	if err != nil {
		return err
	}

	for alias, address := range entries {
		wns.aliases[alias] = address
	}
	return nil
}

// hashAlias creates a hash of the alias to ensure it meets security standards before storage.
func hashAlias(alias string) string {
	hash := sha256.Sum256([]byte(alias))
	return hex.EncodeToString(hash[:])
}
package display

import (
	"errors"
	"log"
	"sync"

	"github.com/fyne-io/fyne/v2"
	"github.com/fyne-io/fyne/v2/widget"
)

// WidgetManager manages the dynamic creation and destruction of widgets within the wallet GUI.
type WidgetManager struct {
	app          fyne.App
	window       fyne.Window
	widgets      map[string]fyne.CanvasObject
	widgetLock   sync.RWMutex
	eventHandler func(eventName string, details map[string]interface{})
}

// NewWidgetManager creates a new WidgetManager to handle widgets dynamically.
func NewWidgetManager(app fyne.App, window fyne.Window, eventHandler func(eventName string, details map[string]interface{})) *WidgetManager {
	return &WidgetManager{
		app:          app,
		window:       window,
		widgets:      make(map[string]fyne.CanvasObject),
		eventHandler: eventHandler,
	}
}

// AddWidget adds a new widget to the GUI.
func (wm *WidgetManager) AddWidget(id string, widget fyne.CanvasObject) error {
	wm.widgetLock.Lock()
	defer wm.widgetLock.Unlock()

	if _, exists := wm.widgets[id]; exists {
		return errors.New("widget already exists")
	}

	wm.widgets[id] = widget
	wm.window.Content().Add(widget)
	wm.eventHandler("widget_added", map[string]interface{}{"id": id})
	return nil
}

// RemoveWidget removes a widget from the GUI.
func (wm *WidgetManager) RemoveWidget(id string) error {
	wm.widgetLock.Lock()
	defer wm.widgetLock.Unlock()

	widget, exists := wm.widgets[id]
	if !exists {
		return errors.New("widget not found")
	}

	wm.window.Content().Remove(widget)
	delete(wm.widgets, id)
	wm.eventHandler("widget_removed", map[string]interface{}{"id": id})
	return nil
}

// UpdateWidget updates an existing widget with a new one.
func (wm *WidgetManager) UpdateWidget(id string, newWidget fyne.CanvasObject) error {
	wm.widgetLock.Lock()
	defer wm.widgetLock.Unlock()

	if _, exists := wm.widgets[id]; !exists {
		return errors.New("widget not found for update")
	}

	wm.window.Content().Remove(wm.widgets[id])
	wm.widgets[id] = newWidget
	wm.window.Content().Add(newWidget)
	wm.eventHandler("widget_updated", map[string]interface{}{"id": id})
	return nil
}

// GetWidget returns a widget by its ID.
func (wm *WidgetManager) GetWidget(id string) (fyne.CanvasObject, error) {
	wm.widgetLock.RLock()
	defer wm.widgetLock.RUnlock()

	widget, exists := wm.widgets[id]
	if !exists {
		return nil, errors.New("widget not found")
	}
	return widget, nil
}

// ListWidgets returns a list of all current widget IDs.
func (wm *WidgetManager) ListWidgets() []string {
	wm.widgetLock.RLock()
	defer wm.widgetLock.RUnlock()

	ids := make([]string, 0, len(wm.widgets))
	for id := range wm.widgets {
		ids = append(ids, id)
	}
	return ids
}

func main() {
	// Setup Fyne application
	app := app.New()
	window := app.NewWindow("Wallet Widgets")

	// Initialize Widget Manager
	wm := NewWidgetManager(app, window, func(eventName string, details map[string]interface{}) {
		log.Printf("Event: %s, Details: %v\n", eventName, details)
	})

	// Example widgets
	balanceWidget := widget.NewLabel("Balance: 1000")
	transactionWidget := widget.NewLabel("Last Transaction: -100")

	// Adding widgets
	if err := wm.AddWidget("balance", balanceWidget); err != nil {
		log.Println("Failed to add balance widget:", err)
	}
	if err := wm.AddWidget("last_transaction", transactionWidget); err != nil {
		log.Println("Failed to add transaction widget:", err)
	}

	// Run application
	window.ShowAndRun()
}
