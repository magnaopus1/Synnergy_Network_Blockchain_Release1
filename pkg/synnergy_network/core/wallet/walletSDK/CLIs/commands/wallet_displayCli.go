package commands

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"github.com/spf13/cobra"
	"synnergy_network_blockchain/pkg/synnergy_network/core/wallet/display"
)

var (
	walletID     string
	themeFile    string
	themeName    string
	primaryColor string
	secondaryColor string
	backgroundColor string
	foregroundColor string
	fontStyle    string
	fontSize     int
	borderStyle  string
	borderWidth  int
	alias        string
	walletAddress string
	enabled      bool
	locale       string
	widgetID     string
	widgetContent string
)

func init() {
	rootCmd.AddCommand(displayARCmd)
	rootCmd.AddCommand(themeCmd)
	rootCmd.AddCommand(voiceCmd)
	rootCmd.AddCommand(aliasCmd)
	rootCmd.AddCommand(widgetCmd)
}

var rootCmd = &cobra.Command{
	Use:   "walletDisplayCli",
	Short: "CLI for wallet display operations",
	Long:  "CLI for performing various display operations within the Synnergy Network Blockchain wallet.",
}

var displayARCmd = &cobra.Command{
	Use:   "displayAR",
	Short: "Display AR information for a wallet",
	Run: func(cmd *cobra.Command, args []string) {
		data, err := display.FetchARData(walletID)
		if err != nil {
			log.Fatalf("Error fetching AR data: %v", err)
		}

		jsonData, err := json.MarshalIndent(data, "", "  ")
		if err != nil {
			log.Fatalf("Error marshalling data to JSON: %v", err)
		}

		fmt.Println(string(jsonData))
	},
}

var themeCmd = &cobra.Command{
	Use:   "theme",
	Short: "Manage wallet display themes",
	Run: func(cmd *cobra.Command, args []string) {
		tm := display.NewThemeManager(themeFile)
		err := tm.LoadOrInitThemes(themeFile)
		if err != nil {
			log.Fatalf("Error loading or initializing themes: %v", err)
		}

		if themeName != "" {
			theme, exists := tm.GetCurrentTheme(themeName)
			if !exists {
				log.Fatalf("Theme %s not found", themeName)
			}

			if primaryColor != "" {
				theme.Primary = parseColor(primaryColor)
			}
			if secondaryColor != "" {
				theme.Secondary = parseColor(secondaryColor)
			}
			if backgroundColor != "" {
				theme.Background = parseColor(backgroundColor)
			}
			if foregroundColor != "" {
				theme.Foreground = parseColor(foregroundColor)
			}
			if fontStyle != "" {
				theme.FontStyle = fontStyle
			}
			if fontSize != 0 {
				theme.FontSize = fontSize
			}
			if borderStyle != "" {
				theme.BorderStyle = borderStyle
			}
			if borderWidth != 0 {
				theme.BorderWidth = borderWidth
			}

			err = tm.CustomizeTheme(themeName, theme)
			if err != nil {
				log.Fatalf("Error customizing theme: %v", err)
			}

			err = tm.SaveThemes(themeFile)
			if err != nil {
				log.Fatalf("Error saving themes: %v", err)
			}

			fmt.Println("Theme updated and saved successfully.")
		} else {
			tm.DisplayThemes()
		}
	},
}

var voiceCmd = &cobra.Command{
	Use:   "voice",
	Short: "Manage voice command settings",
	Run: func(cmd *cobra.Command, args []string) {
		err := display.InitVoiceInterface()
		if err != nil {
			log.Fatalf("Error initializing voice interface: %v", err)
		}

		if locale != "" {
			err = display.UpdateSettings(enabled, locale)
			if err != nil {
				log.Fatalf("Error updating voice command settings: %v", err)
			}
			fmt.Println("Voice command settings updated.")
		} else {
			settings, err := json.MarshalIndent(display.CurrentSettings(), "", "  ")
			if err != nil {
				log.Fatalf("Error marshalling settings to JSON: %v", err)
			}

			fmt.Println(string(settings))
		}
	},
}

var aliasCmd = &cobra.Command{
	Use:   "alias",
	Short: "Manage wallet aliases",
	Run: func(cmd *cobra.Command, args []string) {
		wns, err := display.NewWalletNamingService("aliasStore.json")
		if err != nil {
			log.Fatalf("Error creating WalletNamingService: %v", err)
		}

		if alias != "" && walletAddress != "" {
			err := wns.RegisterAlias(alias, walletAddress)
			if err != nil {
				log.Fatalf("Error registering alias: %v", err)
			}
			fmt.Println("Alias registered successfully.")
		} else if alias != "" {
			address, err := wns.ResolveAlias(alias)
			if err != nil {
				log.Fatalf("Error resolving alias: %v", err)
			}
			fmt.Printf("Alias %s resolved to address %s\n", alias, address)
		} else {
			log.Fatalf("Alias and wallet address are required.")
		}
	},
}

var widgetCmd = &cobra.Command{
	Use:   "widget",
	Short: "Manage wallet display widgets",
	Run: func(cmd *cobra.Command, args []string) {
		app := app.New()
		window := app.NewWindow("Wallet Widgets")

		wm := display.NewWidgetManager(app, window, func(eventName string, details map[string]interface{}) {
			log.Printf("Event: %s, Details: %v\n", eventName, details)
		})

		if widgetID != "" {
			if widgetContent != "" {
				err := wm.AddWidget(widgetID, widget.NewLabel(widgetContent))
				if err != nil {
					log.Fatalf("Error adding widget: %v", err)
				}
				fmt.Println("Widget added successfully.")
			} else {
				widget, err := wm.GetWidget(widgetID)
				if err != nil {
					log.Fatalf("Error getting widget: %v", err)
				}
				fmt.Printf("Widget ID: %s, Content: %v\n", widgetID, widget)
			}
		} else {
			ids := wm.ListWidgets()
			fmt.Println("Widget IDs:", ids)
		}

		window.ShowAndRun()
	},
}

func parseColor(hexStr string) color.RGBA {
	c, err := hex.DecodeString(hexStr)
	if err != nil {
		log.Fatalf("Invalid color format: %v", err)
	}
	return color.RGBA{R: c[0], G: c[1], B: c[2], A: 255}
}

func main() {
	rootCmd.PersistentFlags().StringVar(&walletID, "walletID", "", "Wallet ID for AR display")
	rootCmd.PersistentFlags().StringVar(&themeFile, "themeFile", "themes.json", "File to load/save themes")
	rootCmd.PersistentFlags().StringVar(&themeName, "themeName", "", "Theme name to apply or customize")
	rootCmd.PersistentFlags().StringVar(&primaryColor, "primaryColor", "", "Primary color in hex")
	rootCmd.PersistentFlags().StringVar(&secondaryColor, "secondaryColor", "", "Secondary color in hex")
	rootCmd.PersistentFlags().StringVar(&backgroundColor, "backgroundColor", "", "Background color in hex")
	rootCmd.PersistentFlags().StringVar(&foregroundColor, "foregroundColor", "", "Foreground color in hex")
	rootCmd.PersistentFlags().StringVar(&fontStyle, "fontStyle", "", "Font style")
	rootCmd.PersistentFlags().IntVar(&fontSize, "fontSize", 0, "Font size")
	rootCmd.PersistentFlags().StringVar(&borderStyle, "borderStyle", "", "Border style")
	rootCmd.PersistentFlags().IntVar(&borderWidth, "borderWidth", 0, "Border width")
	rootCmd.PersistentFlags().StringVar(&alias, "alias", "", "Alias for wallet address")
	rootCmd.PersistentFlags().StringVar(&walletAddress, "walletAddress", "", "Wallet address")
	rootCmd.PersistentFlags().BoolVar(&enabled, "enabled", false, "Enable or disable setting")
	rootCmd.PersistentFlags().StringVar(&locale, "locale", "", "Locale for voice commands")
	rootCmd.PersistentFlags().StringVar(&widgetID, "widgetID", "", "Widget ID")
	rootCmd.PersistentFlags().StringVar(&widgetContent, "widgetContent", "", "Widget content")

	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
