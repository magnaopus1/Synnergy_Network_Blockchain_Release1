package commands

import (
	"encoding/json"
	"fmt"
	"log"
	"os"

	"github.com/spf13/cobra"
	"synnergy_network_blockchain/pkg/synnergy_network/core/wallet/notifications"
)

var (
	alertFilePath        string
	alertType            int
	alertDescription     string
	alertID              string
	notificationSettings string
	notificationMessage  string
	userID               string
)

func init() {
	rootCmd.AddCommand(alertCmd)
	rootCmd.AddCommand(notificationSettingsCmd)
	rootCmd.AddCommand(realTimeNotificationCmd)

	alertCmd.AddCommand(addAlertCmd)
	alertCmd.AddCommand(handleAlertCmd)
	alertCmd.AddCommand(listAlertsCmd)

	notificationSettingsCmd.AddCommand(getNotificationSettingsCmd)
	notificationSettingsCmd.AddCommand(updateNotificationSettingsCmd)

	realTimeNotificationCmd.AddCommand(sendRealTimeNotificationCmd)
	realTimeNotificationCmd.AddCommand(listenRealTimeNotificationCmd)
}

var rootCmd = &cobra.Command{
	Use:   "walletNotificationCli",
	Short: "CLI for wallet notification operations",
	Long:  "CLI for performing various notification operations within the Synnergy Network Blockchain wallet.",
}

var alertCmd = &cobra.Command{
	Use:   "alert",
	Short: "Manage alerts",
}

var addAlertCmd = &cobra.Command{
	Use:   "add",
	Short: "Add a new alert",
	Run: func(cmd *cobra.Command, args []string) {
		am := notifications.NewAlertManager(alertFilePath)
		if err := am.LoadAlerts(); err != nil {
			log.Fatalf("Error loading alerts: %v", err)
		}
		if err := am.AddAlert(notifications.AlertType(alertType), alertDescription); err != nil {
			log.Fatalf("Error adding alert: %v", err)
		}
		fmt.Println("Alert added successfully.")
	},
}

var handleAlertCmd = &cobra.Command{
	Use:   "handle",
	Short: "Handle an existing alert",
	Run: func(cmd *cobra.Command, args []string) {
		am := notifications.NewAlertManager(alertFilePath)
		if err := am.LoadAlerts(); err != nil {
			log.Fatalf("Error loading alerts: %v", err)
		}
		if err := am.HandleAlert(alertID); err != nil {
			log.Fatalf("Error handling alert: %v", err)
		}
		fmt.Println("Alert handled successfully.")
	},
}

var listAlertsCmd = &cobra.Command{
	Use:   "list",
	Short: "List all alerts",
	Run: func(cmd *cobra.Command, args []string) {
		am := notifications.NewAlertManager(alertFilePath)
		if err := am.LoadAlerts(); err != nil {
			log.Fatalf("Error loading alerts: %v", err)
		}
		alerts, err := am.ListAlerts()
		if err != nil {
			log.Fatalf("Error listing alerts: %v", err)
		}
		data, err := json.MarshalIndent(alerts, "", "  ")
		if err != nil {
			log.Fatalf("Error marshalling alerts: %v", err)
		}
		fmt.Println(string(data))
	},
}

var notificationSettingsCmd = &cobra.Command{
	Use:   "settings",
	Short: "Manage notification settings",
}

var getNotificationSettingsCmd = &cobra.Command{
	Use:   "get",
	Short: "Get current notification settings",
	Run: func(cmd *cobra.Command, args []string) {
		ns := notifications.NewNotificationSettings()
		settings := ns.GetSettings()
		data, err := json.MarshalIndent(settings, "", "  ")
		if err != nil {
			log.Fatalf("Error marshalling settings: %v", err)
		}
		fmt.Println(string(data))
	},
}

var updateNotificationSettingsCmd = &cobra.Command{
	Use:   "update",
	Short: "Update notification settings",
	Run: func(cmd *cobra.Command, args []string) {
		ns := notifications.NewNotificationSettings()
		if notificationSettings != "" {
			var settings map[string]bool
			if err := json.Unmarshal([]byte(notificationSettings), &settings); err != nil {
				log.Fatalf("Error unmarshalling settings: %v", err)
			}
			if settings["emailEnabled"] {
				ns.EnableEmailNotifications()
			} else {
				ns.DisableEmailNotifications()
			}
			if settings["pushEnabled"] {
				ns.EnablePushNotifications()
			} else {
				ns.DisablePushNotifications()
			}
			if settings["smsEnabled"] {
				ns.EnableSMSNotifications()
			} else {
				ns.DisableSMSNotifications()
			}
			if settings["securityAlerts"] {
				ns.EnableSecurityAlerts()
			} else {
				ns.DisableSecurityAlerts()
			}
			if settings["transactionUpdates"] {
				ns.EnableTransactionUpdates()
			} else {
				ns.DisableTransactionUpdates()
			}
			if settings["performanceMetrics"] {
				ns.EnablePerformanceMetrics()
			} else {
				ns.DisablePerformanceMetrics()
			}
		}
		if err := ns.ValidateSettings(); err != nil {
			log.Fatalf("Error validating settings: %v", err)
		}
		fmt.Println("Notification settings updated successfully.")
	},
}

var realTimeNotificationCmd = &cobra.Command{
	Use:   "realTime",
	Short: "Manage real-time notifications",
}

var sendRealTimeNotificationCmd = &cobra.Command{
	Use:   "send",
	Short: "Send a real-time notification",
	Run: func(cmd *cobra.Command, args []string) {
		mailer := notifications.NewMailer("smtp.example.com", "no-reply@example.com", "password")
		wsPool := notifications.NewWebSocketPool()
		ns := notifications.NewNotificationService("encryptionKey123", mailer, wsPool)

		message := notifications.NotificationMessage{
			Title:   "Alert",
			Content: notificationMessage,
		}

		if err := ns.SendNotification(userID, message); err != nil {
			log.Fatalf("Failed to send notification: %v", err)
		}
		fmt.Println("Real-time notification sent successfully.")
	},
}

var listenRealTimeNotificationCmd = &cobra.Command{
	Use:   "listen",
	Short: "Listen for real-time notifications",
	Run: func(cmd *cobra.Command, args []string) {
		nm := notifications.NewNotificationManager()
		if err := nm.Connect("ws://notification-server:port"); err != nil {
			log.Fatalf("Failed to connect to notification server: %v", err)
		}
		nm.ListenForNotifications()
	},
}

func main() {
	rootCmd.PersistentFlags().StringVar(&alertFilePath, "alertFilePath", "alerts.json", "Path to the alerts file")
	rootCmd.PersistentFlags().IntVar(&alertType, "alertType", 0, "Type of alert (0=Security, 1=Transaction, 2=System)")
	rootCmd.PersistentFlags().StringVar(&alertDescription, "alertDescription", "", "Description of the alert")
	rootCmd.PersistentFlags().StringVar(&alertID, "alertID", "", "ID of the alert to handle")
	rootCmd.PersistentFlags().StringVar(&notificationSettings, "notificationSettings", "", "JSON string of notification settings to update")
	rootCmd.PersistentFlags().StringVar(&notificationMessage, "notificationMessage", "", "Content of the notification message")
	rootCmd.PersistentFlags().StringVar(&userID, "userID", "", "User ID to send the notification to")

	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
