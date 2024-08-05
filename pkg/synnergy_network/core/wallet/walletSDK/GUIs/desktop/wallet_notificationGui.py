import tkinter as tk
from tkinter import messagebox, simpledialog
import requests
import json

class WalletNotificationGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Wallet Notification GUI")

        self.create_widgets()

    def create_widgets(self):
        tk.Button(self.root, text="Add Alert", command=self.add_alert).pack(pady=10)
        tk.Button(self.root, text="List Alerts", command=self.list_alerts).pack(pady=10)
        tk.Button(self.root, text="Handle Alert", command=self.handle_alert).pack(pady=10)
        tk.Button(self.root, text="Send Notification", command=self.send_notification).pack(pady=10)
        tk.Button(self.root, text="Update Notification Settings", command=self.update_notification_settings).pack(pady=10)
        tk.Button(self.root, text="Connect WebSocket", command=self.connect_websocket).pack(pady=10)

    def add_alert(self):
        alert_type = simpledialog.askinteger("Input", "Enter Alert Type (0: Security, 1: Transaction, 2: System):")
        description = simpledialog.askstring("Input", "Enter Description:")

        alert_data = {
            "type": alert_type,
            "description": description
        }

        response = requests.post("http://localhost:8000/api/add_alert", json=alert_data)
        if response.status_code == 200:
            messagebox.showinfo("Success", "Alert added successfully")
        else:
            messagebox.showerror("Error", response.json().get("message", "Failed to add alert"))

    def list_alerts(self):
        response = requests.get("http://localhost:8000/api/list_alerts")
        if response.status_code == 200:
            alerts = response.json().get("data", [])
            alert_list = "\n".join([f"ID: {alert['id']}, Type: {alert['type']}, Description: {alert['description']}, Handled: {alert['handled']}" for alert in alerts])
            messagebox.showinfo("Alerts", alert_list)
        else:
            messagebox.showerror("Error", response.json().get("message", "Failed to list alerts"))

    def handle_alert(self):
        alert_id = simpledialog.askstring("Input", "Enter Alert ID to Handle:")

        response = requests.post(f"http://localhost:8000/api/handle_alert/{alert_id}")
        if response.status_code == 200:
            messagebox.showinfo("Success", "Alert handled successfully")
        else:
            messagebox.showerror("Error", response.json().get("message", "Failed to handle alert"))

    def send_notification(self):
        user_id = simpledialog.askstring("Input", "Enter User ID:")
        title = simpledialog.askstring("Input", "Enter Notification Title:")
        content = simpledialog.askstring("Input", "Enter Notification Content:")

        notification_data = {
            "user_id": user_id,
            "message": {
                "title": title,
                "content": content
            }
        }

        response = requests.post("http://localhost:8000/api/send_notification", json=notification_data)
        if response.status_code == 200:
            messagebox.showinfo("Success", "Notification sent successfully")
        else:
            messagebox.showerror("Error", response.json().get("message", "Failed to send notification"))

    def update_notification_settings(self):
        email_enabled = messagebox.askyesno("Input", "Enable Email Notifications?")
        push_enabled = messagebox.askyesno("Input", "Enable Push Notifications?")
        sms_enabled = messagebox.askyesno("Input", "Enable SMS Notifications?")
        security_alerts = messagebox.askyesno("Input", "Enable Security Alerts?")
        transaction_updates = messagebox.askyesno("Input", "Enable Transaction Updates?")
        performance_metrics = messagebox.askyesno("Input", "Enable Performance Metrics?")

        settings_data = {
            "email_enabled": email_enabled,
            "push_enabled": push_enabled,
            "sms_enabled": sms_enabled,
            "security_alerts": security_alerts,
            "transaction_updates": transaction_updates,
            "performance_metrics": performance_metrics
        }

        response = requests.post("http://localhost:8000/api/update_notification_settings", json=settings_data)
        if response.status_code == 200:
            messagebox.showinfo("Success", "Notification settings updated successfully")
        else:
            messagebox.showerror("Error", response.json().get("message", "Failed to update notification settings"))

    def connect_websocket(self):
        response = requests.get("http://localhost:8000/api/connect_websocket")
        if response.status_code == 200:
            messagebox.showinfo("Success", "WebSocket connection established")
        else:
            messagebox.showerror("Error", response.json().get("message", "Failed to connect to WebSocket"))

if __name__ == "__main__":
    root = tk.Tk()
    app = WalletNotificationGUI(root)
    root.mainloop()
