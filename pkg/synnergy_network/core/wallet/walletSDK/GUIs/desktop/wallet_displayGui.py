import tkinter as tk
from tkinter import messagebox, simpledialog
import requests
import json

class WalletDisplayGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Wallet Display GUI")
        
        self.create_widgets()

    def create_widgets(self):
        tk.Button(self.root, text="Show AR Display", command=self.show_ar_display).pack(pady=10)
        tk.Button(self.root, text="Customize Theme", command=self.customize_theme).pack(pady=10)
        tk.Button(self.root, text="Get Voice Command Settings", command=self.get_voice_command_settings).pack(pady=10)
        tk.Button(self.root, text="Update Voice Command Settings", command=self.update_voice_command_settings).pack(pady=10)
        tk.Button(self.root, text="Manage Widgets", command=self.manage_widgets).pack(pady=10)
        tk.Button(self.root, text="Register Wallet Alias", command=self.register_wallet_alias).pack(pady=10)
        tk.Button(self.root, text="Resolve Wallet Alias", command=self.resolve_wallet_alias).pack(pady=10)
        tk.Button(self.root, text="Remove Wallet Alias", command=self.remove_wallet_alias).pack(pady=10)
        
    def show_ar_display(self):
        wallet_id = simpledialog.askstring("Input", "Enter Wallet ID:")
        response = requests.get(f"http://localhost:8000/api/ar_display?wallet_id={wallet_id}")
        if response.status_code == 200:
            data = response.json().get("data", {})
            messagebox.showinfo("AR Display Data", json.dumps(data, indent=4))
        else:
            messagebox.showerror("Error", response.json().get("message", "Failed to show AR display"))

    def customize_theme(self):
        theme_name = simpledialog.askstring("Input", "Enter Theme Name:")
        primary = simpledialog.askstring("Input", "Enter Primary Color (e.g., #RRGGBB):")
        secondary = simpledialog.askstring("Input", "Enter Secondary Color (e.g., #RRGGBB):")
        background = simpledialog.askstring("Input", "Enter Background Color (e.g., #RRGGBB):")
        foreground = simpledialog.askstring("Input", "Enter Foreground Color (e.g., #RRGGBB):")
        
        theme_data = {
            "name": theme_name,
            "primary": primary,
            "secondary": secondary,
            "background": background,
            "foreground": foreground
        }

        response = requests.post("http://localhost:8000/api/theme_customization", json=theme_data)
        if response.status_code == 200:
            messagebox.showinfo("Success", "Theme customized successfully")
        else:
            messagebox.showerror("Error", response.json().get("message", "Failed to customize theme"))

    def get_voice_command_settings(self):
        response = requests.get("http://localhost:8000/api/voice_command")
        if response.status_code == 200:
            data = response.json().get("data", {})
            messagebox.showinfo("Voice Command Settings", json.dumps(data, indent=4))
        else:
            messagebox.showerror("Error", response.json().get("message", "Failed to get voice command settings"))

    def update_voice_command_settings(self):
        enabled = simpledialog.askstring("Input", "Enable Voice Command? (true/false):")
        locale = simpledialog.askstring("Input", "Enter Locale (e.g., en-US):")

        settings_data = {
            "enabled": enabled.lower() == "true",
            "locale": locale
        }

        response = requests.post("http://localhost:8000/api/voice_command", json=settings_data)
        if response.status_code == 204:
            messagebox.showinfo("Success", "Voice command settings updated successfully")
        else:
            messagebox.showerror("Error", response.json().get("message", "Failed to update voice command settings"))

    def manage_widgets(self):
        action = simpledialog.askstring("Input", "Enter action (add/remove/list):")
        if action == "add":
            widget_id = simpledialog.askstring("Input", "Enter Widget ID:")
            widget_type = simpledialog.askstring("Input", "Enter Widget Type (e.g., label, button):")
            widget_content = simpledialog.askstring("Input", "Enter Widget Content:")

            widget_data = {
                "id": widget_id,
                "widget": {
                    "type": widget_type,
                    "content": widget_content
                }
            }

            response = requests.post("http://localhost:8000/api/widget_management", json=widget_data)
            if response.status_code == 201:
                messagebox.showinfo("Success", "Widget added successfully")
            else:
                messagebox.showerror("Error", response.json().get("message", "Failed to add widget"))

        elif action == "remove":
            widget_id = simpledialog.askstring("Input", "Enter Widget ID:")
            response = requests.delete("http://localhost:8000/api/widget_management", json={"id": widget_id})
            if response.status_code == 204:
                messagebox.showinfo("Success", "Widget removed successfully")
            else:
                messagebox.showerror("Error", response.json().get("message", "Failed to remove widget"))

        elif action == "list":
            response = requests.get("http://localhost:8000/api/widget_management")
            if response.status_code == 200:
                widgets = response.json().get("data", [])
                messagebox.showinfo("Widgets", json.dumps(widgets, indent=4))
            else:
                messagebox.showerror("Error", response.json().get("message", "Failed to list widgets"))

    def register_wallet_alias(self):
        alias = simpledialog.askstring("Input", "Enter Alias:")
        address = simpledialog.askstring("Input", "Enter Wallet Address:")

        alias_data = {
            "alias": alias,
            "address": address
        }

        response = requests.post("http://localhost:8000/api/wallet_naming", json=alias_data)
        if response.status_code == 201:
            messagebox.showinfo("Success", "Alias registered successfully")
        else:
            messagebox.showerror("Error", response.json().get("message", "Failed to register alias"))

    def resolve_wallet_alias(self):
        alias = simpledialog.askstring("Input", "Enter Alias:")
        response = requests.get(f"http://localhost:8000/api/wallet_naming?alias={alias}")
        if response.status_code == 200:
            address = response.json().get("data", "")
            messagebox.showinfo("Wallet Address", address)
        else:
            messagebox.showerror("Error", response.json().get("message", "Failed to resolve alias"))

    def remove_wallet_alias(self):
        alias = simpledialog.askstring("Input", "Enter Alias:")
        response = requests.delete("http://localhost:8000/api/wallet_naming", json={"alias": alias})
        if response.status_code == 204:
            messagebox.showinfo("Success", "Alias removed successfully")
        else:
            messagebox.showerror("Error", response.json().get("message", "Failed to remove alias"))

if __name__ == "__main__":
    root = tk.Tk()
    app = WalletDisplayGUI(root)
    root.mainloop()
