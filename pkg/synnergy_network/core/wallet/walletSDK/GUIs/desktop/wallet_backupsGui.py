import tkinter as tk
from tkinter import messagebox, scrolledtext, filedialog
import requests
import json
import os

API_BASE_URL = os.getenv("API_BASE_URL", "http://localhost:8080")

class WalletBackupsGUI(tk.Tk):
    def __init__(self):
        super().__init__()

        self.title("Wallet Backups")
        self.geometry("800x600")

        self.create_widgets()

    def create_widgets(self):
        # Encrypt Data Section
        encrypt_frame = tk.LabelFrame(self, text="Encrypt Data", padx=10, pady=10)
        encrypt_frame.pack(fill="both", expand="yes", padx=10, pady=10)

        tk.Label(encrypt_frame, text="Data:").pack(anchor=tk.W)
        self.encrypt_data_entry = tk.Entry(encrypt_frame, width=50)
        self.encrypt_data_entry.pack(pady=5)

        tk.Label(encrypt_frame, text="Passphrase:").pack(anchor=tk.W)
        self.encrypt_passphrase_entry = tk.Entry(encrypt_frame, show='*', width=50)
        self.encrypt_passphrase_entry.pack(pady=5)

        tk.Button(encrypt_frame, text="Encrypt", command=self.encrypt_data).pack(pady=5)

        self.encrypt_result_text = scrolledtext.ScrolledText(encrypt_frame, height=5)
        self.encrypt_result_text.pack(fill="both", padx=10, pady=10)

        # Decrypt Data Section
        decrypt_frame = tk.LabelFrame(self, text="Decrypt Data", padx=10, pady=10)
        decrypt_frame.pack(fill="both", expand="yes", padx=10, pady=10)

        tk.Label(decrypt_frame, text="Encrypted Data:").pack(anchor=tk.W)
        self.decrypt_data_entry = tk.Entry(decrypt_frame, width=50)
        self.decrypt_data_entry.pack(pady=5)

        tk.Label(decrypt_frame, text="Passphrase:").pack(anchor=tk.W)
        self.decrypt_passphrase_entry = tk.Entry(decrypt_frame, show='*', width=50)
        self.decrypt_passphrase_entry.pack(pady=5)

        tk.Button(decrypt_frame, text="Decrypt", command=self.decrypt_data).pack(pady=5)

        self.decrypt_result_text = scrolledtext.ScrolledText(decrypt_frame, height=5)
        self.decrypt_result_text.pack(fill="both", padx=10, pady=10)

        # Backup Data Section
        backup_frame = tk.LabelFrame(self, text="Backup Data", padx=10, pady=10)
        backup_frame.pack(fill="both", expand="yes", padx=10, pady=10)

        tk.Label(backup_frame, text="User ID:").pack(anchor=tk.W)
        self.backup_user_id_entry = tk.Entry(backup_frame, width=50)
        self.backup_user_id_entry.pack(pady=5)

        tk.Label(backup_frame, text="Data:").pack(anchor=tk.W)
        self.backup_data_entry = tk.Entry(backup_frame, width=50)
        self.backup_data_entry.pack(pady=5)

        tk.Label(backup_frame, text="Passphrase:").pack(anchor=tk.W)
        self.backup_passphrase_entry = tk.Entry(backup_frame, show='*', width=50)
        self.backup_passphrase_entry.pack(pady=5)

        tk.Button(backup_frame, text="Backup", command=self.backup_data).pack(pady=5)

        # Restore Data Section
        restore_frame = tk.LabelFrame(self, text="Restore Data", padx=10, pady=10)
        restore_frame.pack(fill="both", expand="yes", padx=10, pady=10)

        tk.Label(restore_frame, text="User ID:").pack(anchor=tk.W)
        self.restore_user_id_entry = tk.Entry(restore_frame, width=50)
        self.restore_user_id_entry.pack(pady=5)

        tk.Label(restore_frame, text="Passphrase:").pack(anchor=tk.W)
        self.restore_passphrase_entry = tk.Entry(restore_frame, show='*', width=50)
        self.restore_passphrase_entry.pack(pady=5)

        tk.Button(restore_frame, text="Restore", command=self.restore_data).pack(pady=5)

        self.restore_result_text = scrolledtext.ScrolledText(restore_frame, height=5)
        self.restore_result_text.pack(fill="both", padx=10, pady=10)

        # Schedule Backup Section
        schedule_frame = tk.LabelFrame(self, text="Schedule Backup", padx=10, pady=10)
        schedule_frame.pack(fill="both", expand="yes", padx=10, pady=10)

        tk.Label(schedule_frame, text="Interval (hours):").pack(anchor=tk.W)
        self.schedule_interval_entry = tk.Entry(schedule_frame, width=50)
        self.schedule_interval_entry.pack(pady=5)

        tk.Button(schedule_frame, text="Schedule", command=self.schedule_backup).pack(pady=5)

        # Backup Status Section
        status_frame = tk.LabelFrame(self, text="Backup Status", padx=10, pady=10)
        status_frame.pack(fill="both", expand="yes", padx=10, pady=10)

        tk.Button(status_frame, text="Get Backup Status", command=self.get_backup_status).pack(pady=5)

        self.status_result_text = scrolledtext.ScrolledText(status_frame, height=5)
        self.status_result_text.pack(fill="both", padx=10, pady=10)

    def encrypt_data(self):
        data = self.encrypt_data_entry.get().encode('utf-8')
        passphrase = self.encrypt_passphrase_entry.get()

        try:
            response = requests.post(f"{API_BASE_URL}/api/v1/backups/encrypt", json={"data": data, "passphrase": passphrase})
            response.raise_for_status()
            encrypted_data = response.json().get("encrypted_data")
            self.encrypt_result_text.insert(tk.END, encrypted_data + "\n")
        except requests.RequestException as e:
            messagebox.showerror("Error", str(e))

    def decrypt_data(self):
        encrypted_data = self.decrypt_data_entry.get()
        passphrase = self.decrypt_passphrase_entry.get()

        try:
            response = requests.post(f"{API_BASE_URL}/api/v1/backups/decrypt", json={"encrypted_data": encrypted_data, "passphrase": passphrase})
            response.raise_for_status()
            decrypted_data = response.json().get("decrypted_data").decode('utf-8')
            self.decrypt_result_text.insert(tk.END, decrypted_data + "\n")
        except requests.RequestException as e:
            messagebox.showerror("Error", str(e))

    def backup_data(self):
        user_id = self.backup_user_id_entry.get()
        data = self.backup_data_entry.get().encode('utf-8')
        passphrase = self.backup_passphrase_entry.get()

        try:
            response = requests.post(f"{API_BASE_URL}/api/v1/backups/backup", json={"user_id": user_id, "data": data, "passphrase": passphrase})
            response.raise_for_status()
            messagebox.showinfo("Success", "Data backed up successfully")
        except requests.RequestException as e:
            messagebox.showerror("Error", str(e))

    def restore_data(self):
        user_id = self.restore_user_id_entry.get()
        passphrase = self.restore_passphrase_entry.get()

        try:
            response = requests.post(f"{API_BASE_URL}/api/v1/backups/restore", json={"user_id": user_id, "passphrase": passphrase})
            response.raise_for_status()
            data = response.json().get("data").decode('utf-8')
            self.restore_result_text.insert(tk.END, data + "\n")
        except requests.RequestException as e:
            messagebox.showerror("Error", str(e))

    def schedule_backup(self):
        interval = self.schedule_interval_entry.get()

        try:
            response = requests.post(f"{API_BASE_URL}/api/v1/backups/schedule", json={"interval": int(interval)})
            response.raise_for_status()
            messagebox.showinfo("Success", "Backup schedule set successfully")
        except requests.RequestException as e:
            messagebox.showerror("Error", str(e))

    def get_backup_status(self):
        try:
            response = requests.get(f"{API_BASE_URL}/api/v1/backups/status")
            response.raise_for_status()
            status = response.json().get("status")
            self.status_result_text.insert(tk.END, status + "\n")
        except requests.RequestException as e:
            messagebox.showerror("Error", str(e))

if __name__ == "__main__":
    app = WalletBackupsGUI()
    app.mainloop()
