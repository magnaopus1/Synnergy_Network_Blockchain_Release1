import tkinter as tk
from tkinter import messagebox, scrolledtext, filedialog
import requests
import json
import os

API_BASE_URL = os.getenv("API_BASE_URL", "http://localhost:8080")

class WalletCoreGUI(tk.Tk):
    def __init__(self):
        super().__init__()

        self.title("Wallet Core")
        self.geometry("800x600")

        self.create_widgets()

    def create_widgets(self):
        # Create HD Wallet Section
        hd_wallet_frame = tk.LabelFrame(self, text="Create HD Wallet", padx=10, pady=10)
        hd_wallet_frame.pack(fill="both", expand="yes", padx=10, pady=10)

        tk.Label(hd_wallet_frame, text="Seed:").pack(anchor=tk.W)
        self.seed_entry = tk.Entry(hd_wallet_frame, width=50)
        self.seed_entry.pack(pady=5)

        tk.Button(hd_wallet_frame, text="Create HD Wallet", command=self.create_hd_wallet).pack(pady=5)

        # Generate Keypair Section
        keypair_frame = tk.LabelFrame(self, text="Generate Keypair", padx=10, pady=10)
        keypair_frame.pack(fill="both", expand="yes", padx=10, pady=10)

        tk.Button(keypair_frame, text="Generate Keypair", command=self.generate_keypair).pack(pady=5)
        
        self.keypair_result_text = scrolledtext.ScrolledText(keypair_frame, height=5)
        self.keypair_result_text.pack(fill="both", padx=10, pady=10)

        # Add Currency Section
        add_currency_frame = tk.LabelFrame(self, text="Add Currency", padx=10, pady=10)
        add_currency_frame.pack(fill="both", expand="yes", padx=10, pady=10)

        tk.Label(add_currency_frame, text="Name:").pack(anchor=tk.W)
        self.currency_name_entry = tk.Entry(add_currency_frame, width=50)
        self.currency_name_entry.pack(pady=5)

        tk.Label(add_currency_frame, text="Blockchain:").pack(anchor=tk.W)
        self.blockchain_entry = tk.Entry(add_currency_frame, width=50)
        self.blockchain_entry.pack(pady=5)

        tk.Label(add_currency_frame, text="Keypair:").pack(anchor=tk.W)
        self.keypair_entry = tk.Entry(add_currency_frame, width=50)
        self.keypair_entry.pack(pady=5)

        tk.Button(add_currency_frame, text="Add Currency", command=self.add_currency).pack(pady=5)

        # Notify Balance Update Section
        notify_balance_frame = tk.LabelFrame(self, text="Notify Balance Update", padx=10, pady=10)
        notify_balance_frame.pack(fill="both", expand="yes", padx=10, pady=10)

        tk.Label(notify_balance_frame, text="Currency:").pack(anchor=tk.W)
        self.notify_currency_entry = tk.Entry(notify_balance_frame, width=50)
        self.notify_currency_entry.pack(pady=5)

        tk.Label(notify_balance_frame, text="Amount:").pack(anchor=tk.W)
        self.notify_amount_entry = tk.Entry(notify_balance_frame, width=50)
        self.notify_amount_entry.pack(pady=5)

        tk.Button(notify_balance_frame, text="Notify Balance Update", command=self.notify_balance_update).pack(pady=5)

        # Freeze/Unfreeze Wallet Section
        freeze_wallet_frame = tk.LabelFrame(self, text="Freeze/Unfreeze Wallet", padx=10, pady=10)
        freeze_wallet_frame.pack(fill="both", expand="yes", padx=10, pady=10)

        tk.Label(freeze_wallet_frame, text="Wallet ID:").pack(anchor=tk.W)
        self.wallet_id_entry = tk.Entry(freeze_wallet_frame, width=50)
        self.wallet_id_entry.pack(pady=5)

        tk.Button(freeze_wallet_frame, text="Freeze Wallet", command=self.freeze_wallet).pack(pady=5)
        tk.Button(freeze_wallet_frame, text="Unfreeze Wallet", command=self.unfreeze_wallet).pack(pady=5)

        # Save/Load Metadata Section
        metadata_frame = tk.LabelFrame(self, text="Save/Load Metadata", padx=10, pady=10)
        metadata_frame.pack(fill="both", expand="yes", padx=10, pady=10)

        tk.Label(metadata_frame, text="File Path:").pack(anchor=tk.W)
        self.metadata_file_path_entry = tk.Entry(metadata_frame, width=50)
        self.metadata_file_path_entry.pack(pady=5)

        tk.Label(metadata_frame, text="Encryption Key:").pack(anchor=tk.W)
        self.encryption_key_entry = tk.Entry(metadata_frame, width=50)
        self.encryption_key_entry.pack(pady=5)

        tk.Label(metadata_frame, text="Metadata (JSON):").pack(anchor=tk.W)
        self.metadata_json_entry = tk.Entry(metadata_frame, width=50)
        self.metadata_json_entry.pack(pady=5)

        tk.Button(metadata_frame, text="Save Metadata", command=self.save_metadata).pack(pady=5)
        tk.Button(metadata_frame, text="Load Metadata", command=self.load_metadata).pack(pady=5)
        
        self.metadata_result_text = scrolledtext.ScrolledText(metadata_frame, height=5)
        self.metadata_result_text.pack(fill="both", padx=10, pady=10)

    def create_hd_wallet(self):
        seed = self.seed_entry.get()

        try:
            response = requests.post(f"{API_BASE_URL}/api/v1/wallet/hdwallet", json={"seed": seed})
            response.raise_for_status()
            wallet = response.json().get("wallet")
            messagebox.showinfo("Success", f"HD Wallet Created: {wallet}")
        except requests.RequestException as e:
            messagebox.showerror("Error", str(e))

    def generate_keypair(self):
        try:
            response = requests.post(f"{API_BASE_URL}/api/v1/wallet/keypair")
            response.raise_for_status()
            keypair = response.json().get("keypair")
            self.keypair_result_text.insert(tk.END, json.dumps(keypair, indent=4) + "\n")
        except requests.RequestException as e:
            messagebox.showerror("Error", str(e))

    def add_currency(self):
        name = self.currency_name_entry.get()
        blockchain = self.blockchain_entry.get()
        keypair = self.keypair_entry.get()

        try:
            response = requests.post(f"{API_BASE_URL}/api/v1/wallet/add_currency", json={"name": name, "blockchain": blockchain, "keypair": keypair})
            response.raise_for_status()
            messagebox.showinfo("Success", "Currency Added Successfully")
        except requests.RequestException as e:
            messagebox.showerror("Error", str(e))

    def notify_balance_update(self):
        currency = self.notify_currency_entry.get()
        amount = self.notify_amount_entry.get()

        try:
            response = requests.post(f"{API_BASE_URL}/api/v1/wallet/notify_balance", json={"currency": currency, "amount": amount})
            response.raise_for_status()
            messagebox.showinfo("Success", "Balance Update Notification Sent")
        except requests.RequestException as e:
            messagebox.showerror("Error", str(e))

    def freeze_wallet(self):
        wallet_id = self.wallet_id_entry.get()

        try:
            response = requests.post(f"{API_BASE_URL}/api/v1/wallet/freeze", json={"wallet_id": wallet_id})
            response.raise_for_status()
            messagebox.showinfo("Success", "Wallet Frozen Successfully")
        except requests.RequestException as e:
            messagebox.showerror("Error", str(e))

    def unfreeze_wallet(self):
        wallet_id = self.wallet_id_entry.get()

        try:
            response = requests.post(f"{API_BASE_URL}/api/v1/wallet/unfreeze", json={"wallet_id": wallet_id})
            response.raise_for_status()
            messagebox.showinfo("Success", "Wallet Unfrozen Successfully")
        except requests.RequestException as e:
            messagebox.showerror("Error", str(e))

    def save_metadata(self):
        file_path = self.metadata_file_path_entry.get()
        encryption_key = self.encryption_key_entry.get()
        metadata_json = self.metadata_json_entry.get()

        try:
            metadata = json.loads(metadata_json)
            response = requests.post(f"{API_BASE_URL}/api/v1/wallet/save_metadata", json={"file_path": file_path, "encryption_key": encryption_key, "wallet_metadata": metadata})
            response.raise_for_status()
            messagebox.showinfo("Success", "Metadata Saved Successfully")
        except requests.RequestException as e:
            messagebox.showerror("Error", str(e))
        except json.JSONDecodeError:
            messagebox.showerror("Error", "Invalid JSON in Metadata")

    def load_metadata(self):
        file_path = self.metadata_file_path_entry.get()
        encryption_key = self.encryption_key_entry.get()

        try:
            response = requests.post(f"{API_BASE_URL}/api/v1/wallet/load_metadata", json={"file_path": file_path, "encryption_key": encryption_key})
            response.raise_for_status()
            metadata = response.json().get("metadata")
            self.metadata_result_text.insert(tk.END, json.dumps(metadata, indent=4) + "\n")
        except requests.RequestException as e:
            messagebox.showerror("Error", str(e))

if __name__ == "__main__":
    app = WalletCoreGUI()
    app.mainloop()
