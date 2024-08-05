import tkinter as tk
from tkinter import messagebox, simpledialog
import requests
import json

class WalletIntegrationGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Wallet Integration GUI")

        self.create_widgets()

    def create_widgets(self):
        tk.Button(self.root, text="Check Balance", command=self.check_balance).pack(pady=10)
        tk.Button(self.root, text="Send Transaction", command=self.send_transaction).pack(pady=10)
        tk.Button(self.root, text="Sync with Blockchain", command=self.sync_blockchain).pack(pady=10)
        tk.Button(self.root, text="Cross-Chain Transfer", command=self.cross_chain_transfer).pack(pady=10)
        tk.Button(self.root, text="Sync with External API", command=self.sync_external_api).pack(pady=10)
        tk.Button(self.root, text="Generate HSM Key Pair", command=self.generate_hsm_keypair).pack(pady=10)
        tk.Button(self.root, text="Third-Party Service Integration", command=self.third_party_service_integration).pack(pady=10)

    def check_balance(self):
        wallet_address = simpledialog.askstring("Input", "Enter Wallet Address:")
        response = requests.get(f"http://localhost:8000/api/check_balance?wallet_address={wallet_address}")
        if response.status_code == 200:
            data = response.json().get("data", {})
            messagebox.showinfo("Balance", f"Balance: {data}")
        else:
            messagebox.showerror("Error", response.json().get("message", "Failed to check balance"))

    def send_transaction(self):
        from_addr = simpledialog.askstring("Input", "Enter From Address:")
        to_addr = simpledialog.askstring("Input", "Enter To Address:")
        amount = simpledialog.askfloat("Input", "Enter Amount:")
        private_key = simpledialog.askstring("Input", "Enter Private Key:")

        transaction_data = {
            "from": from_addr,
            "to": to_addr,
            "amount": amount,
            "private_key": private_key
        }

        response = requests.post("http://localhost:8000/api/send_transaction", json=transaction_data)
        if response.status_code == 200:
            messagebox.showinfo("Success", "Transaction sent successfully")
        else:
            messagebox.showerror("Error", response.json().get("message", "Failed to send transaction"))

    def sync_blockchain(self):
        response = requests.post("http://localhost:8000/api/sync_blockchain")
        if response.status_code == 200:
            messagebox.showinfo("Success", "Synced with blockchain successfully")
        else:
            messagebox.showerror("Error", response.json().get("message", "Failed to sync with blockchain"))

    def cross_chain_transfer(self):
        source_chain = simpledialog.askstring("Input", "Enter Source Chain:")
        target_chain = simpledialog.askstring("Input", "Enter Target Chain:")
        from_addr = simpledialog.askstring("Input", "Enter From Address:")
        to_addr = simpledialog.askstring("Input", "Enter To Address:")
        amount = simpledialog.askfloat("Input", "Enter Amount:")

        transfer_data = {
            "source_chain": source_chain,
            "target_chain": target_chain,
            "from_addr": from_addr,
            "to_addr": to_addr,
            "amount": amount
        }

        response = requests.post("http://localhost:8000/api/cross_chain_transfer", json=transfer_data)
        if response.status_code == 200:
            tx_id = response.json().get("data", "")
            messagebox.showinfo("Success", f"Transfer successful. Transaction ID: {tx_id}")
        else:
            messagebox.showerror("Error", response.json().get("message", "Failed to transfer assets"))

    def sync_external_api(self):
        response = requests.post("http://localhost:8000/api/external_api_sync")
        if response.status_code == 200:
            messagebox.showinfo("Success", "Synced with external API successfully")
        else:
            messagebox.showerror("Error", response.json().get("message", "Failed to sync with external API"))

    def generate_hsm_keypair(self):
        response = requests.post("http://localhost:8000/api/hsm_generate_keypair")
        if response.status_code == 200:
            key_pair = response.json().get("data", {})
            messagebox.showinfo("Key Pair", json.dumps(key_pair, indent=4))
        else:
            messagebox.showerror("Error", response.json().get("message", "Failed to generate HSM key pair"))

    def third_party_service_integration(self):
        url = simpledialog.askstring("Input", "Enter Service URL:")
        response = requests.post("http://localhost:8000/api/third_party_service", json={"url": url})
        if response.status_code == 200:
            data = response.json().get("data", {})
            messagebox.showinfo("Service Data", json.dumps(data, indent=4))
        else:
            messagebox.showerror("Error", response.json().get("message", "Failed to query third-party service"))

if __name__ == "__main__":
    root = tk.Tk()
    app = WalletIntegrationGUI(root)
    root.mainloop()
