import tkinter as tk
from tkinter import messagebox, simpledialog
import requests
import json

class WalletCryptoGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Wallet Crypto GUI")
        
        self.create_widgets()

    def create_widgets(self):
        tk.Button(self.root, text="Generate Key Pair", command=self.generate_key_pair).pack(pady=10)
        tk.Button(self.root, text="Encrypt Data", command=self.encrypt_data).pack(pady=10)
        tk.Button(self.root, text="Decrypt Data", command=self.decrypt_data).pack(pady=10)
        tk.Button(self.root, text="Sign Data", command=self.sign_data).pack(pady=10)
        tk.Button(self.root, text="Verify Signature", command=self.verify_signature).pack(pady=10)
        tk.Button(self.root, text="Hash Data", command=self.hash_data).pack(pady=10)
        
    def generate_key_pair(self):
        response = requests.post("http://localhost:8000/api/generate_keypair")
        if response.status_code == 200:
            data = response.json().get("data", {})
            messagebox.showinfo("Key Pair Generated", json.dumps(data, indent=4))
        else:
            messagebox.showerror("Error", response.json().get("message", "Failed to generate key pair"))

    def encrypt_data(self):
        data = simpledialog.askstring("Input", "Enter data to encrypt:")
        passphrase = simpledialog.askstring("Input", "Enter passphrase:")
        response = requests.post("http://localhost:8000/api/encrypt_data", json={"data": data, "passphrase": passphrase})
        if response.status_code == 200:
            encrypted_data = response.json().get("data", {}).get("encrypted_data", "")
            messagebox.showinfo("Encrypted Data", encrypted_data)
        else:
            messagebox.showerror("Error", response.json().get("message", "Failed to encrypt data"))

    def decrypt_data(self):
        data = simpledialog.askstring("Input", "Enter data to decrypt:")
        passphrase = simpledialog.askstring("Input", "Enter passphrase:")
        response = requests.post("http://localhost:8000/api/decrypt_data", json={"data": data, "passphrase": passphrase})
        if response.status_code == 200:
            decrypted_data = response.json().get("data", {}).get("decrypted_data", "")
            messagebox.showinfo("Decrypted Data", decrypted_data)
        else:
            messagebox.showerror("Error", response.json().get("message", "Failed to decrypt data"))

    def sign_data(self):
        data = simpledialog.askstring("Input", "Enter data to sign:")
        private_key = simpledialog.askstring("Input", "Enter private key:")
        response = requests.post("http://localhost:8000/api/sign_data", json={"data": data, "private_key": private_key})
        if response.status_code == 200:
            signature = response.json().get("data", {}).get("signature", "")
            messagebox.showinfo("Signature", signature)
        else:
            messagebox.showerror("Error", response.json().get("message", "Failed to sign data"))

    def verify_signature(self):
        data = simpledialog.askstring("Input", "Enter data:")
        public_key = simpledialog.askstring("Input", "Enter public key:")
        signature = simpledialog.askstring("Input", "Enter signature:")
        response = requests.post("http://localhost:8000/api/verify_signature", json={"data": data, "public_key": public_key, "signature": signature})
        if response.status_code == 200:
            is_valid = response.json().get("data", {}).get("is_valid", False)
            messagebox.showinfo("Verification Result", f"Signature is valid: {is_valid}")
        else:
            messagebox.showerror("Error", response.json().get("message", "Failed to verify signature"))

    def hash_data(self):
        data = simpledialog.askstring("Input", "Enter data to hash:")
        response = requests.post("http://localhost:8000/api/hash_data", json={"data": data})
        if response.status_code == 200:
            hash_value = response.json().get("data", {}).get("hash", "")
            messagebox.showinfo("Hash Value", hash_value)
        else:
            messagebox.showerror("Error", response.json().get("message", "Failed to hash data"))

if __name__ == "__main__":
    root = tk.Tk()
    app = WalletCryptoGUI(root)
    root.mainloop()
