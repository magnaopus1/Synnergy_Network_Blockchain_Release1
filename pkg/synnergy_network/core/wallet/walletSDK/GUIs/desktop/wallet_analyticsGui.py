import tkinter as tk
from tkinter import messagebox, scrolledtext
import requests
import json
import os

API_BASE_URL = os.getenv("API_BASE_URL", "http://localhost:8080")

class WalletAnalyticsGUI(tk.Tk):
    def __init__(self):
        super().__init__()

        self.title("Wallet Analytics")
        self.geometry("800x600")

        self.create_widgets()

    def create_widgets(self):
        # Performance Metrics Section
        performance_frame = tk.LabelFrame(self, text="Performance Metrics", padx=10, pady=10)
        performance_frame.pack(fill="both", expand="yes", padx=10, pady=10)

        tk.Button(performance_frame, text="Get Performance Metrics", command=self.get_performance_metrics).pack(pady=5)
        tk.Button(performance_frame, text="Log Performance Metrics", command=self.log_performance_metrics).pack(pady=5)
        
        self.performance_text = scrolledtext.ScrolledText(performance_frame, height=10)
        self.performance_text.pack(fill="both", padx=10, pady=10)

        # Transaction Analytics Section
        transaction_frame = tk.LabelFrame(self, text="Transaction Analytics", padx=10, pady=10)
        transaction_frame.pack(fill="both", expand="yes", padx=10, pady=10)

        tk.Button(transaction_frame, text="Get Transaction Analytics", command=self.get_transaction_analytics).pack(pady=5)
        
        self.transaction_text = scrolledtext.ScrolledText(transaction_frame, height=10)
        self.transaction_text.pack(fill="both", padx=10, pady=10)

        # Risk Analysis Section
        risk_frame = tk.LabelFrame(self, text="Risk Analysis", padx=10, pady=10)
        risk_frame.pack(fill="both", expand="yes", padx=10, pady=10)

        tk.Button(risk_frame, text="Get Risk Events", command=self.get_risk_events).pack(pady=5)
        tk.Button(risk_frame, text="Analyze Risks", command=self.analyze_risks).pack(pady=5)
        
        self.risk_text = scrolledtext.ScrolledText(risk_frame, height=10)
        self.risk_text.pack(fill="both", padx=10, pady=10)

        # User Activity Section
        user_frame = tk.LabelFrame(self, text="User Activities", padx=10, pady=10)
        user_frame.pack(fill="both", expand="yes", padx=10, pady=10)

        tk.Label(user_frame, text="User ID:").pack(side=tk.LEFT, padx=5)
        self.user_id_entry = tk.Entry(user_frame)
        self.user_id_entry.pack(side=tk.LEFT, padx=5)
        
        tk.Button(user_frame, text="Get User Activities", command=self.get_user_activities).pack(side=tk.LEFT, padx=5)
        tk.Button(user_frame, text="Analyze User Patterns", command=self.analyze_user_patterns).pack(side=tk.LEFT, padx=5)
        
        self.user_text = scrolledtext.ScrolledText(user_frame, height=10)
        self.user_text.pack(fill="both", padx=10, pady=10)

    def get_performance_metrics(self):
        try:
            response = requests.get(f"{API_BASE_URL}/api/v1/performance/metrics")
            response.raise_for_status()
            metrics = response.json()
            self.performance_text.insert(tk.END, json.dumps(metrics, indent=2) + "\n")
        except requests.RequestException as e:
            messagebox.showerror("Error", str(e))

    def log_performance_metrics(self):
        try:
            # Here you would collect metrics data from your system
            metrics_data = {
                "TransactionProcessingTimes": [0.5, 0.8, 0.3],
                "ResourceUsage": {
                    "CPUUsage": 25.5,
                    "MemoryUsage": 512000
                }
            }
            response = requests.post(f"{API_BASE_URL}/api/v1/performance/metrics", json=metrics_data)
            response.raise_for_status()
            messagebox.showinfo("Success", "Performance metrics logged successfully")
        except requests.RequestException as e:
            messagebox.showerror("Error", str(e))

    def get_transaction_analytics(self):
        try:
            response = requests.get(f"{API_BASE_URL}/api/v1/transactions/analytics")
            response.raise_for_status()
            analytics = response.json()
            self.transaction_text.insert(tk.END, json.dumps(analytics, indent=2) + "\n")
        except requests.RequestException as e:
            messagebox.showerror("Error", str(e))

    def get_risk_events(self):
        try:
            response = requests.get(f"{API_BASE_URL}/api/v1/risks")
            response.raise_for_status()
            risks = response.json()
            self.risk_text.insert(tk.END, json.dumps(risks, indent=2) + "\n")
        except requests.RequestException as e:
            messagebox.showerror("Error", str(e))

    def analyze_risks(self):
        try:
            response = requests.post(f"{API_BASE_URL}/api/v1/risks/analyze")
            response.raise_for_status()
            messagebox.showinfo("Success", "Risk analysis triggered successfully")
        except requests.RequestException as e:
            messagebox.showerror("Error", str(e))

    def get_user_activities(self):
        user_id = self.user_id_entry.get()
        try:
            response = requests.get(f"{API_BASE_URL}/api/v1/user/activities/{user_id}")
            response.raise_for_status()
            activities = response.json()
            self.user_text.insert(tk.END, json.dumps(activities, indent=2) + "\n")
        except requests.RequestException as e:
            messagebox.showerror("Error", str(e))

    def analyze_user_patterns(self):
        try:
            response = requests.get(f"{API_BASE_URL}/api/v1/user/patterns")
            response.raise_for_status()
            patterns = response.json()
            self.user_text.insert(tk.END, json.dumps(patterns, indent=2) + "\n")
        except requests.RequestException as e:
            messagebox.showerror("Error", str(e))

if __name__ == "__main__":
    app = WalletAnalyticsGUI()
    app.mainloop()
