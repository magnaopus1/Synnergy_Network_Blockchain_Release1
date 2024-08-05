import tkinter as tk
from tkinter import messagebox, scrolledtext, filedialog
import requests
import json
import os

API_BASE_URL = os.getenv("API_BASE_URL", "http://localhost:8080")

class WalletComplianceGUI(tk.Tk):
    def __init__(self):
        super().__init__()

        self.title("Wallet Compliance")
        self.geometry("800x600")

        self.create_widgets()

    def create_widgets(self):
        # KYC Verification Section
        kyc_frame = tk.LabelFrame(self, text="KYC Verification", padx=10, pady=10)
        kyc_frame.pack(fill="both", expand="yes", padx=10, pady=10)

        tk.Label(kyc_frame, text="User ID:").pack(anchor=tk.W)
        self.kyc_user_id_entry = tk.Entry(kyc_frame, width=50)
        self.kyc_user_id_entry.pack(pady=5)

        tk.Button(kyc_frame, text="Verify KYC", command=self.verify_kyc).pack(pady=5)

        # AML Check Section
        aml_frame = tk.LabelFrame(self, text="AML Check", padx=10, pady=10)
        aml_frame.pack(fill="both", expand="yes", padx=10, pady=10)

        tk.Label(aml_frame, text="User ID:").pack(anchor=tk.W)
        self.aml_user_id_entry = tk.Entry(aml_frame, width=50)
        self.aml_user_id_entry.pack(pady=5)

        tk.Button(aml_frame, text="Check AML", command=self.check_aml).pack(pady=5)

        # Compliance Check Section
        compliance_frame = tk.LabelFrame(self, text="Compliance Check", padx=10, pady=10)
        compliance_frame.pack(fill="both", expand="yes", padx=10, pady=10)

        tk.Label(compliance_frame, text="User ID:").pack(anchor=tk.W)
        self.compliance_user_id_entry = tk.Entry(compliance_frame, width=50)
        self.compliance_user_id_entry.pack(pady=5)

        tk.Button(compliance_frame, text="Check Compliance", command=self.check_compliance).pack(pady=5)

        # Log Transaction Section
        log_transaction_frame = tk.LabelFrame(self, text="Log Transaction", padx=10, pady=10)
        log_transaction_frame.pack(fill="both", expand="yes", padx=10, pady=10)

        tk.Label(log_transaction_frame, text="Transaction Data:").pack(anchor=tk.W)
        self.log_transaction_data_entry = tk.Entry(log_transaction_frame, width=50)
        self.log_transaction_data_entry.pack(pady=5)

        tk.Button(log_transaction_frame, text="Log Transaction", command=self.log_transaction).pack(pady=5)

        # Log Access Section
        log_access_frame = tk.LabelFrame(self, text="Log Access", padx=10, pady=10)
        log_access_frame.pack(fill="both", expand="yes", padx=10, pady=10)

        tk.Label(log_access_frame, text="User ID:").pack(anchor=tk.W)
        self.log_access_user_id_entry = tk.Entry(log_access_frame, width=50)
        self.log_access_user_id_entry.pack(pady=5)

        tk.Label(log_access_frame, text="Resource:").pack(anchor=tk.W)
        self.log_access_resource_entry = tk.Entry(log_access_frame, width=50)
        self.log_access_resource_entry.pack(pady=5)

        tk.Label(log_access_frame, text="Access Type:").pack(anchor=tk.W)
        self.log_access_type_entry = tk.Entry(log_access_frame, width=50)
        self.log_access_type_entry.pack(pady=5)

        tk.Label(log_access_frame, text="Allowed:").pack(anchor=tk.W)
        self.log_access_allowed_entry = tk.Entry(log_access_frame, width=50)
        self.log_access_allowed_entry.pack(pady=5)

        tk.Button(log_access_frame, text="Log Access", command=self.log_access).pack(pady=5)

        # Log Compliance Event Section
        log_event_frame = tk.LabelFrame(self, text="Log Compliance Event", padx=10, pady=10)
        log_event_frame.pack(fill="both", expand="yes", padx=10, pady=10)

        tk.Label(log_event_frame, text="Event:").pack(anchor=tk.W)
        self.log_event_entry = tk.Entry(log_event_frame, width=50)
        self.log_event_entry.pack(pady=5)

        tk.Label(log_event_frame, text="Details:").pack(anchor=tk.W)
        self.log_event_details_entry = tk.Entry(log_event_frame, width=50)
        self.log_event_details_entry.pack(pady=5)

        tk.Button(log_event_frame, text="Log Event", command=self.log_event).pack(pady=5)

        # Generate Report Section
        generate_report_frame = tk.LabelFrame(self, text="Generate Compliance Report", padx=10, pady=10)
        generate_report_frame.pack(fill="both", expand="yes", padx=10, pady=10)

        tk.Label(generate_report_frame, text="Start Time:").pack(anchor=tk.W)
        self.start_time_entry = tk.Entry(generate_report_frame, width=50)
        self.start_time_entry.pack(pady=5)

        tk.Label(generate_report_frame, text="End Time:").pack(anchor=tk.W)
        self.end_time_entry = tk.Entry(generate_report_frame, width=50)
        self.end_time_entry.pack(pady=5)

        tk.Button(generate_report_frame, text="Generate Report", command=self.generate_report).pack(pady=5)

        self.report_result_text = scrolledtext.ScrolledText(generate_report_frame, height=5)
        self.report_result_text.pack(fill="both", padx=10, pady=10)

        # Submit Report Section
        submit_report_frame = tk.LabelFrame(self, text="Submit Compliance Report", padx=10, pady=10)
        submit_report_frame.pack(fill="both", expand="yes", padx=10, pady=10)

        tk.Label(submit_report_frame, text="Report Data:").pack(anchor=tk.W)
        self.submit_report_entry = tk.Entry(submit_report_frame, width=50)
        self.submit_report_entry.pack(pady=5)

        tk.Button(submit_report_frame, text="Submit Report", command=self.submit_report).pack(pady=5)

    def verify_kyc(self):
        user_id = self.kyc_user_id_entry.get()

        try:
            response = requests.post(f"{API_BASE_URL}/api/v1/compliance/kyc", json={"user_id": user_id})
            response.raise_for_status()
            messagebox.showinfo("Success", "KYC Verification Successful")
        except requests.RequestException as e:
            messagebox.showerror("Error", str(e))

    def check_aml(self):
        user_id = self.aml_user_id_entry.get()

        try:
            response = requests.post(f"{API_BASE_URL}/api/v1/compliance/aml", json={"user_id": user_id})
            response.raise_for_status()
            messagebox.showinfo("Success", "AML Check Successful")
        except requests.RequestException as e:
            messagebox.showerror("Error", str(e))

    def check_compliance(self):
        user_id = self.compliance_user_id_entry.get()

        try:
            response = requests.post(f"{API_BASE_URL}/api/v1/compliance/check", json={"user_id": user_id})
            response.raise_for_status()
            messagebox.showinfo("Success", "Compliance Check Successful")
        except requests.RequestException as e:
            messagebox.showerror("Error", str(e))

    def log_transaction(self):
        transaction_data = self.log_transaction_data_entry.get()

        try:
            response = requests.post(f"{API_BASE_URL}/api/v1/compliance/audit/log_transaction", json={"transaction": transaction_data})
            response.raise_for_status()
            messagebox.showinfo("Success", "Transaction Logged Successfully")
        except requests.RequestException as e:
            messagebox.showerror("Error", str(e))

    def log_access(self):
        user_id = self.log_access_user_id_entry.get()
        resource = self.log_access_resource_entry.get()
        access_type = self.log_access_type_entry.get()
        allowed = self.log_access_allowed_entry.get()

        try:
            response = requests.post(f"{API_BASE_URL}/api/v1/compliance/audit/log_access", json={"user_id": user_id, "resource": resource, "access_type": access_type, "allowed": allowed})
            response.raise_for_status()
            messagebox.showinfo("Success", "Access Logged Successfully")
        except requests.RequestException as e:
            messagebox.showerror("Error", str(e))

    def log_event(self):
        event = self.log_event_entry.get()
        details = self.log_event_details_entry.get()

        try:
            response = requests.post(f"{API_BASE_URL}/api/v1/compliance/audit/log_event", json={"event": event, "details": details})
            response.raise_for_status()
            messagebox.showinfo("Success", "Event Logged Successfully")
        except requests.RequestException as e:
            messagebox.showerror("Error", str(e))

    def generate_report(self):
        start_time = self.start_time_entry.get()
        end_time = self.end_time_entry.get()

        try:
            response = requests.post(f"{API_BASE_URL}/api/v1/compliance/report/generate", json={"start_time": start_time, "end_time": end_time})
            response.raise_for_status()
            report = response.json().get("report")
            self.report_result_text.insert(tk.END, json.dumps(report, indent=4) + "\n")
        except requests.RequestException as e:
            messagebox.showerror("Error", str(e))

    def submit_report(self):
        report_data = self.submit_report_entry.get()

        try:
            response = requests.post(f"{API_BASE_URL}/api/v1/compliance/report/submit", json={"report": report_data})
            response.raise_for_status()
            messagebox.showinfo("Success", "Report Submitted Successfully")
        except requests.RequestException as e:
            messagebox.showerror("Error", str(e))

if __name__ == "__main__":
    app = WalletComplianceGUI()
    app.mainloop()
