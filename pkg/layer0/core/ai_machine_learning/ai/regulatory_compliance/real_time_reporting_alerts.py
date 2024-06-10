import hashlib
import time

class RealTimeReportingAlerts:
    def __init__(self):
        # Initialize with empty alerts
        self.alerts = []

    def generate_alert(self, alert_type, message):
        """
        Generate an alert/notification for compliance breaches or irregularities.

        Args:
        - alert_type (str): Type of alert (e.g., "Compliance Risk").
        - message (str): Alert message providing details about the event.

        Returns:
        - alert_id (int): Unique identifier for the generated alert.
        """
        # Generate unique identifier for the alert (e.g., hash of timestamp)
        alert_id = int(hashlib.sha256(str(time.time()).encode()).hexdigest(), 16) % 10**8
        # Add the alert to the list of alerts
        self.alerts.append({"id": alert_id, "type": alert_type, "message": message})
        return alert_id

    def get_alerts(self):
        """
        Retrieve the list of generated alerts.

        Returns:
        - alerts (list of dict): List of alerts, each containing id, type, and message.
        """
        return self.alerts

# Example usage:
if __name__ == "__main__":
    # Initialize RealTimeReportingAlerts
    rtra = RealTimeReportingAlerts()
    
    # Generate alerts
    alert_id_1 = rtra.generate_alert("Compliance Risk", "Large transaction detected.")
    alert_id_2 = rtra.generate_alert("Compliance Risk", "Code vulnerability detected.")
    
    # Get the list of alerts
    alerts = rtra.get_alerts()
    print("Alerts:", alerts)
