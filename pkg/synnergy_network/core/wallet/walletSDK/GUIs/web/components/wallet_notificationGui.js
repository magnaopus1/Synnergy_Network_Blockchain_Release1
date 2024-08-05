import React, { useState, useEffect } from 'react';
import {
  addAlert,
  listAlerts,
  handleAlert,
  sendNotification,
  updateNotificationSettings,
  connectWebSocket
} from '../api_service/wallet_notification_api_service';

const WalletNotificationGui = () => {
  const [alerts, setAlerts] = useState([]);
  const [alertType, setAlertType] = useState('');
  const [alertDescription, setAlertDescription] = useState('');
  const [userId, setUserId] = useState('');
  const [messageTitle, setMessageTitle] = useState('');
  const [messageContent, setMessageContent] = useState('');
  const [notificationSettings, setNotificationSettings] = useState({
    email_enabled: false,
    push_enabled: false,
    sms_enabled: false,
    security_alerts: false,
    transaction_updates: false,
    performance_metrics: false,
  });

  useEffect(() => {
    fetchAlerts();
    establishWebSocketConnection();
  }, []);

  const fetchAlerts = async () => {
    try {
      const response = await listAlerts();
      setAlerts(response.data);
    } catch (error) {
      console.error('Failed to fetch alerts', error);
    }
  };

  const establishWebSocketConnection = async () => {
    try {
      await connectWebSocket();
      console.log('WebSocket connection established');
    } catch (error) {
      console.error('Failed to connect WebSocket', error);
    }
  };

  const handleAddAlert = async () => {
    try {
      await addAlert(alertType, alertDescription);
      fetchAlerts();
    } catch (error) {
      console.error('Failed to add alert', error);
    }
  };

  const handleHandleAlert = async (alertID) => {
    try {
      await handleAlert(alertID);
      fetchAlerts();
    } catch (error) {
      console.error('Failed to handle alert', error);
    }
  };

  const handleSendNotification = async () => {
    const message = { title: messageTitle, content: messageContent };
    try {
      await sendNotification(userId, message);
    } catch (error) {
      console.error('Failed to send notification', error);
    }
  };

  const handleUpdateNotificationSettings = async () => {
    try {
      await updateNotificationSettings(notificationSettings);
    } catch (error) {
      console.error('Failed to update notification settings', error);
    }
  };

  return (
    <div>
      <h1>Wallet Notification Management</h1>
      
      <section>
        <h2>Add Alert</h2>
        <input
          type="text"
          value={alertType}
          onChange={(e) => setAlertType(e.target.value)}
          placeholder="Alert Type"
        />
        <input
          type="text"
          value={alertDescription}
          onChange={(e) => setAlertDescription(e.target.value)}
          placeholder="Alert Description"
        />
        <button onClick={handleAddAlert}>Add Alert</button>
      </section>

      <section>
        <h2>List Alerts</h2>
        <ul>
          {alerts.map((alert) => (
            <li key={alert.id}>
              {alert.type}: {alert.description}
              <button onClick={() => handleHandleAlert(alert.id)}>Handle</button>
            </li>
          ))}
        </ul>
      </section>

      <section>
        <h2>Send Notification</h2>
        <input
          type="text"
          value={userId}
          onChange={(e) => setUserId(e.target.value)}
          placeholder="User ID"
        />
        <input
          type="text"
          value={messageTitle}
          onChange={(e) => setMessageTitle(e.target.value)}
          placeholder="Message Title"
        />
        <input
          type="text"
          value={messageContent}
          onChange={(e) => setMessageContent(e.target.value)}
          placeholder="Message Content"
        />
        <button onClick={handleSendNotification}>Send Notification</button>
      </section>

      <section>
        <h2>Update Notification Settings</h2>
        <label>
          Email Enabled
          <input
            type="checkbox"
            checked={notificationSettings.email_enabled}
            onChange={(e) => setNotificationSettings({ ...notificationSettings, email_enabled: e.target.checked })}
          />
        </label>
        <label>
          Push Enabled
          <input
            type="checkbox"
            checked={notificationSettings.push_enabled}
            onChange={(e) => setNotificationSettings({ ...notificationSettings, push_enabled: e.target.checked })}
          />
        </label>
        <label>
          SMS Enabled
          <input
            type="checkbox"
            checked={notificationSettings.sms_enabled}
            onChange={(e) => setNotificationSettings({ ...notificationSettings, sms_enabled: e.target.checked })}
          />
        </label>
        <label>
          Security Alerts
          <input
            type="checkbox"
            checked={notificationSettings.security_alerts}
            onChange={(e) => setNotificationSettings({ ...notificationSettings, security_alerts: e.target.checked })}
          />
        </label>
        <label>
          Transaction Updates
          <input
            type="checkbox"
            checked={notificationSettings.transaction_updates}
            onChange={(e) => setNotificationSettings({ ...notificationSettings, transaction_updates: e.target.checked })}
          />
        </label>
        <label>
          Performance Metrics
          <input
            type="checkbox"
            checked={notificationSettings.performance_metrics}
            onChange={(e) => setNotificationSettings({ ...notificationSettings, performance_metrics: e.target.checked })}
          />
        </label>
        <button onClick={handleUpdateNotificationSettings}>Update Settings</button>
      </section>
    </div>
  );
};

export default WalletNotificationGui;
