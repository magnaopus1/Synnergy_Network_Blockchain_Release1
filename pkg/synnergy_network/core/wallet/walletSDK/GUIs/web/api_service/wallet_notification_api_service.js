import axios from 'axios';

const API_URL = process.env.REACT_APP_API_URL;

const apiClient = axios.create({
  baseURL: API_URL,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Add Alert
export const addAlert = async (type, description) => {
  try {
    await apiClient.post('/api/add_alert', {
      type,
      description,
    });
  } catch (error) {
    console.error('Failed to add alert', error);
    throw error;
  }
};

// List Alerts
export const listAlerts = async () => {
  try {
    const response = await apiClient.get('/api/list_alerts');
    return response.data;
  } catch (error) {
    console.error('Failed to list alerts', error);
    throw error;
  }
};

// Handle Alert
export const handleAlert = async (alertID) => {
  try {
    await apiClient.post(`/api/handle_alert/${alertID}`);
  } catch (error) {
    console.error('Failed to handle alert', error);
    throw error;
  }
};

// Send Notification
export const sendNotification = async (userID, message) => {
  try {
    await apiClient.post('/api/send_notification', {
      user_id: userID,
      message,
    });
  } catch (error) {
    console.error('Failed to send notification', error);
    throw error;
  }
};

// Update Notification Settings
export const updateNotificationSettings = async (settings) => {
  try {
    await apiClient.post('/api/update_notification_settings', settings);
  } catch (error) {
    console.error('Failed to update notification settings', error);
    throw error;
  }
};

// Connect WebSocket
export const connectWebSocket = async () => {
  try {
    const response = await apiClient.get('/api/connect_websocket');
    return response.data;
  } catch (error) {
    console.error('Failed to connect WebSocket', error);
    throw error;
  }
};
