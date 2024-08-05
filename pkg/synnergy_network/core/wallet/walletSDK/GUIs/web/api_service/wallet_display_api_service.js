import axios from 'axios';

const API_URL = process.env.REACT_APP_API_URL;

const apiClient = axios.create({
  baseURL: API_URL,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Handle AR Display
export const handleARDisplay = async (walletId) => {
  try {
    const response = await apiClient.get(`/api/ar_display`, {
      params: {
        wallet_id: walletId,
      },
    });
    return response.data;
  } catch (error) {
    console.error('Failed to handle AR display', error);
    throw error;
  }
};

// Handle Theme Customization
export const handleThemeCustomization = async (theme) => {
  try {
    await apiClient.post('/api/theme_customization', theme);
  } catch (error) {
    console.error('Failed to handle theme customization', error);
    throw error;
  }
};

// Handle Voice Command (GET and POST)
export const getVoiceCommandSettings = async () => {
  try {
    const response = await apiClient.get('/api/voice_command');
    return response.data;
  } catch (error) {
    console.error('Failed to get voice command settings', error);
    throw error;
  }
};

export const updateVoiceCommandSettings = async (settings) => {
  try {
    await apiClient.post('/api/voice_command', settings);
  } catch (error) {
    console.error('Failed to update voice command settings', error);
    throw error;
  }
};

// Handle Widget Management (GET, POST, DELETE)
export const listWidgets = async () => {
  try {
    const response = await apiClient.get('/api/widget_management');
    return response.data;
  } catch (error) {
    console.error('Failed to list widgets', error);
    throw error;
  }
};

export const addWidget = async (id, widget) => {
  try {
    await apiClient.post('/api/widget_management', { id, widget });
  } catch (error) {
    console.error('Failed to add widget', error);
    throw error;
  }
};

export const removeWidget = async (id) => {
  try {
    await apiClient.delete('/api/widget_management', { data: { id } });
  } catch (error) {
    console.error('Failed to remove widget', error);
    throw error;
  }
};

// Handle Wallet Naming (GET, POST, DELETE)
export const resolveAlias = async (alias) => {
  try {
    const response = await apiClient.get('/api/wallet_naming', {
      params: {
        alias: alias,
      },
    });
    return response.data;
  } catch (error) {
    console.error('Failed to resolve alias', error);
    throw error;
  }
};

export const registerAlias = async (alias, address) => {
  try {
    await apiClient.post('/api/wallet_naming', { alias, address });
  } catch (error) {
    console.error('Failed to register alias', error);
    throw error;
  }
};

export const removeAlias = async (alias) => {
  try {
    await apiClient.delete('/api/wallet_naming', { data: { alias } });
  } catch (error) {
    console.error('Failed to remove alias', error);
    throw error;
  }
};
