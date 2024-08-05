import axios from 'axios';

const API_URL = process.env.REACT_APP_API_URL;

const apiClient = axios.create({
  baseURL: API_URL,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Encrypt data
export const encryptData = async (data, passphrase) => {
  try {
    const response = await apiClient.post('/api/v1/backups/encrypt', {
      data,
      passphrase,
    });
    return response.data.encrypted_data;
  } catch (error) {
    console.error('Failed to encrypt data', error);
    throw error;
  }
};

// Decrypt data
export const decryptData = async (encryptedData, passphrase) => {
  try {
    const response = await apiClient.post('/api/v1/backups/decrypt', {
      encrypted_data: encryptedData,
      passphrase,
    });
    return response.data.decrypted_data;
  } catch (error) {
    console.error('Failed to decrypt data', error);
    throw error;
  }
};

// Backup data
export const backupData = async (userId, data, passphrase) => {
  try {
    await apiClient.post('/api/v1/backups/backup', {
      user_id: userId,
      data,
      passphrase,
    });
  } catch (error) {
    console.error('Failed to backup data', error);
    throw error;
  }
};

// Restore data
export const restoreData = async (userId, passphrase) => {
  try {
    const response = await apiClient.post('/api/v1/backups/restore', {
      user_id: userId,
      passphrase,
    });
    return response.data.data;
  } catch (error) {
    console.error('Failed to restore data', error);
    throw error;
  }
};

// Schedule backup
export const scheduleBackup = async (interval) => {
  try {
    await apiClient.post('/api/v1/backups/schedule', {
      interval,
    });
  } catch (error) {
    console.error('Failed to schedule backup', error);
    throw error;
  }
};

// Get backup status
export const getBackupStatus = async () => {
  try {
    const response = await apiClient.get('/api/v1/backups/status');
    return response.data.status;
  } catch (error) {
    console.error('Failed to get backup status', error);
    throw error;
  }
};
