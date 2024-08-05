import axios from 'axios';

const API_URL = process.env.REACT_APP_API_URL;

const apiClient = axios.create({
  baseURL: API_URL,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Create HD Wallet
export const createHDWallet = async (seed) => {
  try {
    const response = await apiClient.post('/api/v1/wallet/hdwallet', { seed });
    return response.data.wallet;
  } catch (error) {
    console.error('Failed to create HD wallet', error);
    throw error;
  }
};

// Generate Key Pair
export const generateKeyPair = async () => {
  try {
    const response = await apiClient.post('/api/v1/wallet/keypair');
    return response.data.keypair;
  } catch (error) {
    console.error('Failed to generate key pair', error);
    throw error;
  }
};

// Add Currency to Wallet
export const addCurrency = async (name, blockchain, keypair) => {
  try {
    await apiClient.post('/api/v1/wallet/add_currency', { name, blockchain, keypair });
  } catch (error) {
    console.error('Failed to add currency', error);
    throw error;
  }
};

// Notify Balance Update
export const notifyBalanceUpdate = async (currency, amount) => {
  try {
    await apiClient.post('/api/v1/wallet/notify_balance', { currency, amount });
  } catch (error) {
    console.error('Failed to notify balance update', error);
    throw error;
  }
};

// Freeze Wallet
export const freezeWallet = async (walletId) => {
  try {
    await apiClient.post('/api/v1/wallet/freeze', { wallet_id: walletId });
  } catch (error) {
    console.error('Failed to freeze wallet', error);
    throw error;
  }
};

// Unfreeze Wallet
export const unfreezeWallet = async (walletId) => {
  try {
    await apiClient.post('/api/v1/wallet/unfreeze', { wallet_id: walletId });
  } catch (error) {
    console.error('Failed to unfreeze wallet', error);
    throw error;
  }
};

// Save Wallet Metadata
export const saveWalletMetadata = async (filePath, encryptionKey, walletMetadata) => {
  try {
    await apiClient.post('/api/v1/wallet/save_metadata', { file_path: filePath, encryption_key: encryptionKey, wallet_metadata: walletMetadata });
  } catch (error) {
    console.error('Failed to save wallet metadata', error);
    throw error;
  }
};

// Load Wallet Metadata
export const loadWalletMetadata = async (filePath, encryptionKey) => {
  try {
    const response = await apiClient.post('/api/v1/wallet/load_metadata', { file_path: filePath, encryption_key: encryptionKey });
    return response.data.metadata;
  } catch (error) {
    console.error('Failed to load wallet metadata', error);
    throw error;
  }
};
