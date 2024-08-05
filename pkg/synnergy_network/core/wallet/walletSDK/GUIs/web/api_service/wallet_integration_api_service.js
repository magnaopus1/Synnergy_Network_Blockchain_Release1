import axios from 'axios';

const API_URL = process.env.REACT_APP_API_URL;

const apiClient = axios.create({
  baseURL: API_URL,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Check Balance
export const checkBalance = async (walletAddress) => {
  try {
    const response = await apiClient.get('/api/check_balance', {
      params: { wallet_address: walletAddress },
    });
    return response.data;
  } catch (error) {
    console.error('Failed to check balance', error);
    throw error;
  }
};

// Send Transaction
export const sendTransaction = async (from, to, amount, privateKey) => {
  try {
    await apiClient.post('/api/send_transaction', {
      from,
      to,
      amount,
      private_key: privateKey,
    });
  } catch (error) {
    console.error('Failed to send transaction', error);
    throw error;
  }
};

// Sync with Blockchain
export const syncWithBlockchain = async () => {
  try {
    await apiClient.post('/api/sync_blockchain');
  } catch (error) {
    console.error('Failed to sync with blockchain', error);
    throw error;
  }
};

// Cross-Chain Transfer
export const crossChainTransfer = async (sourceChain, targetChain, fromAddr, toAddr, amount) => {
  try {
    const response = await apiClient.post('/api/cross_chain_transfer', {
      source_chain: sourceChain,
      target_chain: targetChain,
      from_addr: fromAddr,
      to_addr: toAddr,
      amount,
    });
    return response.data;
  } catch (error) {
    console.error('Failed to transfer assets', error);
    throw error;
  }
};

// Sync with External API
export const syncWithExternalAPI = async () => {
  try {
    await apiClient.post('/api/external_api_sync');
  } catch (error) {
    console.error('Failed to sync with external API', error);
    throw error;
  }
};

// Generate Key Pair using HSM
export const hsmGenerateKeyPair = async () => {
  try {
    const response = await apiClient.post('/api/hsm_generate_keypair');
    return response.data;
  } catch (error) {
    console.error('Failed to generate key pair using HSM', error);
    throw error;
  }
};

// Integrate Third-Party Service
export const integrateThirdPartyService = async (url) => {
  try {
    const response = await apiClient.post('/api/third_party_service', { url });
    return response.data;
  } catch (error) {
    console.error('Failed to integrate third-party service', error);
    throw error;
  }
};
