import axios from 'axios';

const API_URL = process.env.REACT_APP_API_URL;

const apiClient = axios.create({
  baseURL: API_URL,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Generate Key Pair
export const generateKeyPair = async () => {
  try {
    const response = await apiClient.post('/api/generate_keypair');
    return response.data;
  } catch (error) {
    console.error('Failed to generate key pair', error);
    throw error;
  }
};

// Encrypt Data
export const encryptData = async (data, passphrase) => {
  try {
    const response = await apiClient.post('/api/encrypt_data', {
      data,
      passphrase,
    });
    return response.data.encrypted_data;
  } catch (error) {
    console.error('Failed to encrypt data', error);
    throw error;
  }
};

// Decrypt Data
export const decryptData = async (encryptedData, passphrase) => {
  try {
    const response = await apiClient.post('/api/decrypt_data', {
      data: encryptedData,
      passphrase,
    });
    return response.data.decrypted_data;
  } catch (error) {
    console.error('Failed to decrypt data', error);
    throw error;
  }
};

// Sign Data
export const signData = async (data, privateKey) => {
  try {
    const response = await apiClient.post('/api/sign_data', {
      data,
      private_key: privateKey,
    });
    return response.data.signature;
  } catch (error) {
    console.error('Failed to sign data', error);
    throw error;
  }
};

// Verify Signature
export const verifySignature = async (data, publicKey, signature) => {
  try {
    const response = await apiClient.post('/api/verify_signature', {
      data,
      public_key: publicKey,
      signature,
    });
    return response.data.is_valid;
  } catch (error) {
    console.error('Failed to verify signature', error);
    throw error;
  }
};

// Hash Data
export const hashData = async (data) => {
  try {
    const response = await apiClient.post('/api/hash_data', {
      data,
    });
    return response.data.hash;
  } catch (error) {
    console.error('Failed to hash data', error);
    throw error;
  }
};
