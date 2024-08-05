import React, { useState } from 'react';
import {
  generateKeyPair,
  encryptData,
  decryptData,
  signData,
  verifySignature,
  hashData
} from '../api_service/wallet_crypto_api_service';

const WalletCryptoGui = () => {
  const [data, setData] = useState('');
  const [passphrase, setPassphrase] = useState('');
  const [privateKey, setPrivateKey] = useState('');
  const [publicKey, setPublicKey] = useState('');
  const [signature, setSignature] = useState('');
  const [result, setResult] = useState('');

  const handleGenerateKeyPair = async () => {
    try {
      const response = await generateKeyPair();
      setPrivateKey(response.private_key);
      setPublicKey(response.public_key);
      setResult('Key pair generated successfully');
    } catch (error) {
      setResult('Failed to generate key pair');
    }
  };

  const handleEncryptData = async () => {
    try {
      const encryptedData = await encryptData(data, passphrase);
      setResult(`Encrypted Data: ${encryptedData}`);
    } catch (error) {
      setResult('Failed to encrypt data');
    }
  };

  const handleDecryptData = async () => {
    try {
      const decryptedData = await decryptData(data, passphrase);
      setResult(`Decrypted Data: ${decryptedData}`);
    } catch (error) {
      setResult('Failed to decrypt data');
    }
  };

  const handleSignData = async () => {
    try {
      const sign = await signData(data, privateKey);
      setSignature(sign);
      setResult(`Signature: ${sign}`);
    } catch (error) {
      setResult('Failed to sign data');
    }
  };

  const handleVerifySignature = async () => {
    try {
      const isValid = await verifySignature(data, publicKey, signature);
      setResult(`Signature Valid: ${isValid}`);
    } catch (error) {
      setResult('Failed to verify signature');
    }
  };

  const handleHashData = async () => {
    try {
      const hash = await hashData(data);
      setResult(`Hash: ${hash}`);
    } catch (error) {
      setResult('Failed to hash data');
    }
  };

  return (
    <div>
      <h2>Wallet Crypto Operations</h2>
      <div>
        <label>Data:</label>
        <input
          type="text"
          value={data}
          onChange={(e) => setData(e.target.value)}
        />
      </div>
      <div>
        <label>Passphrase:</label>
        <input
          type="password"
          value={passphrase}
          onChange={(e) => setPassphrase(e.target.value)}
        />
      </div>
      <div>
        <label>Private Key:</label>
        <input
          type="text"
          value={privateKey}
          onChange={(e) => setPrivateKey(e.target.value)}
        />
      </div>
      <div>
        <label>Public Key:</label>
        <input
          type="text"
          value={publicKey}
          onChange={(e) => setPublicKey(e.target.value)}
        />
      </div>
      <div>
        <label>Signature:</label>
        <input
          type="text"
          value={signature}
          onChange={(e) => setSignature(e.target.value)}
        />
      </div>
      <div>
        <button onClick={handleGenerateKeyPair}>Generate Key Pair</button>
        <button onClick={handleEncryptData}>Encrypt Data</button>
        <button onClick={handleDecryptData}>Decrypt Data</button>
        <button onClick={handleSignData}>Sign Data</button>
        <button onClick={handleVerifySignature}>Verify Signature</button>
        <button onClick={handleHashData}>Hash Data</button>
      </div>
      <div>
        <h3>Result:</h3>
        <p>{result}</p>
      </div>
    </div>
  );
};

export default WalletCryptoGui;
