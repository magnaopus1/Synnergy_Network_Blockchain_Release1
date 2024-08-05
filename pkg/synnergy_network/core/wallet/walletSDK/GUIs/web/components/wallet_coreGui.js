import React, { useState } from 'react';
import { createHDWallet, generateKeyPair, addCurrency, notifyBalanceUpdate, freezeWallet, unfreezeWallet, saveWalletMetadata, loadWalletMetadata } from '../api_service/wallet_core_api_service';

const WalletCoreGui = () => {
  const [seed, setSeed] = useState('');
  const [keyPair, setKeyPair] = useState(null);
  const [currencyName, setCurrencyName] = useState('');
  const [blockchain, setBlockchain] = useState('');
  const [currencyKeyPair, setCurrencyKeyPair] = useState(null);
  const [walletId, setWalletId] = useState('');
  const [currency, setCurrency] = useState('');
  const [amount, setAmount] = useState('');
  const [filePath, setFilePath] = useState('');
  const [encryptionKey, setEncryptionKey] = useState('');
  const [walletMetadata, setWalletMetadata] = useState('');
  const [loadedMetadata, setLoadedMetadata] = useState(null);

  const handleCreateHDWallet = async () => {
    try {
      const wallet = await createHDWallet(seed);
      console.log('HD Wallet Created:', wallet);
    } catch (error) {
      console.error('Error creating HD Wallet:', error);
    }
  };

  const handleGenerateKeyPair = async () => {
    try {
      const keypair = await generateKeyPair();
      setKeyPair(keypair);
      console.log('Key Pair Generated:', keypair);
    } catch (error) {
      console.error('Error generating key pair:', error);
    }
  };

  const handleAddCurrency = async () => {
    try {
      await addCurrency(currencyName, blockchain, currencyKeyPair);
      console.log('Currency added to wallet');
    } catch (error) {
      console.error('Error adding currency:', error);
    }
  };

  const handleNotifyBalanceUpdate = async () => {
    try {
      await notifyBalanceUpdate(currency, parseFloat(amount));
      console.log('Balance update notification sent');
    } catch (error) {
      console.error('Error notifying balance update:', error);
    }
  };

  const handleFreezeWallet = async () => {
    try {
      await freezeWallet(walletId);
      console.log('Wallet frozen');
    } catch (error) {
      console.error('Error freezing wallet:', error);
    }
  };

  const handleUnfreezeWallet = async () => {
    try {
      await unfreezeWallet(walletId);
      console.log('Wallet unfrozen');
    } catch (error) {
      console.error('Error unfreezing wallet:', error);
    }
  };

  const handleSaveWalletMetadata = async () => {
    try {
      await saveWalletMetadata(filePath, encryptionKey, walletMetadata);
      console.log('Wallet metadata saved');
    } catch (error) {
      console.error('Error saving wallet metadata:', error);
    }
  };

  const handleLoadWalletMetadata = async () => {
    try {
      const metadata = await loadWalletMetadata(filePath, encryptionKey);
      setLoadedMetadata(metadata);
      console.log('Wallet metadata loaded:', metadata);
    } catch (error) {
      console.error('Error loading wallet metadata:', error);
    }
  };

  return (
    <div>
      <h1>Wallet Core Management</h1>
      <div>
        <h2>Create HD Wallet</h2>
        <input type="text" value={seed} onChange={(e) => setSeed(e.target.value)} placeholder="Seed" />
        <button onClick={handleCreateHDWallet}>Create HD Wallet</button>
      </div>
      <div>
        <h2>Generate Key Pair</h2>
        <button onClick={handleGenerateKeyPair}>Generate Key Pair</button>
        {keyPair && (
          <div>
            <p>Public Key: {keyPair.publicKey}</p>
            <p>Private Key: {keyPair.privateKey}</p>
          </div>
        )}
      </div>
      <div>
        <h2>Add Currency</h2>
        <input type="text" value={currencyName} onChange={(e) => setCurrencyName(e.target.value)} placeholder="Currency Name" />
        <input type="text" value={blockchain} onChange={(e) => setBlockchain(e.target.value)} placeholder="Blockchain" />
        <input type="text" value={currencyKeyPair} onChange={(e) => setCurrencyKeyPair(e.target.value)} placeholder="Key Pair" />
        <button onClick={handleAddCurrency}>Add Currency</button>
      </div>
      <div>
        <h2>Notify Balance Update</h2>
        <input type="text" value={currency} onChange={(e) => setCurrency(e.target.value)} placeholder="Currency" />
        <input type="text" value={amount} onChange={(e) => setAmount(e.target.value)} placeholder="Amount" />
        <button onClick={handleNotifyBalanceUpdate}>Notify Balance Update</button>
      </div>
      <div>
        <h2>Freeze Wallet</h2>
        <input type="text" value={walletId} onChange={(e) => setWalletId(e.target.value)} placeholder="Wallet ID" />
        <button onClick={handleFreezeWallet}>Freeze Wallet</button>
      </div>
      <div>
        <h2>Unfreeze Wallet</h2>
        <input type="text" value={walletId} onChange={(e) => setWalletId(e.target.value)} placeholder="Wallet ID" />
        <button onClick={handleUnfreezeWallet}>Unfreeze Wallet</button>
      </div>
      <div>
        <h2>Save Wallet Metadata</h2>
        <input type="text" value={filePath} onChange={(e) => setFilePath(e.target.value)} placeholder="File Path" />
        <input type="text" value={encryptionKey} onChange={(e) => setEncryptionKey(e.target.value)} placeholder="Encryption Key" />
        <textarea value={walletMetadata} onChange={(e) => setWalletMetadata(e.target.value)} placeholder="Wallet Metadata"></textarea>
        <button onClick={handleSaveWalletMetadata}>Save Wallet Metadata</button>
      </div>
      <div>
        <h2>Load Wallet Metadata</h2>
        <input type="text" value={filePath} onChange={(e) => setFilePath(e.target.value)} placeholder="File Path" />
        <input type="text" value={encryptionKey} onChange={(e) => setEncryptionKey(e.target.value)} placeholder="Encryption Key" />
        <button onClick={handleLoadWalletMetadata}>Load Wallet Metadata</button>
        {loadedMetadata && (
          <div>
            <pre>{JSON.stringify(loadedMetadata, null, 2)}</pre>
          </div>
        )}
      </div>
    </div>
  );
};

export default WalletCoreGui;
