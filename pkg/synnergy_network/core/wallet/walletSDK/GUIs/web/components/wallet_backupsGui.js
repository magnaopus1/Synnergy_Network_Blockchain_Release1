import React, { useState } from 'react';
import {
  encryptData,
  decryptData,
  backupData,
  restoreData,
  scheduleBackup,
  getBackupStatus,
} from '../api_service/wallet_backups_api_service';

const WalletBackupsGui = () => {
  const [data, setData] = useState('');
  const [passphrase, setPassphrase] = useState('');
  const [userId, setUserId] = useState('');
  const [interval, setInterval] = useState('');
  const [encryptedData, setEncryptedData] = useState('');
  const [decryptedData, setDecryptedData] = useState('');
  const [backupStatus, setBackupStatus] = useState('');

  const handleEncryptData = async () => {
    try {
      const result = await encryptData(data, passphrase);
      setEncryptedData(result);
    } catch (error) {
      console.error('Failed to encrypt data', error);
    }
  };

  const handleDecryptData = async () => {
    try {
      const result = await decryptData(encryptedData, passphrase);
      setDecryptedData(result);
    } catch (error) {
      console.error('Failed to decrypt data', error);
    }
  };

  const handleBackupData = async () => {
    try {
      await backupData(userId, data, passphrase);
      alert('Backup successful');
    } catch (error) {
      console.error('Failed to backup data', error);
    }
  };

  const handleRestoreData = async () => {
    try {
      const result = await restoreData(userId, passphrase);
      setDecryptedData(result);
    } catch (error) {
      console.error('Failed to restore data', error);
    }
  };

  const handleScheduleBackup = async () => {
    try {
      await scheduleBackup(Number(interval));
      alert('Backup scheduled successfully');
    } catch (error) {
      console.error('Failed to schedule backup', error);
    }
  };

  const handleGetBackupStatus = async () => {
    try {
      const status = await getBackupStatus();
      setBackupStatus(status);
    } catch (error) {
      console.error('Failed to get backup status', error);
    }
  };

  return (
    <div>
      <h1>Wallet Backups Management</h1>
      <div>
        <h2>Encrypt Data</h2>
        <input
          type="text"
          placeholder="Data"
          value={data}
          onChange={(e) => setData(e.target.value)}
        />
        <input
          type="password"
          placeholder="Passphrase"
          value={passphrase}
          onChange={(e) => setPassphrase(e.target.value)}
        />
        <button onClick={handleEncryptData}>Encrypt Data</button>
        {encryptedData && <p>Encrypted Data: {encryptedData}</p>}
      </div>
      <div>
        <h2>Decrypt Data</h2>
        <input
          type="password"
          placeholder="Passphrase"
          value={passphrase}
          onChange={(e) => setPassphrase(e.target.value)}
        />
        <button onClick={handleDecryptData}>Decrypt Data</button>
        {decryptedData && <p>Decrypted Data: {decryptedData}</p>}
      </div>
      <div>
        <h2>Backup Data</h2>
        <input
          type="text"
          placeholder="User ID"
          value={userId}
          onChange={(e) => setUserId(e.target.value)}
        />
        <button onClick={handleBackupData}>Backup Data</button>
      </div>
      <div>
        <h2>Restore Data</h2>
        <input
          type="password"
          placeholder="Passphrase"
          value={passphrase}
          onChange={(e) => setPassphrase(e.target.value)}
        />
        <button onClick={handleRestoreData}>Restore Data</button>
        {decryptedData && <p>Restored Data: {decryptedData}</p>}
      </div>
      <div>
        <h2>Schedule Backup</h2>
        <input
          type="number"
          placeholder="Interval (hours)"
          value={interval}
          onChange={(e) => setInterval(e.target.value)}
        />
        <button onClick={handleScheduleBackup}>Schedule Backup</button>
      </div>
      <div>
        <h2>Backup Status</h2>
        <button onClick={handleGetBackupStatus}>Get Backup Status</button>
        {backupStatus && <p>Backup Status: {backupStatus}</p>}
      </div>
    </div>
  );
};

export default WalletBackupsGui;
