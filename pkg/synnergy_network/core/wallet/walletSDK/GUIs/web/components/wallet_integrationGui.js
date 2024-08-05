import React, { useState } from 'react';
import {
  checkBalance,
  sendTransaction,
  syncWithBlockchain,
  crossChainTransfer,
  syncWithExternalAPI,
  hsmGenerateKeyPair,
  integrateThirdPartyService,
} from '../api_service/wallet_integration_api_service';

const WalletIntegrationGui = () => {
  const [walletAddress, setWalletAddress] = useState('');
  const [balance, setBalance] = useState(null);
  const [fromAddress, setFromAddress] = useState('');
  const [toAddress, setToAddress] = useState('');
  const [amount, setAmount] = useState('');
  const [privateKey, setPrivateKey] = useState('');
  const [sourceChain, setSourceChain] = useState('');
  const [targetChain, setTargetChain] = useState('');
  const [externalAPIUrl, setExternalAPIUrl] = useState('');
  const [transactionResult, setTransactionResult] = useState(null);
  const [hsmKeyPair, setHsmKeyPair] = useState(null);
  const [thirdPartyData, setThirdPartyData] = useState(null);

  const handleCheckBalance = async () => {
    try {
      const data = await checkBalance(walletAddress);
      setBalance(data);
    } catch (error) {
      console.error('Error checking balance:', error);
    }
  };

  const handleSendTransaction = async () => {
    try {
      await sendTransaction(fromAddress, toAddress, parseFloat(amount), privateKey);
      setTransactionResult('Transaction sent successfully');
    } catch (error) {
      console.error('Error sending transaction:', error);
      setTransactionResult('Failed to send transaction');
    }
  };

  const handleSyncWithBlockchain = async () => {
    try {
      await syncWithBlockchain();
      setTransactionResult('Synced with blockchain successfully');
    } catch (error) {
      console.error('Error syncing with blockchain:', error);
      setTransactionResult('Failed to sync with blockchain');
    }
  };

  const handleCrossChainTransfer = async () => {
    try {
      const data = await crossChainTransfer(sourceChain, targetChain, fromAddress, toAddress, parseFloat(amount));
      setTransactionResult(`Cross-chain transfer successful: ${data}`);
    } catch (error) {
      console.error('Error performing cross-chain transfer:', error);
      setTransactionResult('Failed to perform cross-chain transfer');
    }
  };

  const handleSyncWithExternalAPI = async () => {
    try {
      await syncWithExternalAPI();
      setTransactionResult('Synced with external API successfully');
    } catch (error) {
      console.error('Error syncing with external API:', error);
      setTransactionResult('Failed to sync with external API');
    }
  };

  const handleHSMGenerateKeyPair = async () => {
    try {
      const data = await hsmGenerateKeyPair();
      setHsmKeyPair(data);
    } catch (error) {
      console.error('Error generating key pair using HSM:', error);
    }
  };

  const handleIntegrateThirdPartyService = async () => {
    try {
      const data = await integrateThirdPartyService(externalAPIUrl);
      setThirdPartyData(data);
    } catch (error) {
      console.error('Error integrating third-party service:', error);
    }
  };

  return (
    <div>
      <h1>Wallet Integration Management</h1>

      <div>
        <h2>Check Balance</h2>
        <input
          type="text"
          placeholder="Wallet Address"
          value={walletAddress}
          onChange={(e) => setWalletAddress(e.target.value)}
        />
        <button onClick={handleCheckBalance}>Check Balance</button>
        {balance && <p>Balance: {balance}</p>}
      </div>

      <div>
        <h2>Send Transaction</h2>
        <input
          type="text"
          placeholder="From Address"
          value={fromAddress}
          onChange={(e) => setFromAddress(e.target.value)}
        />
        <input
          type="text"
          placeholder="To Address"
          value={toAddress}
          onChange={(e) => setToAddress(e.target.value)}
        />
        <input
          type="number"
          placeholder="Amount"
          value={amount}
          onChange={(e) => setAmount(e.target.value)}
        />
        <input
          type="text"
          placeholder="Private Key"
          value={privateKey}
          onChange={(e) => setPrivateKey(e.target.value)}
        />
        <button onClick={handleSendTransaction}>Send Transaction</button>
        {transactionResult && <p>{transactionResult}</p>}
      </div>

      <div>
        <h2>Sync with Blockchain</h2>
        <button onClick={handleSyncWithBlockchain}>Sync with Blockchain</button>
      </div>

      <div>
        <h2>Cross-Chain Transfer</h2>
        <input
          type="text"
          placeholder="Source Chain"
          value={sourceChain}
          onChange={(e) => setSourceChain(e.target.value)}
        />
        <input
          type="text"
          placeholder="Target Chain"
          value={targetChain}
          onChange={(e) => setTargetChain(e.target.value)}
        />
        <button onClick={handleCrossChainTransfer}>Cross-Chain Transfer</button>
        {transactionResult && <p>{transactionResult}</p>}
      </div>

      <div>
        <h2>Sync with External API</h2>
        <button onClick={handleSyncWithExternalAPI}>Sync with External API</button>
      </div>

      <div>
        <h2>Generate Key Pair using HSM</h2>
        <button onClick={handleHSMGenerateKeyPair}>Generate Key Pair</button>
        {hsmKeyPair && (
          <div>
            <p>Private Key: {hsmKeyPair.private_key}</p>
            <p>Public Key: {hsmKeyPair.public_key}</p>
          </div>
        )}
      </div>

      <div>
        <h2>Integrate Third-Party Service</h2>
        <input
          type="text"
          placeholder="External API URL"
          value={externalAPIUrl}
          onChange={(e) => setExternalAPIUrl(e.target.value)}
        />
        <button onClick={handleIntegrateThirdPartyService}>Integrate</button>
        {thirdPartyData && <p>{JSON.stringify(thirdPartyData)}</p>}
      </div>
    </div>
  );
};

export default WalletIntegrationGui;
