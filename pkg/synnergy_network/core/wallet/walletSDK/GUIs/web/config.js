// config.js

const config = {
    apiBaseUrl: process.env.REACT_APP_API_URL || 'https://default-api-url.com',
    webSocketUrl: process.env.REACT_APP_WS_URL || 'wss://default-websocket-url.com',
    encryptionKey: process.env.REACT_APP_ENCRYPTION_KEY || 'default-encryption-key',
    theme: {
      primaryColor: process.env.REACT_APP_PRIMARY_COLOR || '#007BFF',
      secondaryColor: process.env.REACT_APP_SECONDARY_COLOR || '#6c757d',
      backgroundColor: process.env.REACT_APP_BACKGROUND_COLOR || '#f5f5f5',
      textColor: process.env.REACT_APP_TEXT_COLOR || '#333',
    },
    mailer: {
      smtpServer: process.env.REACT_APP_SMTP_SERVER || 'smtp.example.com',
      email: process.env.REACT_APP_EMAIL || 'no-reply@example.com',
      password: process.env.REACT_APP_EMAIL_PASSWORD || 'password',
    },
    storage: {
      localBackupPath: process.env.REACT_APP_LOCAL_BACKUP_PATH || '/path/to/local/backup',
      cloudBackupProviderUrl: process.env.REACT_APP_CLOUD_BACKUP_PROVIDER_URL || 'https://cloud-backup-provider-url.com',
    },
    thirdPartyServices: {
      externalApiUrl: process.env.REACT_APP_EXTERNAL_API_URL || 'https://external-api-url.com',
      apiKey: process.env.REACT_APP_API_KEY || 'default-api-key',
    },
    blockchain: {
      integrationUrl: process.env.REACT_APP_BLOCKCHAIN_INTEGRATION_URL || 'https://blockchain-integration-url.com',
      crossChainIntegrationUrl: process.env.REACT_APP_CROSS_CHAIN_INTEGRATION_URL || 'https://cross-chain-integration-url.com',
    },
    hsm: {
      modulePath: process.env.REACT_APP_HSM_MODULE_PATH || '/path/to/pkcs11/module',
      pin: process.env.REACT_APP_HSM_PIN || 'pin',
    }
  };
  
  export default config;
  