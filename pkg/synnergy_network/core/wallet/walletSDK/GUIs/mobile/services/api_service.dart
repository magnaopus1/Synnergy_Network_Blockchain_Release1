import 'dart:convert';
import 'package:http/http.dart' as http;

class ApiService {
  static const String baseUrl = 'http://your_api_url/api';

  // General method for GET requests
  static Future<Map<String, dynamic>> getRequest(String endpoint) async {
    final response = await http.get(Uri.parse('$baseUrl/$endpoint'));
    if (response.statusCode == 200) {
      return json.decode(response.body);
    } else {
      throw Exception('Failed to load data');
    }
  }

  // General method for POST requests
  static Future<Map<String, dynamic>> postRequest(String endpoint, Map<String, dynamic> body) async {
    final response = await http.post(
      Uri.parse('$baseUrl/$endpoint'),
      headers: {'Content-Type': 'application/json'},
      body: json.encode(body),
    );
    if (response.statusCode == 200 || response.statusCode == 201) {
      return json.decode(response.body);
    } else if (response.statusCode == 204) {
      return {};
    } else {
      throw Exception('Failed to post data');
    }
  }

  // Wallet Analytics
  static Future<Map<String, dynamic>> fetchPerformanceMetrics() async {
    return await getRequest('v1/performance/metrics');
  }

  static Future<Map<String, dynamic>> fetchTransactionAnalytics() async {
    return await getRequest('v1/transactions/analytics');
  }

  static Future<List<dynamic>> fetchRiskEvents() async {
    final data = await getRequest('v1/risks');
    return data['data'];
  }

  static Future<List<dynamic>> fetchUserActivities(String userId) async {
    final data = await getRequest('v1/user/activities/$userId');
    return data['data'];
  }

  static Future<List<dynamic>> fetchUserPatterns() async {
    final data = await getRequest('v1/user/patterns');
    return data['data'];
  }

  // Wallet Backups
  static Future<String> encryptData(String data, String passphrase) async {
    final result = await postRequest('v1/backups/encrypt', {'data': data, 'passphrase': passphrase});
    return result['encrypted_data'];
  }

  static Future<String> decryptData(String encryptedData, String passphrase) async {
    final result = await postRequest('v1/backups/decrypt', {'encrypted_data': encryptedData, 'passphrase': passphrase});
    return result['decrypted_data'];
  }

  static Future<void> backupData(String userId, String data, String passphrase) async {
    await postRequest('v1/backups/backup', {'user_id': userId, 'data': data, 'passphrase': passphrase});
  }

  static Future<String> restoreData(String userId, String passphrase) async {
    final result = await postRequest('v1/backups/restore', {'user_id': userId, 'passphrase': passphrase});
    return result['data'];
  }

  static Future<String> getBackupStatus() async {
    final result = await getRequest('v1/backups/status');
    return result['status'];
  }

  // Wallet Compliance
  static Future<void> kycVerification(String userId) async {
    await postRequest('v1/compliance/kyc', {'user_id': userId});
  }

  static Future<void> amlCheck(String userId) async {
    await postRequest('v1/compliance/aml', {'user_id': userId});
  }

  static Future<void> complianceCheck(String userId) async {
    await postRequest('v1/compliance/check', {'user_id': userId});
  }

  static Future<void> logTransaction(String transactionData) async {
    await postRequest('v1/compliance/audit/log_transaction', {'transaction': transactionData});
  }

  static Future<void> logAccess(String userId, String resource, String accessType, bool allowed) async {
    await postRequest('v1/compliance/audit/log_access', {'user_id': userId, 'resource': resource, 'access_type': accessType, 'allowed': allowed});
  }

  static Future<void> logComplianceEvent(String event, String details) async {
    await postRequest('v1/compliance/audit/log_event', {'event': event, 'details': details});
  }

  static Future<Map<String, dynamic>> generateReport(String startTime, String endTime) async {
    return await postRequest('v1/compliance/report/generate', {'start_time': startTime, 'end_time': endTime});
  }

  static Future<void> submitReport(Map<String, dynamic> reportData) async {
    await postRequest('v1/compliance/report/submit', {'report': reportData});
  }

  // Core Wallet Management
  static Future<void> createHDWallet(String seed) async {
    await postRequest('v1/wallet/hdwallet', {'seed': seed});
  }

  static Future<void> generateKeyPair() async {
    await postRequest('v1/wallet/keypair', {});
  }

  static Future<void> addCurrency(String name, String blockchain, String keyPair) async {
    await postRequest('v1/wallet/add_currency', {'name': name, 'blockchain': blockchain, 'keypair': keyPair});
  }

  static Future<void> notifyBalanceUpdate(String currency, double amount) async {
    await postRequest('v1/wallet/notify_balance', {'currency': currency, 'amount': amount});
  }

  static Future<void> freezeWallet(String walletId) async {
    await postRequest('v1/wallet/freeze', {'wallet_id': walletId});
  }

  static Future<void> unfreezeWallet(String walletId) async {
    await postRequest('v1/wallet/unfreeze', {'wallet_id': walletId});
  }

  static Future<void> saveWalletMetadata(String filePath, String encryptionKey, String walletMetadata) async {
    await postRequest('v1/wallet/save_metadata', {'file_path': filePath, 'encryption_key': encryptionKey, 'wallet_metadata': walletMetadata});
  }

  static Future<Map<String, dynamic>> loadWalletMetadata(String filePath, String encryptionKey) async {
    return await postRequest('v1/wallet/load_metadata', {'file_path': filePath, 'encryption_key': encryptionKey});
  }

  // Crypto Operations
  static Future<Map<String, dynamic>> generateCryptoKeyPair() async {
    return await postRequest('generate_keypair', {});
  }

  static Future<String> encryptCryptoData(String data, String passphrase) async {
    final result = await postRequest('encrypt_data', {'data': data, 'passphrase': passphrase});
    return result['encrypted_data'];
  }

  static Future<String> decryptCryptoData(String encryptedData, String passphrase) async {
    final result = await postRequest('decrypt_data', {'data': encryptedData, 'passphrase': passphrase});
    return result['decrypted_data'];
  }

  static Future<String> signCryptoData(String data, String privateKey) async {
    final result = await postRequest('sign_data', {'data': data, 'private_key': privateKey});
    return result['signature'];
  }

  static Future<bool> verifyCryptoSignature(String data, String publicKey, String signature) async {
    final result = await postRequest('verify_signature', {'data': data, 'public_key': publicKey, 'signature': signature});
    return result['is_valid'];
  }

  static Future<String> hashCryptoData(String data) async {
    final result = await postRequest('hash_data', {'data': data});
    return result['hash'];
  }

  // Wallet Display
  static Future<Map<String, dynamic>> handleARDisplay(String walletId) async {
    return await getRequest('ar_display?wallet_id=$walletId');
  }

  static Future<void> handleThemeCustomization(String name) async {
    await postRequest('theme_customization', {'name': name});
  }

  static Future<void> handleVoiceCommandSettings(bool enabled, String locale) async {
    await postRequest('voice_command', {'enabled': enabled, 'locale': locale});
  }

  static Future<void> registerWalletAlias(String alias, String address) async {
    await postRequest('wallet_naming', {'alias': alias, 'address': address});
  }

  static Future<void> removeWalletAlias(String alias) async {
    await postRequest('wallet_naming', {'alias': alias});
  }

  // Wallet Integration
  static Future<Map<String, dynamic>> checkBalance(String walletAddress) async {
    return await getRequest('check_balance?wallet_address=$walletAddress');
  }

  static Future<void> sendTransaction(String from, String to, double amount, String privateKey) async {
    await postRequest('send_transaction', {'from': from, 'to': to, 'amount': amount, 'private_key': privateKey});
  }

  static Future<void> syncWithBlockchain() async {
    await postRequest('sync_blockchain', {});
  }

  static Future<String> crossChainTransfer(String sourceChain, String targetChain, String fromAddr, String toAddr, double amount) async {
    final result = await postRequest('cross_chain_transfer', {
      'source_chain': sourceChain,
      'target_chain': targetChain,
      'from_addr': fromAddr,
      'to_addr': toAddr,
      'amount': amount
    });
    return result['txID'];
  }

  static Future<void> syncWithExternalAPI(String url) async {
    await postRequest('external_api_sync', {'url': url});
  }
}
