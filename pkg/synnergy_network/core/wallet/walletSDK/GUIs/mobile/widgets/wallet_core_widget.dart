import 'package:flutter/material.dart';
import 'package:http/http.dart' as http;
import 'dart:convert';

class WalletCoreWidget extends StatefulWidget {
  @override
  _WalletCoreWidgetState createState() => _WalletCoreWidgetState();
}

class _WalletCoreWidgetState extends State<WalletCoreWidget> {
  final TextEditingController seedController = TextEditingController();
  final TextEditingController nameController = TextEditingController();
  final TextEditingController blockchainController = TextEditingController();
  final TextEditingController keyPairController = TextEditingController();
  final TextEditingController currencyController = TextEditingController();
  final TextEditingController amountController = TextEditingController();
  final TextEditingController walletIdController = TextEditingController();
  final TextEditingController filePathController = TextEditingController();
  final TextEditingController encryptionKeyController = TextEditingController();
  final TextEditingController metadataController = TextEditingController();

  String walletMetadata = '';

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: Text('Core Wallet Management'),
      ),
      body: Padding(
        padding: const EdgeInsets.all(16.0),
        child: ListView(
          children: [
            TextField(
              controller: seedController,
              decoration: InputDecoration(labelText: 'Seed'),
            ),
            ElevatedButton(
              onPressed: () => createHDWallet(seedController.text),
              child: Text('Create HD Wallet'),
            ),
            ElevatedButton(
              onPressed: generateKeyPair,
              child: Text('Generate Key Pair'),
            ),
            TextField(
              controller: nameController,
              decoration: InputDecoration(labelText: 'Currency Name'),
            ),
            TextField(
              controller: blockchainController,
              decoration: InputDecoration(labelText: 'Blockchain'),
            ),
            TextField(
              controller: keyPairController,
              decoration: InputDecoration(labelText: 'Key Pair'),
            ),
            ElevatedButton(
              onPressed: () => addCurrency(nameController.text, blockchainController.text, keyPairController.text),
              child: Text('Add Currency'),
            ),
            TextField(
              controller: currencyController,
              decoration: InputDecoration(labelText: 'Currency'),
            ),
            TextField(
              controller: amountController,
              decoration: InputDecoration(labelText: 'Amount'),
            ),
            ElevatedButton(
              onPressed: () => notifyBalanceUpdate(currencyController.text, double.parse(amountController.text)),
              child: Text('Notify Balance Update'),
            ),
            TextField(
              controller: walletIdController,
              decoration: InputDecoration(labelText: 'Wallet ID'),
            ),
            ElevatedButton(
              onPressed: () => freezeWallet(walletIdController.text),
              child: Text('Freeze Wallet'),
            ),
            ElevatedButton(
              onPressed: () => unfreezeWallet(walletIdController.text),
              child: Text('Unfreeze Wallet'),
            ),
            TextField(
              controller: filePathController,
              decoration: InputDecoration(labelText: 'File Path'),
            ),
            TextField(
              controller: encryptionKeyController,
              decoration: InputDecoration(labelText: 'Encryption Key'),
            ),
            TextField(
              controller: metadataController,
              decoration: InputDecoration(labelText: 'Wallet Metadata'),
            ),
            ElevatedButton(
              onPressed: () => saveWalletMetadata(filePathController.text, encryptionKeyController.text, metadataController.text),
              child: Text('Save Wallet Metadata'),
            ),
            ElevatedButton(
              onPressed: () => loadWalletMetadata(filePathController.text, encryptionKeyController.text),
              child: Text('Load Wallet Metadata'),
            ),
            if (walletMetadata.isNotEmpty)
              Text('Loaded Metadata: $walletMetadata'),
          ],
        ),
      ),
    );
  }

  Future<void> createHDWallet(String seed) async {
    final response = await http.post(
      Uri.parse('http://your_api_url/api/v1/wallet/hdwallet'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode({'seed': seed}),
    );

    if (response.statusCode != 201) {
      throw Exception('Failed to create HD wallet');
    }
  }

  Future<void> generateKeyPair() async {
    final response = await http.post(
      Uri.parse('http://your_api_url/api/v1/wallet/keypair'),
      headers: {'Content-Type': 'application/json'},
    );

    if (response.statusCode != 201) {
      throw Exception('Failed to generate key pair');
    }
  }

  Future<void> addCurrency(String name, String blockchain, String keyPair) async {
    final response = await http.post(
      Uri.parse('http://your_api_url/api/v1/wallet/add_currency'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode({'name': name, 'blockchain': blockchain, 'keypair': keyPair}),
    );

    if (response.statusCode != 204) {
      throw Exception('Failed to add currency');
    }
  }

  Future<void> notifyBalanceUpdate(String currency, double amount) async {
    final response = await http.post(
      Uri.parse('http://your_api_url/api/v1/wallet/notify_balance'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode({'currency': currency, 'amount': amount}),
    );

    if (response.statusCode != 204) {
      throw Exception('Failed to notify balance update');
    }
  }

  Future<void> freezeWallet(String walletId) async {
    final response = await http.post(
      Uri.parse('http://your_api_url/api/v1/wallet/freeze'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode({'wallet_id': walletId}),
    );

    if (response.statusCode != 204) {
      throw Exception('Failed to freeze wallet');
    }
  }

  Future<void> unfreezeWallet(String walletId) async {
    final response = await http.post(
      Uri.parse('http://your_api_url/api/v1/wallet/unfreeze'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode({'wallet_id': walletId}),
    );

    if (response.statusCode != 204) {
      throw Exception('Failed to unfreeze wallet');
    }
  }

  Future<void> saveWalletMetadata(String filePath, String encryptionKey, String walletMetadata) async {
    final response = await http.post(
      Uri.parse('http://your_api_url/api/v1/wallet/save_metadata'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode({'file_path': filePath, 'encryption_key': encryptionKey, 'wallet_metadata': walletMetadata}),
    );

    if (response.statusCode != 204) {
      throw Exception('Failed to save wallet metadata');
    }
  }

  Future<void> loadWalletMetadata(String filePath, String encryptionKey) async {
    final response = await http.post(
      Uri.parse('http://your_api_url/api/v1/wallet/load_metadata'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode({'file_path': filePath, 'encryption_key': encryptionKey}),
    );

    if (response.statusCode == 200) {
      final metadata = json.decode(response.body)['metadata'];
      setState(() {
        walletMetadata = metadata;
      });
    } else {
      throw Exception('Failed to load wallet metadata');
    }
  }
}
