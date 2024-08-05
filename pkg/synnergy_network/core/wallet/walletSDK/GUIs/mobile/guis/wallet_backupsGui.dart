import 'package:flutter/material.dart';
import 'package:http/http.dart' as http;
import 'dart:convert';

class WalletBackupsGui extends StatefulWidget {
  @override
  _WalletBackupsGuiState createState() => _WalletBackupsGuiState();
}

class _WalletBackupsGuiState extends State<WalletBackupsGui> {
  String encryptedData = '';
  String decryptedData = '';
  String backupStatus = '';
  final TextEditingController dataController = TextEditingController();
  final TextEditingController passphraseController = TextEditingController();

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: Text('Wallet Backups'),
      ),
      body: Padding(
        padding: const EdgeInsets.all(16.0),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            TextField(
              controller: dataController,
              decoration: InputDecoration(labelText: 'Data'),
            ),
            TextField(
              controller: passphraseController,
              decoration: InputDecoration(labelText: 'Passphrase'),
              obscureText: true,
            ),
            SizedBox(height: 10),
            ElevatedButton(
              onPressed: () => encryptData(dataController.text, passphraseController.text),
              child: Text('Encrypt Data'),
            ),
            if (encryptedData.isNotEmpty) Text('Encrypted Data: $encryptedData'),
            SizedBox(height: 10),
            ElevatedButton(
              onPressed: () => decryptData(encryptedData, passphraseController.text),
              child: Text('Decrypt Data'),
            ),
            if (decryptedData.isNotEmpty) Text('Decrypted Data: $decryptedData'),
            SizedBox(height: 10),
            ElevatedButton(
              onPressed: () => backupData(dataController.text, passphraseController.text),
              child: Text('Backup Data'),
            ),
            ElevatedButton(
              onPressed: () => restoreData(passphraseController.text),
              child: Text('Restore Data'),
            ),
            ElevatedButton(
              onPressed: getBackupStatus,
              child: Text('Get Backup Status'),
            ),
            if (backupStatus.isNotEmpty) Text('Backup Status: $backupStatus'),
          ],
        ),
      ),
    );
  }

  Future<void> encryptData(String data, String passphrase) async {
    final response = await http.post(
      Uri.parse('http://your_api_url/api/v1/backups/encrypt'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode({'data': data, 'passphrase': passphrase}),
    );

    if (response.statusCode == 200) {
      setState(() {
        encryptedData = json.decode(response.body)['encrypted_data'];
      });
    } else {
      throw Exception('Failed to encrypt data');
    }
  }

  Future<void> decryptData(String encryptedData, String passphrase) async {
    final response = await http.post(
      Uri.parse('http://your_api_url/api/v1/backups/decrypt'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode({'encrypted_data': encryptedData, 'passphrase': passphrase}),
    );

    if (response.statusCode == 200) {
      setState(() {
        decryptedData = json.decode(response.body)['decrypted_data'];
      });
    } else {
      throw Exception('Failed to decrypt data');
    }
  }

  Future<void> backupData(String data, String passphrase) async {
    final response = await http.post(
      Uri.parse('http://your_api_url/api/v1/backups/backup'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode({'user_id': 'user_id', 'data': data, 'passphrase': passphrase}),
    );

    if (response.statusCode == 204) {
      // Backup successful
      ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text('Backup successful')));
    } else {
      throw Exception('Failed to backup data');
    }
  }

  Future<void> restoreData(String passphrase) async {
    final response = await http.post(
      Uri.parse('http://your_api_url/api/v1/backups/restore'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode({'user_id': 'user_id', 'passphrase': passphrase}),
    );

    if (response.statusCode == 200) {
      setState(() {
        decryptedData = json.decode(response.body)['data'];
      });
    } else {
      throw Exception('Failed to restore data');
    }
  }

  Future<void> getBackupStatus() async {
    final response = await http.get(
      Uri.parse('http://your_api_url/api/v1/backups/status'),
      headers: {'Content-Type': 'application/json'},
    );

    if (response.statusCode == 200) {
      setState(() {
        backupStatus = json.decode(response.body)['status'];
      });
    } else {
      throw Exception('Failed to get backup status');
    }
  }
}
