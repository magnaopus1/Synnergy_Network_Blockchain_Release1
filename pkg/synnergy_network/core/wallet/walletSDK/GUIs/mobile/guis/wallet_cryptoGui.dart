import 'package:flutter/material.dart';
import 'package:http/http.dart' as http;
import 'dart:convert';

class WalletCryptoGui extends StatefulWidget {
  @override
  _WalletCryptoGuiState createState() => _WalletCryptoGuiState();
}

class _WalletCryptoGuiState extends State<WalletCryptoGui> {
  final TextEditingController dataController = TextEditingController();
  final TextEditingController passphraseController = TextEditingController();
  final TextEditingController privateKeyController = TextEditingController();
  final TextEditingController publicKeyController = TextEditingController();
  final TextEditingController signatureController = TextEditingController();

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: Text('Crypto Operations'),
      ),
      body: Padding(
        padding: const EdgeInsets.all(16.0),
        child: ListView(
          children: [
            ElevatedButton(
              onPressed: generateKeyPair,
              child: Text('Generate Key Pair'),
            ),
            TextField(
              controller: dataController,
              decoration: InputDecoration(labelText: 'Data'),
            ),
            TextField(
              controller: passphraseController,
              decoration: InputDecoration(labelText: 'Passphrase'),
            ),
            ElevatedButton(
              onPressed: () => encryptData(dataController.text, passphraseController.text),
              child: Text('Encrypt Data'),
            ),
            ElevatedButton(
              onPressed: () => decryptData(dataController.text, passphraseController.text),
              child: Text('Decrypt Data'),
            ),
            TextField(
              controller: privateKeyController,
              decoration: InputDecoration(labelText: 'Private Key'),
            ),
            ElevatedButton(
              onPressed: () => signData(dataController.text, privateKeyController.text),
              child: Text('Sign Data'),
            ),
            TextField(
              controller: publicKeyController,
              decoration: InputDecoration(labelText: 'Public Key'),
            ),
            TextField(
              controller: signatureController,
              decoration: InputDecoration(labelText: 'Signature'),
            ),
            ElevatedButton(
              onPressed: () => verifySignature(dataController.text, publicKeyController.text, signatureController.text),
              child: Text('Verify Signature'),
            ),
            ElevatedButton(
              onPressed: () => hashData(dataController.text),
              child: Text('Hash Data'),
            ),
          ],
        ),
      ),
    );
  }

  Future<void> generateKeyPair() async {
    final response = await http.post(
      Uri.parse('http://your_api_url/api/generate_keypair'),
      headers: {'Content-Type': 'application/json'},
    );

    if (response.statusCode == 200) {
      final data = json.decode(response.body)['data'];
      showDialog(
        context: context,
        builder: (BuildContext context) {
          return AlertDialog(
            title: Text('Key Pair Generated'),
            content: SingleChildScrollView(
              child: ListBody(
                children: <Widget>[
                  Text('Private Key: ${data['private_key']}'),
                  Text('Public Key: ${data['public_key']}'),
                ],
              ),
            ),
            actions: <Widget>[
              TextButton(
                child: Text('Close'),
                onPressed: () {
                  Navigator.of(context).pop();
                },
              ),
            ],
          );
        },
      );
    } else {
      throw Exception('Failed to generate key pair');
    }
  }

  Future<void> encryptData(String data, String passphrase) async {
    final response = await http.post(
      Uri.parse('http://your_api_url/api/encrypt_data'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode({'data': data, 'passphrase': passphrase}),
    );

    if (response.statusCode == 200) {
      final encryptedData = json.decode(response.body)['data']['encrypted_data'];
      showDialog(
        context: context,
        builder: (BuildContext context) {
          return AlertDialog(
            title: Text('Data Encrypted'),
            content: SingleChildScrollView(
              child: ListBody(
                children: <Widget>[
                  Text('Encrypted Data: $encryptedData'),
                ],
              ),
            ),
            actions: <Widget>[
              TextButton(
                child: Text('Close'),
                onPressed: () {
                  Navigator.of(context).pop();
                },
              ),
            ],
          );
        },
      );
    } else {
      throw Exception('Failed to encrypt data');
    }
  }

  Future<void> decryptData(String data, String passphrase) async {
    final response = await http.post(
      Uri.parse('http://your_api_url/api/decrypt_data'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode({'data': data, 'passphrase': passphrase}),
    );

    if (response.statusCode == 200) {
      final decryptedData = json.decode(response.body)['data']['decrypted_data'];
      showDialog(
        context: context,
        builder: (BuildContext context) {
          return AlertDialog(
            title: Text('Data Decrypted'),
            content: SingleChildScrollView(
              child: ListBody(
                children: <Widget>[
                  Text('Decrypted Data: $decryptedData'),
                ],
              ),
            ),
            actions: <Widget>[
              TextButton(
                child: Text('Close'),
                onPressed: () {
                  Navigator.of(context).pop();
                },
              ),
            ],
          );
        },
      );
    } else {
      throw Exception('Failed to decrypt data');
    }
  }

  Future<void> signData(String data, String privateKey) async {
    final response = await http.post(
      Uri.parse('http://your_api_url/api/sign_data'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode({'data': data, 'private_key': privateKey}),
    );

    if (response.statusCode == 200) {
      final signature = json.decode(response.body)['data']['signature'];
      showDialog(
        context: context,
        builder: (BuildContext context) {
          return AlertDialog(
            title: Text('Data Signed'),
            content: SingleChildScrollView(
              child: ListBody(
                children: <Widget>[
                  Text('Signature: $signature'),
                ],
              ),
            ),
            actions: <Widget>[
              TextButton(
                child: Text('Close'),
                onPressed: () {
                  Navigator.of(context).pop();
                },
              ),
            ],
          );
        },
      );
    } else {
      throw Exception('Failed to sign data');
    }
  }

  Future<void> verifySignature(String data, String publicKey, String signature) async {
    final response = await http.post(
      Uri.parse('http://your_api_url/api/verify_signature'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode({'data': data, 'public_key': publicKey, 'signature': signature}),
    );

    if (response.statusCode == 200) {
      final isValid = json.decode(response.body)['data']['is_valid'];
      showDialog(
        context: context,
        builder: (BuildContext context) {
          return AlertDialog(
            title: Text('Signature Verification'),
            content: SingleChildScrollView(
              child: ListBody(
                children: <Widget>[
                  Text('Is Valid: $isValid'),
                ],
              ),
            ),
            actions: <Widget>[
              TextButton(
                child: Text('Close'),
                onPressed: () {
                  Navigator.of(context).pop();
                },
              ),
            ],
          );
        },
      );
    } else {
      throw Exception('Failed to verify signature');
    }
  }

  Future<void> hashData(String data) async {
    final response = await http.post(
      Uri.parse('http://your_api_url/api/hash_data'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode({'data': data}),
    );

    if (response.statusCode == 200) {
      final hash = json.decode(response.body)['data']['hash'];
      showDialog(
        context: context,
        builder: (BuildContext context) {
          return AlertDialog(
            title: Text('Data Hashed'),
            content: SingleChildScrollView(
              child: ListBody(
                children: <Widget>[
                  Text('Hash: $hash'),
                ],
              ),
            ),
            actions: <Widget>[
              TextButton(
                child: Text('Close'),
                onPressed: () {
                  Navigator.of(context).pop();
                },
              ),
            ],
          );
        },
      );
    } else {
      throw Exception('Failed to hash data');
    }
  }
}
