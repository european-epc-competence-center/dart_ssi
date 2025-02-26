import 'dart:async';
import 'dart:typed_data';

import 'package:bip39/bip39.dart';
import 'package:crypto/crypto.dart';
import 'package:hive/hive.dart';

import '../../didcomm.dart';
import '../util/private_util.dart';
import 'hive_model.dart';
import 'key_storage.dart';

class WalletException implements Exception {
  String message;
  WalletException(this.message);
}

/// A wallet storing credentials and keys permanently using Hive.
///
/// Keys are stored and generated according to BIP32 standard.
class WalletStore {
  final String _walletPath;
  late String _nameExpansion;
  Map<String, KeyStoreBackend>? _keyStorage;
  Box<Credential>? _credentialBox;
  Box? _configBox;
  Box<Credential>? _issuingHistory;
  Box<Connection>? _connection;
  Box<List<dynamic>>? _exchangeHistory;
  Box<DidcommConversation>? _didcommConversations;

  /// Constructs a wallet at file-system path [path].
  WalletStore(this._walletPath, [String? nameExpansion]) {
    Hive.init(_walletPath);
    if (nameExpansion == null) {
      _nameExpansion = _walletPath.replaceAll('/', '_').replaceAll(r'\', '_');
      var split = _nameExpansion.split('_');
      if (split.length > 3) {
        _nameExpansion =
            '${split[split.length - 3]}${split[split.length - 2]}${split[split.length - 1]}';
      }
    } else {
      _nameExpansion = nameExpansion;
    }

    if (!Hive.isAdapterRegistered(CredentialAdapter().typeId)) {
      Hive.registerAdapter(CredentialAdapter());
    }
    if (!Hive.isAdapterRegistered(ConnectionAdapter().typeId)) {
      Hive.registerAdapter(ConnectionAdapter());
    }
    if (!Hive.isAdapterRegistered(ExchangeHistoryEntryAdapter().typeId)) {
      Hive.registerAdapter(ExchangeHistoryEntryAdapter());
    }
    if (!Hive.isAdapterRegistered(DidcommConversationAdapter().typeId)) {
      Hive.registerAdapter(DidcommConversationAdapter());
    }
  }

  /// Opens storage containers optional encrypted with [password]
  Future<bool> openBoxes(
      {String? password, Map<String, KeyStoreBackend>? keyStorage}) async {
    if (keyStorage != null) {
      _keyStorage = keyStorage;
    } else {
      _keyStorage = {
        'software': SoftwareKeyStoreBackend(password, _nameExpansion)
      };
    }

    for (var storage in _keyStorage!.values) {
      storage.initializeStorage();
    }

    //password to AES-Key
    if (password != null) {
      var generator = PBKDF2(hash: sha256);
      var aesKey = generator.generateKey(password, "salt", 1000, 32);
      //only values are encrypted, keys are stored in plaintext
      try {
        _credentialBox = await Hive.openBox<Credential>(
            'credentialBox_$_nameExpansion',
            encryptionCipher: HiveAesCipher(aesKey),
            crashRecovery: false);
        _configBox = await Hive.openBox('configBox_$_nameExpansion',
            encryptionCipher: HiveAesCipher(aesKey), crashRecovery: false);
        _issuingHistory = await Hive.openBox<Credential>(
            'issuingHistory_$_nameExpansion',
            encryptionCipher: HiveAesCipher(aesKey),
            crashRecovery: false);
        _connection = await Hive.openBox<Connection>(
            'connections_$_nameExpansion',
            encryptionCipher: HiveAesCipher(aesKey),
            crashRecovery: false);
        _exchangeHistory = await Hive.openBox<List<dynamic>>(
            'exchangeHistory_$_nameExpansion',
            encryptionCipher: HiveAesCipher(aesKey),
            crashRecovery: false);
        _didcommConversations = await Hive.openBox<DidcommConversation>(
            'didcommConversations_$_nameExpansion',
            encryptionCipher: HiveAesCipher(aesKey),
            crashRecovery: false);
      } catch (e) {
        if (e is HiveError && e.message.contains('corrupted')) {
          throw WalletException('Cant open boxes. Maybe wrong password?');
        } else {
          rethrow;
        }
      }
    } else {
      _credentialBox = await Hive.openBox<Credential>(
          'credentialBox_$_nameExpansion',
          path: _walletPath);
      _configBox =
          await Hive.openBox('configBox_$_nameExpansion', path: _walletPath);
      _issuingHistory = await Hive.openBox<Credential>(
          'issuingHistory_$_nameExpansion',
          path: _walletPath);
      _connection = await Hive.openBox<Connection>(
          'connections_$_nameExpansion',
          path: _walletPath);
      _exchangeHistory = await Hive.openBox<List<dynamic>>(
          'exchangeHistory_$_nameExpansion',
          path: _walletPath);
      _didcommConversations = await Hive.openBox<DidcommConversation>(
          'didcommConversations$_nameExpansion',
          path: _walletPath);
    }
    _update();
    return _issuingHistory != null &&
        _credentialBox != null &&
        _configBox != null &&
        _connection != null &&
        _exchangeHistory != null &&
        _didcommConversations != null;
  }

  bool isWalletOpen() {
    if (_issuingHistory == null ||
        _credentialBox == null ||
        _configBox == null ||
        _exchangeHistory == null ||
        _connection == null ||
        _didcommConversations == null) {
      return false;
    } else {
      return (_issuingHistory!.isOpen) &&
          (_credentialBox!.isOpen) &&
          (_configBox!.isOpen) &&
          (_exchangeHistory!.isOpen) &&
          (_connection!.isOpen) &&
          (_didcommConversations!.isOpen);
    }
  }

  /// Closes storage containers.
  Future<void> closeBoxes() async {
    await _credentialBox!.close();
    await _configBox!.close();
    await _connection!.close();
    await _issuingHistory!.close();
    await _exchangeHistory!.close();
    await _didcommConversations!.close();
  }

  // ***** Things to update ****
// - issuerDid & issuerDidEd move from KeyBox to configBox
// - issuerDid und issuerDidEd umbenannt zu issuer$keyType
// - new KeyBox shall store did: HD path
  void _update() {
    var hasUpdate = _configBox!.get('update');
    if (hasUpdate != null) return;
    var softwareKeyStore = _keyStorage?['software'];
    if (softwareKeyStore != null) {
      var keyData = softwareKeyStore.export() as Map;
      var issuerDid = keyData['issuerDid'];
      if (issuerDid != null) {
        _configBox!.put('issuer${KeyType.secp256k1}', issuerDid);
      }
      var issuerDidEd = keyData['issuerDidEd'];
      if (issuerDidEd != null) {
        _configBox!.put('issuer${KeyType.ed25519}', issuerDidEd);
      }

      var creds = getAllCredentials();
      var toImport = creds.map((k, v) => MapEntry(k, v.hdPath));
      softwareKeyStore.import(toImport);
      _configBox!.put('update', 'yes');
    }
  }

  Future<Map<String, Map<String, dynamic>>> export() async {
    Map<String, Map<String, dynamic>> data = {};
    data['configuration'] =
        _configBox!.toMap().map((k, v) => MapEntry(k as String, v));
    data['credentials'] =
        getAllCredentials().map((k, v) => MapEntry(k as String, v.toJson()));
    data['connection'] =
        getAllConnections().map((k, v) => MapEntry(k as String, v.toJson()));
    data['issuedCredentials'] = getAllIssuedCredentials()
        .map((k, v) => MapEntry(k as String, v.toJson()));
    data['history'] = _exchangeHistory!.toMap().map((k, v) => MapEntry(
        k as String,
        v.map((e) => (e as ExchangeHistoryEntry).toJson()).toList()));
    data['communication'] = _didcommConversations!
        .toMap()
        .map((k, v) => MapEntry(k as String, v.toJson()));

    for (var entry in _keyStorage!.entries) {
      try {
        var export = await entry.value.export();
        if (export is Map<String, dynamic>) {
          data['keystore_${entry.key}'] = export;
        } else {
          data['keystore_${entry.key}'] = {'data': export};
        }
      } catch (e) {
        print(e);
        data['keystore_${entry.key}'] = {'warning': 'Not exportable'};
      }
    }
    return data;
  }

  Future<void> import(Map<String, Map<String, dynamic>> data) async {
    _configBox!.putAll(data['configuration'] ?? {});
    _credentialBox!.putAll((data['credentials'] ?? {})
        .map((k, v) => MapEntry(k, Credential.fromJson(v))));
    _connection!.putAll((data['connection'] ?? {})
        .map((k, v) => MapEntry(k, Connection.fromJson(v))));
    _issuingHistory!.putAll((data['issuedCredentials'] ?? {})
        .map((k, v) => MapEntry(k, Credential.fromJson(v))));
    _exchangeHistory!.putAll((data['history'] ?? {}).map((k, v) => MapEntry(
        k, (v as List).map((e) => ExchangeHistoryEntry.fromJson(e)).toList())));
    _didcommConversations!.putAll((data['communication'] ?? {})
        .map((k, v) => MapEntry(k, DidcommConversation.fromJson(v))));

    var keystores = data.keys.where((e) => e.startsWith('keystore_'));
    for (var k in keystores) {
      var values = data[k];
      if (!values!.containsKey('warning')) {
        var kType = k.replaceAll('keystore_', '');
        var newKeyStoreInstance = _keyStorage?[kType];
        if (newKeyStoreInstance != null) {
          try {
            if (values.containsKey('data')) {
              await newKeyStoreInstance.import(values['data']);
            } else {
              await newKeyStoreInstance.import(values);
            }
          } catch (e) {
            continue;
          }
        }
      }
    }
  }

  /// Initializes new hierarchical deterministic wallet or restores one from given mnemonic.
  ///
  /// Returns the used mnemonic.
  /// If the wallet should be used with did:eth and on another ethereum-network than the mainnet,
  /// pass the nme or its id as [network].
  @Deprecated('will happen implicit in future')
  Future<String?> initialize(
      {String? mnemonic, String network = 'mainnet'}) async {
    var mne = mnemonic;
    if (mnemonic == null) {
      mne = generateMnemonic();
    }
    var seed = mnemonicToSeed(mne!);

    await _configBox!.put('network', network);

    return mne;
  }

  /// Generates and returns DID for the issuer.
  Future<String> initializeIssuer(
      {KeyType keyType = KeyType.ed25519, String? storageBackend}) async {
    var s = _keyStorage?[storageBackend ?? 'software'];
    if (s == null) {
      throw WalletException('No keyStore configured');
    }
    var standardDid = getStandardIssuerDid(keyType);
    if (standardDid != null) return standardDid;
    var keyId = await s.generateKey(keyType);
    await _configBox!.put('issuer$keyType', keyId);
    await _configBox!.put(keyId, storageBackend ?? 'software');
    return keyId;
  }

  /// Returns the DID for issuing credentials.
  String? getStandardIssuerDid([KeyType keyType = KeyType.ed25519]) {
    return _configBox!.get('issuer$keyType');
  }

  /// Lists all credentials.
  Map<dynamic, Credential> getAllCredentials() {
    var credMap = _credentialBox!.toMap();
    return credMap;
  }

  /// Lists all connections.
  Map<dynamic, Connection> getAllConnections() {
    var connMap = _connection!.toMap();
    return connMap;
  }

  /// Returns the credential associated with [did].
  Credential? getCredential(String? did) {
    return _credentialBox!.get(did);
  }

  /// Returns the connection associated with [did].
  Connection? getConnection(String? did) {
    return _connection!.get(did);
  }

  /// Returns the Exchange History associated with a credential identified by [credentialDid].
  List<ExchangeHistoryEntry>? getExchangeHistoryEntriesForCredential(
      String credentialDid) {
    return _exchangeHistory!.get(credentialDid)?.cast<ExchangeHistoryEntry>();
  }

  /// Stores a credential permanently.
  ///
  /// What should be stored consists of three parts
  /// - a signed credential [w3cCred] containing hashes of all attribute-values
  /// - a json structure [plaintextCred] containing hashes, salts and values per credential attribute
  /// - the [credentialId] which is the did / keyId the credential was issued to
  Future<void> storeCredential(
      String? w3cCred, String? plaintextCred, String credentialId) async {
    var tmp = Credential('', w3cCred!, plaintextCred!);
    await _credentialBox!.put(credentialId, tmp);
  }

  /// Stores a Connection permanently.
  ///
  /// What should be stored consists of three parts
  /// - the did of the communication partner [otherDid]
  /// - the [name] of the connection / the username used in this connection.
  /// - [myId] which is the did / keyId this wallet used for the communication
  Future<void> storeConnection(
    String otherDid,
    String name,
    String myId,
  ) async {
    var tmp = Connection('', otherDid, name);
    await _connection!.put(myId, tmp);
  }

  /// Put a new Entry to Exchange history of a credential identified by [credentialDid].
  Future<void> storeExchangeHistoryEntry(String credentialDid,
      DateTime timestamp, String action, String otherParty,
      [List<String>? shownAttributes]) async {
    List<ExchangeHistoryEntry>? existingHistoryEntries =
        getExchangeHistoryEntriesForCredential(credentialDid);
    var tmp = ExchangeHistoryEntry(
        timestamp, action, otherParty, shownAttributes ?? []);
    if (existingHistoryEntries == null) {
      await _exchangeHistory!.put(credentialDid, [tmp]);
    } else {
      await _exchangeHistory!
          .put(credentialDid, [tmp] + existingHistoryEntries);
    }
  }

  Future<void> deleteCredential(String credentialDid) async {
    await _credentialBox!.delete(credentialDid);
  }

  Future<void> deleteConnection(String connectionDid) async {
    await _connection!.delete(connectionDid);
  }

  Future<void> deleteConfigEntry(String key) async {
    await _configBox!.delete(key);
  }

  Future<void> deleteExchangeHistory(String credentialDid) async {
    await _exchangeHistory!.delete(credentialDid);
  }

  Future<void> deleteKey(String keyId) async {
    for (var entry in _keyStorage!.entries) {
      if (await entry.value.hasKey(keyId)) {
        return entry.value.deleteKey(keyId);
      }
    }
  }

  FutureOr<Uint8List> sign(String keyId, Uint8List data) async {
    for (var entry in _keyStorage!.entries) {
      if (await entry.value.hasKey(keyId)) {
        return entry.value.signData(data, keyId);
      }
    }
    throw WalletException('No keyStore backend found to sign data');
  }

  FutureOr<bool> verify(
      String keyId, Uint8List data, Uint8List signature) async {
    for (var entry in _keyStorage!.entries) {
      if (await entry.value.hasKey(keyId)) {
        return entry.value.verify(signature, data, keyId);
      }
    }
    throw WalletException('No keyStore backend found to sign data');
  }

  FutureOr<Uint8List> calculateKeyAgreement(
      String keyId, Map<String, dynamic> otherPublicKey) async {
    for (var entry in _keyStorage!.entries) {
      if (await entry.value.hasKey(keyId)) {
        return entry.value.calculateKeyAgreement(keyId, otherPublicKey);
      }
    }

    throw WalletException('No keyStore backend found to sign data');
  }

  Future<bool> containsKey(String keyId) async {
    for (var entry in _keyStorage!.entries) {
      if (await entry.value.hasKey(keyId)) {
        return true;
      }
    }
    return false;
  }

  Future<Map<String, dynamic>> getKeyInformation(String keyId) async {
    for (var entry in _keyStorage!.entries) {
      if (await entry.value.hasKey(keyId)) {
        return entry.value.getKeyInformation(keyId);
      }
    }
    throw WalletException('Cannot find key with id $keyId');
  }

  /// Stores a credential issued to [holderDid].
  void toIssuingHistory(
      String holderDid, String plaintextCredential, String w3cCredential) {
    var tmp = Credential('', w3cCredential, plaintextCredential);
    _issuingHistory!.put(holderDid, tmp);
  }

  /// Returns a credential one issued to [holderDid].
  Credential? getIssuedCredential(String holderDid) {
    return _issuingHistory!.get(holderDid);
  }

  /// Returns all credentials one issued over time.
  Map<dynamic, Credential> getAllIssuedCredentials() {
    return _issuingHistory!.toMap();
  }

  /// Generates a new key in the selected [storageBackend] and returns its keyId.
  Future<String> generateNewKey(
      {KeyType keyType = KeyType.ed25519,
      String storageBackend = 'software',
      Map<String, dynamic>? additionalProperties}) async {
    var s = _keyStorage?[storageBackend];
    if (s == null) {
      throw WalletException('No keyStore configured');
    }
    var keyId = await s.generateKey(keyType, additionalProperties);
    return keyId;
  }

  /// Returns a new DID a credential could be issued for.
  @Deprecated('deprecated in favor of generateNewKey')
  Future<String> getNextCredentialDID(
      {KeyType keyType = KeyType.ed25519, String? storageBackend}) async {
    var s = _keyStorage?[storageBackend ?? 'software'];
    if (s == null) {
      throw WalletException('No keyStore configured');
    }
    var keyId = await s.generateKey(keyType);
    return keyId;
  }

  /// Returns a new connection-DID.
  @Deprecated('deprecated in favor of generateNewKey')
  Future<String> getNextConnectionDID(
      {KeyType keyType = KeyType.x25519, String? storageBackend}) async {
    var s = _keyStorage?[storageBackend ?? 'software'];
    if (s == null) {
      throw WalletException('No keyStore configured');
    }
    var keyId = await s.generateKey(keyType);
    return keyId;
  }

  /// Stores a configuration Entry.
  Future<void> storeConfigEntry(String key, String value) async {
    await _configBox!.put(key, value);
  }

  /// Returns the configuration Entry for [key].
  String? getConfigEntry(String key) {
    return _configBox!.get(key);
  }

  DidcommConversation? getConversationEntry(String threadId) {
    return _didcommConversations!.get(threadId);
  }

  Future<void> storeConversationEntry(
      DidcommPlaintextMessage message, String myDid) async {
    String thid = message.threadId ?? message.id;

    DidcommProtocol protocol;
    if (message.type.contains('issue-credential')) {
      protocol = DidcommProtocol.issueCredential;
    } else if (message.type.contains('present-proof')) {
      protocol = DidcommProtocol.presentProof;
    } else if (message.type.contains('discover-features')) {
      protocol = DidcommProtocol.discoverFeature;
    } else if (message.type.contains('invitation')) {
      protocol = DidcommProtocol.invitation;
    } else if (message.type.contains('request-presentation')) {
      protocol = DidcommProtocol.requestPresentation;
    } else {
      throw Exception('unsupported Protocol');
    }

    await _didcommConversations!.put(
        thid, DidcommConversation(message.toString(), protocol.value, myDid));
  }

  Future<void> deleteConversationEntry(DidcommPlaintextMessage message) async {
    String thid = message.threadId ?? message.id;
    await _didcommConversations!.delete(thid);
  }
}

enum KeyType { secp256k1, ed25519, x25519, p256, p384, p521 }
