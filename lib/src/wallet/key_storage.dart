import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:base_codecs/base_codecs.dart';
import 'package:bip32/bip32.dart';
import 'package:bip39/bip39.dart';
import 'package:crypto/crypto.dart';
import 'package:crypto_keys/crypto_keys.dart';
import 'package:ed25519_edwards/ed25519_edwards.dart' as ed;
import 'package:ed25519_hd_key/ed25519_hd_key.dart';
import 'package:elliptic/ecdh.dart';
import 'package:elliptic/elliptic.dart' as elliptic;
import 'package:hive/hive.dart';
import 'package:web3dart/crypto.dart';
import 'package:web3dart/web3dart.dart';
import 'package:x25519/x25519.dart' as x;

import '../util/private_util.dart';
import '../util/utils.dart';
import 'wallet_store.dart';

abstract class KeyStoreBackend {
  /// Initialize the key store so that it is ready to use
  FutureOr<void> initializeStorage();

  /// generates a new key and returns it's key-id
  FutureOr<String> generateKey(KeyType keyType);

  /// returns whether the backend controls the key or not
  FutureOr<bool> hasKey(String keyId);

  /// signs the given [data] with the key identified by [keyId]
  FutureOr<Uint8List> signData(Uint8List data, String keyId);

  /// verifies the [signature] over [signedData] using the public key for the key identified by [keyId]
  FutureOr<bool> verify(
      Uint8List signature, Uint8List signedData, String keyId);

  /// Calculates a shared secret between the key identified by [keyId] and the [otherPublicKey] given as JWK.
  FutureOr<Uint8List> calculateKeyAgreement(
      String keyId, Map<String, dynamic> otherPublicKey);

  /// Returns metadata about the key identified by [keyId].
  ///
  /// Should be formatted like jwk, including the public key (x and y parameter, depending on keyType)
  FutureOr<Map<String, dynamic>> getKeyInformation(String keyId);

  /// Deletes the key identified by [keyId]
  void deleteKey(String keyId);

  /// Import exported data to restore this keyStore.
  ///
  /// This might not be possible with all keyStore types, especially hardware-backed ones.
  /// In this case the method will throw an Exception.
  FutureOr<void> import(dynamic data);

  /// Exports all data stored in the keystore for backup purpose
  ///
  /// This might not be possible with all keyStore types, especially hardware-backed ones.
  /// In this case the method will throw an Exception.
  FutureOr<dynamic> export();
}

class SoftwareKeyStoreBackend extends KeyStoreBackend {
  // Hive is used as Storage
  Box? _keyBox;
  final String? _password, _nameExpansion;

  ///The path used to derive credential keys with P-256k
  final String _standardPath256k = 'm/456/0/';

  ///The path used to derive credential keys for Ed25519
  final String _standardPathEd25519 = 'm/457\'/0\'/';

  ///The path used to derive connection keys for X25519
  final String _standardPathX25519 = 'm/457\'/1\'/';

  SoftwareKeyStoreBackend([this._password, this._nameExpansion]);

  @override
  Future<void> initializeStorage() async {
    List<int>? aesKey;
    try {
      if (_password != null) {
        var generator = PBKDF2(hash: sha256);
        aesKey = generator.generateKey(_password!, "salt", 1000, 32);
      }
      _keyBox = await Hive.openBox(
          'keybox${_nameExpansion != null ? '_$_nameExpansion' : ''}',
          crashRecovery: false,
          encryptionCipher: aesKey != null ? HiveAesCipher(aesKey) : null);
      var seed = _keyBox!.get('seed');
      if (seed == null) {
        var mne = generateMnemonic();
        seed = mnemonicToSeed(mne);
        _keyBox!.put('seed', seed);
        await _keyBox!.put('lastIndex256k', 0);
        await _keyBox!.put('lastIndexEd25519', 0);
        await _keyBox!.put('lastIndexX25519', 0);
      }
      var lci = _keyBox?.get('lastCredentialIndex');
      if (lci != null) {
        _keyBox!.put('lastIndex256k', lci);
      } else {
        _keyBox!.put('lastIndex256k', 0);
      }
      var lcie = _keyBox?.get('lastCredentialIndexEd');
      if (lcie != null) {
        _keyBox!.put('lastIndexEd25519', lcie);
      } else {
        _keyBox!.put('lastIndexEd25519', 0);
      }
      var lcix = _keyBox?.get('lastCredentialIndexX');
      if (lcix != null) {
        _keyBox!.put('lastIndexX25519', lcix);
      } else {
        _keyBox!.put('lastIndexX25519', 0);
      }

      _keyBox!.put('lastCredentialIndex', _keyBox!.get('lastIndex256k'));
      _keyBox!.put('lastCredentialIndexEd', _keyBox!.get('lastIndexEd25519'));
      _keyBox!.put('lastCredentialIndexX', _keyBox!.get('lastIndexX25519'));
    } catch (e) {
      if (e is HiveError && e.message.contains('corrupted')) {
        throw WalletException('Cant open boxes. Maybe wrong password?');
      } else {
        rethrow;
      }
    }
  }

  @override
  FutureOr<String> generateKey(KeyType keyType) {
    if (keyType == KeyType.secp256k1) {
      return _getNextDidP256k();
    } else if (keyType == KeyType.ed25519) {
      return _getNextDidEd25519();
    } else if (keyType == KeyType.p384 ||
        keyType == KeyType.p256 ||
        keyType == KeyType.p521) {
      return _getNextDidP(keyType);
    } else if (keyType == KeyType.x25519) {
      return _getNextDidX25519();
    } else {
      throw Exception('Unsupported Credential KeyType `$keyType`');
    }
  }

  Future<String> _getNextDidX25519() async {
    //generate new keypair
    var lastIndex = _keyBox!.get('lastIndexX25519');
    var path = '$_standardPathX25519$lastIndex\'';
    var key =
        await ED25519_HD_KEY.derivePath(path, _keyBox!.get('seed').toList());
    var did = await _edKeyToXKeyDid(key);

    //increment derivation index
    lastIndex++;
    await _keyBox!.put('lastIndexX25519', lastIndex);
    await _keyBox!.put(did, path);
    return did;
  }

  Future<String> _edKeyToXKeyDid(KeyData data) async {
    var private = ed.newKeyFromSeed(Uint8List.fromList(data.key));

    return 'did:key:z${base58Bitcoin.encode(Uint8List.fromList([
          236,
          1
        ] + _edPrivateToXPublic(private)))}';
  }

  List<int> _edPrivateToXPublic(ed.PrivateKey private) {
    var xPublic = List.filled(32, 0);
    x.ScalarBaseMult(xPublic, _edPrivateToXPrivate(private));
    return xPublic;
  }

  List<int> _edPrivateToXPrivate(ed.PrivateKey private) {
    var hash = sha512.convert(private.bytes.sublist(0, 32));
    var d = hash.bytes;
    d[0] &= 248;
    d[31] &= 127;
    d[31] |= 64;
    return d;
  }

  Future<String> _getNextDidP(KeyType keyType) async {
    elliptic.Curve c;
    List<int> prefix;
    if (keyType == KeyType.p521) {
      c = elliptic.getP521();
      prefix = [130, 36];
    } else if (keyType == KeyType.p384) {
      c = elliptic.getP384();
      prefix = [129, 36];
    } else {
      c = elliptic.getP256();
      prefix = [128, 36];
    }

    var privateKey = c.generatePrivateKey();
    var did =
        'did:key:z${base58BitcoinEncode(Uint8List.fromList(prefix + hexToBytes(privateKey.publicKey.toCompressedHex())))}';

    await _keyBox!.put(did, privateKey.toHex());
    return did;
  }

  Future<String> _getNextDidP256k() async {
    //generate new keypair
    var master = BIP32.fromSeed(_keyBox!.get('seed'));
    var lastIndex = _keyBox!.get('lastIndex256k');
    var path = '$_standardPath256k${lastIndex.toString()}';
    var key = master.derivePath(path);

    //increment derivation index
    lastIndex++;
    await _keyBox!.put('lastIndex256k', lastIndex);

    var did = _bip32KeyToDid(key);
    await _keyBox!.put(did, path);
    return did;
  }

  String _bip32KeyToDid(BIP32 key) {
    var private = EthPrivateKey.fromHex(bytesToHex(key.privateKey!));
    return 'did:key:z${base58BitcoinEncode(Uint8List.fromList([
          231,
          1
        ] + private.publicKey.getEncoded().toList()))}';
  }

  Future<String> _getNextDidEd25519() async {
    //generate new keypair
    var lastIndex = _keyBox!.get('lastIndexEd25519');
    var path = '$_standardPathEd25519$lastIndex\'';
    var key =
        await ED25519_HD_KEY.derivePath(path, _keyBox!.get('seed').toList());
    var did = await _edKeyToDid(key);

    //increment derivation index
    lastIndex++;
    await _keyBox!.put('lastIndexEd25519', lastIndex);

    await _keyBox!.put(did, path);
    return did;
  }

  Future<String> _edKeyToDid(KeyData d) async {
    var private = ed.newKeyFromSeed(Uint8List.fromList(d.key));
    return 'did:key:z${base58Bitcoin.encode(Uint8List.fromList([
          237,
          1
        ] + ed.public(private).bytes))}';
  }

  @override
  FutureOr<Uint8List> signData(Uint8List data, String keyId) async {
    var keyData = _keyBox!.get(keyId);
    if (keyData == null) {
      throw Exception('Cannot find key');
    }
    if (keyId.startsWith('did:key:z6Mk')) {
      // ed25519 key
      var privateKey = await ED25519_HD_KEY.derivePath(
          keyData, _keyBox!.get('seed').toList());
      var signature = ed.sign(
          ed.PrivateKey(
              ed.newKeyFromSeed(Uint8List.fromList(privateKey.key)).bytes),
          data);
      return signature;
    } else {
      Identifier c, a;
      BigInt privateKey;

      if (keyId.startsWith('did:key:zQ3s')) {
        c = curves.p256k;
        a = algorithms.signing.ecdsa.sha256;
        var master = BIP32.fromSeed(_keyBox!.get('seed'));
        var key = master.derivePath(keyData);
        privateKey = EthPrivateKey(key.privateKey!).privateKeyInt;
      } else if (keyId.startsWith('did:key:zDn')) {
        c = curves.p256;
        a = algorithms.signing.ecdsa.sha256;
        var p = hexToBytes(keyData);
        privateKey = bytesToUnsignedInt(p);
      } else if (keyId.startsWith('did:key:z82')) {
        c = curves.p384;
        a = algorithms.signing.ecdsa.sha384;
        privateKey = hexToInt(keyData);
      } else if (keyId.startsWith('did:key:z2J9')) {
        c = curves.p521;
        a = algorithms.signing.ecdsa.sha512;
        privateKey = hexToInt(keyData);
      } else {
        throw Exception('Unsupported curve');
      }

      var k = EcPrivateKey(eccPrivateKey: privateKey, curve: c);

      var signer = k.createSigner(a);
      var sig = signer.sign(data);
      return sig.data;
    }
  }

  @override
  void deleteKey(String keyId) {
    _keyBox!.delete(keyId);
  }

  @override
  export() {
    return _keyBox?.toMap().map((k, v) => MapEntry(k as String, v));
  }

  @override
  Future<void> import(data) async {
    if (data is Map) {
      await _keyBox!.putAll(data);
    } else {
      throw Exception('cant store this data');
    }
  }

  @override
  FutureOr<Uint8List> calculateKeyAgreement(
      String keyId, Map<String, dynamic> otherPublicKey) async {
    List<int> z;
    // keys given as jwks
    var crv = otherPublicKey['crv'];
    var keyData = _keyBox!.get(keyId);

    if (keyData == null) {
      throw Exception('No key found for id $keyId');
    }

    if (keyId.startsWith('did:key:z6LS')) {
      if (crv != 'X25519') {
        throw Exception(
            'crv of public key does not match private key. ($crv != X25519)');
      }
      var key = await ED25519_HD_KEY.derivePath(
          keyData, _keyBox!.get('seed').toList());
      var private = ed.newKeyFromSeed(Uint8List.fromList(key.key));
      var castedPrivate =
          Uint8List.fromList(_edPrivateToXPrivate(private)).sublist(0, 32);
      var castedPublic = base64Decode(addPaddingToBase64(otherPublicKey['x']));
      z = x.X25519(castedPrivate, castedPublic);
    } else {
      elliptic.Curve? c;
      BigInt privateKey;

      if (keyId.startsWith('did:key:zQ3s')) {
        var master = BIP32.fromSeed(_keyBox!.get('seed'));
        var key = master.derivePath(keyData);
        privateKey = EthPrivateKey(key.privateKey!).privateKeyInt;
        c = elliptic.getSecp256k1();
      } else if (keyId.startsWith('did:key:zDn')) {
        if (crv != 'P-256') {
          throw Exception(
              'crv of public key does not match private key. ($crv != P-256)');
        }
        var p = hexToBytes(keyData);
        privateKey = bytesToUnsignedInt(p);
        c = elliptic.getP256();
      } else if (keyId.startsWith('did:key:z82')) {
        if (crv != 'P-384') {
          throw Exception(
              'crv of public key does not match private key. ($crv != P-384)');
        }
        var p = hexToBytes(keyData);
        privateKey = bytesToUnsignedInt(p);
        c = elliptic.getP384();
      } else if (keyId.startsWith('did:key:z2J9')) {
        if (crv != 'P-521') {
          throw Exception(
              'crv of public key does not match private key. ($crv != P-521)');
        }
        privateKey = hexToInt(keyData);
        c = elliptic.getP521();
      } else {
        throw Exception('Unsupported curve');
      }

      var castedPrivate = elliptic.PrivateKey(c, privateKey);
      var castedPublic = elliptic.PublicKey.fromPoint(
          c,
          elliptic.AffinePoint.fromXY(
              bytesToUnsignedInt(
                  base64Decode(addPaddingToBase64(otherPublicKey['x']))),
              bytesToUnsignedInt(
                  base64Decode(addPaddingToBase64(otherPublicKey['y'])))));
      z = computeSecret(castedPrivate, castedPublic);
    }
    return Uint8List.fromList(z);
  }

  @override
  FutureOr<bool> hasKey(String keyId) {
    return _keyBox?.get(keyId) != null;
  }

  @override
  FutureOr<Map<String, dynamic>> getKeyInformation(String keyId) {
    var multibase = keyId.replaceAll('did:key:', '');
    var jwk = multibaseKeyToJwk(multibase);
    jwk['kid'] = '$keyId#$multibase';
    return jwk;
  }

  @override
  FutureOr<bool> verify(
      Uint8List signature, Uint8List signedData, String keyId) async {
    var pubKey = await getKeyInformation(keyId);
    if (keyId.startsWith('did:key:z6Mk')) {
      var decodedKey = base64Decode(addPaddingToBase64(pubKey['x']));
      return ed.verify(
          ed.PublicKey(decodedKey), Uint8List.fromList(signedData), signature);
    } else {
      Identifier alg, curve;
      if (keyId.startsWith('did:key:zQ3s')) {
        alg = algorithms.signing.ecdsa.sha256;
        curve = curves.p256k;
      } else if (keyId.startsWith('did:key:zDn')) {
        alg = algorithms.signing.ecdsa.sha256;
        curve = curves.p256;
      } else if (keyId.startsWith('did:key:z82')) {
        alg = algorithms.signing.ecdsa.sha384;
        curve = curves.p384;
      } else if (keyId.startsWith('did:key:z2J9')) {
        alg = algorithms.signing.ecdsa.sha512;
        curve = curves.p521;
      } else {
        throw Exception('');
      }
      var castedKey = EcPublicKey(
          xCoordinate:
              bytesToUnsignedInt(base64Decode(addPaddingToBase64(pubKey['x']))),
          yCoordinate:
              bytesToUnsignedInt(base64Decode(addPaddingToBase64(pubKey['y']))),
          curve: curve);
      var verifier = castedKey.createVerifier(alg);

      return verifier.verify(
          Uint8List.fromList(signedData), Signature(signature));
    }
  }
}
