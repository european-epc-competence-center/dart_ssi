import 'dart:convert';

import 'package:crypto_keys/crypto_keys.dart';
import 'package:dart_ssi/did.dart';
import 'package:dart_ssi/src/util/crypto_provider.dart';
import 'package:dart_ssi/src/wallet/wallet_store.dart';
import 'package:json_schema/json_schema.dart';

import '../util/utils.dart';
import 'didcomm_jwm.dart';
import 'didcomm_jws.dart';
import 'types.dart';

var encryptedMessageSchema = JsonSchema.create({
  'type': 'object',
  'properties': {
    'ciphertext': {'type': 'string'},
    'tag': {'type': 'string'},
    'protected': {'type': 'string'},
    'unprotected': {'type': 'string'},
    'aad': {'type': 'string'},
    'iv': {'type': 'string'},
    'recipients': {
      'type': 'array',
      'contains': {
        'type': 'object',
        'properties': {
          'encrypted_key': {'type': 'string'},
          'header': {'type': 'object'}
        },
        'required': ['encrypted_key']
      }
    }
  },
  'required': ['ciphertext', 'recipients', 'iv', 'tag']
});

bool isEncryptedMessage(dynamic message) {
  var asMap = credentialToMap(message);
  return encryptedMessageSchema.validate(asMap).isValid;
}

///A didcomm encrypted message
class DidcommEncryptedMessage extends DidcommMessage {
  late String protectedHeader;
  late String tag;
  late String iv;
  late String ciphertext;
  late List<dynamic> recipients;
  String? protectedHeaderApu;
  String? protectedHeaderApv;
  String? protectedHeaderAlg;
  String? protectedHeaderSkid;
  Map<String, dynamic>? protectedHeaderEpk;
  String? protectedHeaderEnc;

  DidcommEncryptedMessage(
      {required this.protectedHeader,
      required this.tag,
      required this.iv,
      required this.ciphertext,
      required this.recipients});

  DidcommEncryptedMessage.fromJson(dynamic message) {
    Map<String, dynamic> decoded = credentialToMap(message);
    ciphertext = decoded['ciphertext']!;
    iv = decoded['iv']!;
    tag = decoded['tag']!;
    recipients = decoded['recipients']! as List;
    protectedHeader = decoded['protected']!;
    _decodeProtected();
  }

  Future<String> _searchPrivateKey(WalletStore wallet) async {
    var didsTried = [];
    for (var entry in recipients) {
      String kid = entry['header']['kid']!;
      var did = kid.split('#').first;
      didsTried.add(did);
      if (await wallet.containsKey(did)) return did;
    }
    throw Exception('No Key found in the wallet for following '
        'dids: ${didsTried.isNotEmpty ? didsTried.join(', ') : 'none due to '
            'recipient in message'}');
  }

  Future<DidcommMessage> decrypt(
      {WalletStore? wallet,
      Map<String, dynamic>? privateKeyJwk,
      Map<String, dynamic>? senderPublicKeyJwk,
      Future<DidDocument> Function(String) didResolver =
          resolveDidDocument}) async {
    _decodeProtected();

    KeyAgreementGenerator? keyAgreement;
    String? keyId;
    if (wallet != null) {
      keyId = await _searchPrivateKey(wallet);
      keyAgreement = WalletKeyAgreementGenerator(wallet, keyId);
    }
    if (privateKeyJwk != null) {
      keyAgreement = JwkKeyAgreementGenerator(privateKeyJwk);
    }
    if (keyAgreement == null) {
      throw Exception('No private key given');
    }

    //2) compute shared Secret
    List<int> sharedSecret;
    bool authcrypt = false;
    if (protectedHeaderAlg!.startsWith('ECDH-ES')) {
      sharedSecret = await ecdhES(keyAgreement, protectedHeaderEpk!,
          protectedHeaderAlg!, protectedHeaderEnc!,
          apv: protectedHeaderApv);
    } else if (protectedHeaderAlg!.startsWith('ECDH-1PU')) {
      authcrypt = true;
      if (senderPublicKeyJwk == null) {
        if (protectedHeaderSkid == null) {
          throw Exception('sender id needed when using AuthCrypt');
        }

        var senderDDO =
            (await didResolver(protectedHeaderSkid!.split('#').first))
                .resolveKeyIds()
                .convertAllKeysToJwk();
        for (var key in senderDDO.keyAgreement!) {
          if (key is VerificationMethod) {
            if (key.publicKeyJwk!['kid'] == protectedHeaderSkid ||
                key.id == protectedHeaderSkid) {
              senderPublicKeyJwk = key.publicKeyJwk!;
              break;
            }
          }
        }
        if (senderPublicKeyJwk == null) {
          throw Exception('Public key of sender needed');
        }
      }
      //var senderDid = base64Decode(addPaddingToBase64(apu));

      sharedSecret = await ecdh1PU(
          keyAgreement,
          keyAgreement,
          protectedHeaderEpk!,
          senderPublicKeyJwk,
          base64Decode(addPaddingToBase64(tag)),
          protectedHeaderAlg!,
          protectedHeaderApu!,
          protectedHeaderApv!);
    } else {
      throw UnimplementedError("Algorithm `${protectedHeaderAlg!}`"
          " is not supported");
    }
    //3) Decrypt cek

    //a)search encrypted cek
    String encryptedCek = '';
    for (var entry in recipients) {
      var kid = entry['header']['kid']!;
      if (kid == privateKeyJwk?['kid'] ||
          kid == '$keyId#${keyId?.replaceAll('did:key:', '')}') {
        encryptedCek = entry['encrypted_key'];
        break;
      }
    }

    Map<String, dynamic> sharedSecretJwk = {
      'kty': 'oct',
      'k': base64UrlEncode(sharedSecret)
    };

    var keyWrapKey = KeyPair.fromJwk(sharedSecretJwk);
    Encrypter kw = keyWrapKey.publicKey!
        .createEncrypter(algorithms.encryption.aes.keyWrap);
    var decryptedCek = kw.decrypt(
        EncryptionResult(base64Decode(addPaddingToBase64(encryptedCek))));
    var cek = SymmetricKey(keyValue: decryptedCek);
    //4) Decrypt Body
    Encrypter e;
    if (protectedHeaderEnc! == 'A256CBC-HS512') {
      e = cek.createEncrypter(algorithms.encryption.aes.cbcWithHmac.sha512);
    } else if (protectedHeaderEnc == 'A256GCM') {
      e = cek.createEncrypter(algorithms.encryption.aes.gcm);
    } else {
      throw UnimplementedError();
    }

    var toDecrypt = EncryptionResult(
        base64Decode(addPaddingToBase64(ciphertext)),
        authenticationTag: base64Decode(addPaddingToBase64(tag)),
        additionalAuthenticatedData: ascii.encode(protectedHeader),
        initializationVector: base64Decode(addPaddingToBase64(iv)));

    var plain = e.decrypt(toDecrypt);
    //5)return body
    DidcommMessage m;
    Map message = jsonDecode(utf8.decode(plain));

    if (message.containsKey('id')) {
      m = DidcommPlaintextMessage.fromJson(message);
      m as DidcommPlaintextMessage;
      if (authcrypt) {
        if (m.from != null) {
          if (m.from != protectedHeaderSkid!.split('#').first) {
            throw Exception(
                'From value of plaintext Message do not match skid of encrypted message. (${m.from} != ${protectedHeaderSkid!.split('#').first}');
          }
        } else {
          throw Exception(
              'from header in plaintext message is required if authcrypt is used');
        }
      }
    } else if (message.containsKey('ciphertext')) {
      m = DidcommSignedMessage.fromJson(message);
    } else if (message.containsKey('signatures')) {
      m = DidcommEncryptedMessage.fromJson(message);
    } else {
      throw Exception('Unknown Message type');
    }

    return m;
  }

  @override
  Map<String, dynamic> toJson() {
    return {
      'ciphertext': ciphertext,
      'protected': protectedHeader,
      'tag': tag,
      'iv': iv,
      'recipients': recipients
    };
  }

  @override
  String toString() {
    return jsonEncode(toJson());
  }

  _decodeProtected() {
    Map<String, dynamic> protectedJson = jsonDecode(
        utf8.decode(base64Decode(addPaddingToBase64(protectedHeader))));
    if (protectedJson.containsKey('alg')) {
      protectedHeaderAlg = protectedJson['alg'];
    }
    if (protectedJson.containsKey('epk')) {
      protectedHeaderEpk = protectedJson['epk'];
    }
    if (protectedJson.containsKey('apv')) {
      protectedHeaderApv = protectedJson['apv'];
    }
    if (protectedJson.containsKey('skid')) {
      protectedHeaderSkid = protectedJson['skid'];
    }
    if (protectedJson.containsKey('enc')) {
      protectedHeaderEnc = protectedJson['enc'];
    }
    if (protectedJson.containsKey('apu')) {
      protectedHeaderApu = protectedJson['apu'];
      protectedHeaderSkid ??=
          utf8.decode(base64Decode(addPaddingToBase64(protectedHeaderApu!)));
    }
  }
}
