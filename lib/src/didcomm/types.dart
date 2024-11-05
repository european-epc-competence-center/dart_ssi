import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';
import 'package:crypto_keys/crypto_keys.dart';
import 'package:dart_ssi/didcomm.dart';
import 'package:dart_ssi/src/util/crypto_provider.dart';
import 'package:dart_ssi/src/util/types.dart';
import 'package:dart_ssi/src/wallet/wallet_store.dart';
import 'package:elliptic/elliptic.dart' as elliptic;
import 'package:web3dart/crypto.dart';
import 'package:x25519/x25519.dart' as x25519;

import '../util/utils.dart';

enum DidcommProfiles {
  aip1,
  rfc19,
  rfc587,
  v2;

  static const Map<DidcommProfiles, String> stringValues = {
    DidcommProfiles.aip1: 'didcomm/aip1',
    DidcommProfiles.rfc19: 'didcomm/aip2;env=rfc19',
    DidcommProfiles.rfc587: 'didcomm/aip2;env=rfc587',
    DidcommProfiles.v2: 'didcomm/v2'
  };
  String get value => stringValues[this]!;
}

enum DidcommMessageTyp {
  plain,
  signed,
  encrypted;

  static const Map<DidcommMessageTyp, String> stringValues = {
    DidcommMessageTyp.plain: 'application/didcomm-plain+json',
    DidcommMessageTyp.signed: 'application/didcomm-signed+json',
    DidcommMessageTyp.encrypted: 'application/didcomm-encrypted+json'
  };
  String get value => stringValues[this]!;
}

class DidcommMessage implements JsonObject {
  Future<DidcommEncryptedMessage> encrypt({
    KeyWrapAlgorithm keyWrapAlgorithm = KeyWrapAlgorithm.ecdh1PU,
    EncryptionAlgorithm encryptionAlgorithm = EncryptionAlgorithm.a256cbc,
    Map<String, dynamic>? senderPrivateKeyJwk,
    WalletStore? wallet,
    String? keyId,
    required List<Map<String, dynamic>> recipientPublicKeyJwk,
  }) async {
    var plaintext = this;
    if (keyWrapAlgorithm == KeyWrapAlgorithm.ecdh1PU &&
        plaintext is DidcommPlaintextMessage &&
        plaintext.from == null) {
      throw Exception(
          'For authcrypted messages the from-header of the plaintext message must not be null');
    }
    Map<String, dynamic> jweHeader = {};
    jweHeader['enc'] = encryptionAlgorithm.value;
    jweHeader['alg'] = keyWrapAlgorithm.value;

    String curve, keyType;
    String? kid;
    if (wallet != null && keyId != null) {
      var keyInfo = await wallet.getKeyInformation(keyId);
      if (keyWrapAlgorithm == KeyWrapAlgorithm.ecdh1PU) {
        jweHeader['apu'] = removePaddingFromBase64(
            base64UrlEncode(utf8.encode(keyInfo['kid'])));
      }
      kid = keyInfo['kid'];
      jweHeader['skid'] = keyInfo['kid'];
      curve = keyInfo['crv']!;
      keyType = keyInfo['kty']!;
    } else if (senderPrivateKeyJwk != null) {
      kid = senderPrivateKeyJwk['kid'];
      jweHeader['skid'] = senderPrivateKeyJwk['kid'];
      curve = senderPrivateKeyJwk['crv']!;
      keyType = senderPrivateKeyJwk['kty']!;
      if (keyWrapAlgorithm == KeyWrapAlgorithm.ecdh1PU) {
        jweHeader['apu'] = removePaddingFromBase64(
            base64UrlEncode(utf8.encode(senderPrivateKeyJwk['kid'])));
      }
    } else {
      throw Exception('No private Key');
    }

    List<String> receiverKeyIds = [];
    for (Map<String, dynamic> key in recipientPublicKeyJwk) {
      if (key['crv'] == curve) {
        receiverKeyIds.add(key['kid']);
      }
    }
    receiverKeyIds.sort();
    String keyIdString = '';
    for (var keyId in receiverKeyIds) {
      keyIdString += '$keyId.';
    }
    if (keyIdString.isEmpty) {
      throw Exception('Cant find keys with matching crv parameter');
    }
    keyIdString = keyIdString.substring(0, keyIdString.length - 1);
    var apv = removePaddingFromBase64(
        base64UrlEncode(sha256.convert(utf8.encode(keyIdString)).bytes));
    jweHeader['apv'] = apv;

    //1) Resolve dids to get public keys

    //important: KeyAgreement section in diddoc
    //apu = key-id of sender (first entry in keyAgreementArray) -> entry istsef (if did) or id of key-Object

    //apv: get all key-ids in KeyAgreement _> search which match curve of sender key -> sort alphanumerical -> concat with . -> sha256 -> base64URL

    //2) look for Key-Type and generate Ephermal Key

    elliptic.Curve? c;
    Object epkPrivate;
    List<int> epkPublic = [];
    if (curve.startsWith('P') || curve.startsWith('secp256k1')) {
      if (curve == 'P-256') {
        c = elliptic.getP256();
      } else if (curve == 'P-384') {
        c = elliptic.getP384();
      } else if (curve == 'P-521') {
        c = elliptic.getP521();
      } else if (curve == 'secp256k1') {
        c = elliptic.getSecp256k1();
      } else {
        throw UnimplementedError();
      }

      epkPrivate = c.generatePrivateKey();
    } else if (curve.startsWith('X')) {
      var eKeyPair = x25519.generateKeyPair();
      epkPrivate = eKeyPair.privateKey;
      epkPublic = eKeyPair.publicKey;
    } else {
      throw UnimplementedError();
    }

    Map<String, dynamic> epkJwk = {'kty': keyType, 'crv': curve};
    if (epkPrivate is elliptic.PrivateKey) {
      epkJwk['x'] = removePaddingFromBase64(
          base64UrlEncode(intToBytes(epkPrivate.publicKey.X)));
      epkJwk['y'] = removePaddingFromBase64(
          base64UrlEncode(intToBytes(epkPrivate.publicKey.Y)));
    } else if (epkPrivate is List<int>) {
      epkJwk['x'] = removePaddingFromBase64(base64UrlEncode(epkPublic));
    } else {
      throw Exception('Unknown Key type');
    }
    jweHeader['epk'] = epkJwk;

    Map<String, dynamic> epkPrivateJwk = Map.from(epkJwk);
    if (epkPrivate is elliptic.PrivateKey) {
      epkPrivateJwk['d'] =
          removePaddingFromBase64(base64UrlEncode(epkPrivate.bytes));
    } else if (epkPrivate is List<int>) {
      epkPrivateJwk['d'] = removePaddingFromBase64(base64UrlEncode(epkPrivate));
    } else {
      throw Exception('Unknown Key type');
    }

    //3) generate symmetric CEK
    SymmetricKey cek;
    if (encryptionAlgorithm == EncryptionAlgorithm.a256cbc) {
      cek = SymmetricKey.generate(512);
    } else {
      cek = SymmetricKey.generate(256);
    }
    Encrypter e;
    if (encryptionAlgorithm == EncryptionAlgorithm.a256cbc) {
      e = cek.createEncrypter(algorithms.encryption.aes.cbcWithHmac.sha512);
    } else if (encryptionAlgorithm == EncryptionAlgorithm.a256gcm) {
      e = cek.createEncrypter(algorithms.encryption.aes.gcm);
    } else {
      throw UnimplementedError();
    }

    //4) Generate IV

    //5) build aad ( ASCII(BASE64URL(UTF8(JWE Protected Header))) )
    var aad = ascii.encode(removePaddingFromBase64(
        base64UrlEncode(utf8.encode(jsonEncode(jweHeader)))));
    //6) encrypt and get tag
    var encrypted = e.encrypt(
        Uint8List.fromList(utf8.encode(plaintext.toString())),
        additionalAuthenticatedData: aad);

    // 7) Encrypt cek for all recipients
    KeyAgreementGenerator? senderKeyAgreement;
    if (wallet != null && keyId != null) {
      senderKeyAgreement = WalletKeyAgreementGenerator(wallet, keyId);
    }
    if (senderPrivateKeyJwk != null) {
      senderKeyAgreement = JwkKeyAgreementGenerator(senderPrivateKeyJwk);
    }
    List<Map<String, dynamic>> recipients = [];
    for (var key in recipientPublicKeyJwk) {
      if (key['crv'] == curve) {
        Map<String, dynamic> r = {};
        r['header'] = {'kid': key['kid']};
        var encryptedCek = await _encryptSymmetricKey(
            cek, keyWrapAlgorithm.value, curve, key, epkPrivateJwk, apv,
            c: c,
            senderKeyAgreement: senderKeyAgreement,
            kid: kid,
            tag: encrypted.authenticationTag);
        r['encrypted_key'] =
            removePaddingFromBase64(base64UrlEncode(encryptedCek.data));
        recipients.add(r);
      }
    }

    //9) put everything together
    return DidcommEncryptedMessage(
        protectedHeader: ascii.decode(aad),
        tag: removePaddingFromBase64(
            base64UrlEncode(encrypted.authenticationTag!)),
        iv: removePaddingFromBase64(
            base64UrlEncode(encrypted.initializationVector!)),
        ciphertext: removePaddingFromBase64(base64UrlEncode(encrypted.data)),
        recipients: recipients);
  }

  Future<EncryptionResult> _encryptSymmetricKey(
      SymmetricKey symmetricKey,
      String keyWrapAlgorithm,
      String curve,
      Map<String, dynamic> publicKeyJwk,
      dynamic epkPrivate,
      String apv,
      {KeyAgreementGenerator? senderKeyAgreement,
      String? kid,
      List<int>? tag,
      elliptic.Curve? c}) async {
    //7) do ecdh to get shared Secret
    List<int> sharedSecret;
    var keyAgreement = JwkKeyAgreementGenerator(epkPrivate);
    if (keyWrapAlgorithm.startsWith('ECDH-ES')) {
      sharedSecret = await ecdhES(
          keyAgreement, publicKeyJwk, 'ECDH-ES', 'ECDH-ES+A256KW',
          apv: apv);
    } else if (keyWrapAlgorithm.startsWith('ECDH-1PU')) {
      if (kid == null) throw Exception('no Kid');
      if (senderKeyAgreement == null) {
        throw Exception('No sender agreement');
      }
      sharedSecret = await ecdh1PU(
          keyAgreement,
          senderKeyAgreement,
          publicKeyJwk,
          publicKeyJwk,
          tag!,
          keyWrapAlgorithm,
          removePaddingFromBase64(base64Encode(utf8.encode(kid))),
          apv);
    } else {
      throw UnimplementedError();
    }

    Map<String, dynamic> sharedSecretJwk = {
      'kty': 'oct',
      'k': base64UrlEncode(sharedSecret)
    };

    //8) Encrypt CEK with Key Wrap algo
    var keyWrapKey = KeyPair.fromJwk(sharedSecretJwk);
    Encrypter kw = keyWrapKey.publicKey!
        .createEncrypter(algorithms.encryption.aes.keyWrap);
    return kw.encrypt(symmetricKey.keyValue);
  }

  @override
  Map<String, dynamic> toJson() {
    return <String, dynamic>{};
  }
}

/// Combination of Key-Wrap and Key agreement algorithm
enum KeyWrapAlgorithm {
  ecdhES,
  ecdh1PU;

  static const Map<KeyWrapAlgorithm, String> stringValues = {
    KeyWrapAlgorithm.ecdhES: 'ECDH-ES+A256KW',
    KeyWrapAlgorithm.ecdh1PU: 'ECDH-1PU+A256KW',
  };
  String get value => stringValues[this]!;
}

enum EncryptionAlgorithm {
  a256cbc,
  a256gcm;

  static const Map<EncryptionAlgorithm, String> stringValues = {
    EncryptionAlgorithm.a256cbc: 'A256CBC-HS512',
    EncryptionAlgorithm.a256gcm: 'A256GCM',
  };
  String get value => stringValues[this]!;
}

enum JwsSignatureAlgorithm {
  edDsa,
  es256,
  es256k;

  static const Map<JwsSignatureAlgorithm, String> stringValues = {
    JwsSignatureAlgorithm.edDsa: 'EdDSA',
    JwsSignatureAlgorithm.es256: 'ES256',
    JwsSignatureAlgorithm.es256k: 'ES256K'
  };
  String get value => stringValues[this]!;
}

enum DidcommProtocol {
  issueCredential,
  presentProof,
  discoverFeature,
  invitation,
  requestPresentation;

  static const Map<DidcommProtocol, String> stringValues = {
    DidcommProtocol.issueCredential: 'issue-credential',
    DidcommProtocol.presentProof: 'present-proof',
    DidcommProtocol.discoverFeature: 'discover-features',
    DidcommProtocol.invitation: 'invitation'
  };
  String get value => stringValues[this]!;
}

class DidcommMessages {
  static const String proposeCredential =
      'https://didcomm.org/issue-credential/3.0/propose-credential';

  static const offerCredential =
      'https://didcomm.org/issue-credential/3.0/offer-credential';

  static const requestCredential =
      'https://didcomm.org/issue-credential/3.0/request-credential';

  static const issueCredential =
      'https://didcomm.org/issue-credential/3.0/issue-credential';

  static const issueCredentialProblem =
      'https://didcomm.org/issue-credential/3.0/problem-report';

  static const previewCredential =
      'https://didcomm.org/issue-credential/3.0/credential-preview';

  static const emptyMessage = 'https://didcomm.org/empty/1.0';

  static const presentation =
      'https://didcomm.org/present-proof/3.0/presentation';

  static const requestPresentation =
      'https://didcomm.org/present-proof/3.0/request-presentation';

  static const proposePresentation =
      'https://didcomm.org/present-proof/3.0/propose-presentation';

  static const requestPresentationProblem =
      'https://didcomm.org/present-proof/3.0/problem-report';

  static const discoverFeatureQuery =
      'https://didcomm.org/discover-features/2.0/queries';

  static const discoverFeatureDisclose =
      'https://didcomm.org/discover-features/1.0/disclose';

  static const invitation = 'https://didcomm.org/out-of-band/2.0/invitation';

  static const problemReport =
      'https://didcomm.org/report-problem/2.0/problem-report';

  List<String> get allValues => [
        proposeCredential,
        offerCredential,
        requestCredential,
        issueCredential,
        previewCredential,
        emptyMessage,
        presentation,
        requestPresentation,
        proposePresentation,
        discoverFeatureQuery,
        discoverFeatureDisclose,
        invitation,
        problemReport
      ];
}

class AttachmentFormat {
  static const presentationDefinition =
      'dif/presentation-exchange/definitions@v1.0';
  static const presentationDefinition2 =
      'dif/presentation-exchange/definitions@v2.0';
  static const presentationSubmission =
      'dif/presentation-exchange/submission@v1.0';
  static const presentationSubmission2 =
      'dif/presentation-exchange/submission@v2.0';
  static const ldProofVc = 'aries/ld-proof-vc@v1.0';
  static const ldProofVcDetail = 'aries/ld-proof-vc-detail@v1.0';
  static const credentialManifestAries = 'dif/credential-manifest@v1.0';
  static const credentialManifest = 'dif/credential-manifest/manifest@v1.0';
  static const credentialFulfillment =
      'dif/credential-manifest/fulfillment@v1.0';
  static const credentialApplication =
      'dif/credential-manifest/application@v1.0';
  static const indyProofRequest = 'hlindy/proof-req@v2.0';
  static const indyProof = 'hlindy/proof@v2.0';
  static const indyCredential = 'hlindy/cred@v2.0';
  static const indyCredentialRequest = 'hlindy/cred-req@v2.0';
  static const indyCredentialAbstract = 'hlindy/cred-abstract@v2.0';
  static const indyCredentialFilter = 'hlindy/cred-filter@v2.0';

  List<String> get allValues => [
        presentationDefinition,
        presentationDefinition2,
        presentationSubmission,
        presentationSubmission2,
        ldProofVc,
        ldProofVcDetail,
        credentialManifestAries,
        credentialManifest,
        credentialFulfillment,
        credentialApplication,
        indyProofRequest,
        indyProof,
        indyCredential,
        indyCredentialRequest,
        indyCredentialAbstract,
        indyCredentialFilter
      ];
}

enum AcknowledgeStatus {
  ok,
  fail,
  pending;

  static const Map<AcknowledgeStatus, String> stringValues = {
    AcknowledgeStatus.ok: 'OK',
    AcknowledgeStatus.pending: 'PENDING',
    AcknowledgeStatus.fail: 'FAIL'
  };
  String get value => stringValues[this]!;
}

enum ReturnRouteValue {
  none,
  all,
  thread;

  static const Map<ReturnRouteValue, String> stringValues = {
    ReturnRouteValue.none: 'none',
    ReturnRouteValue.all: 'all',
    ReturnRouteValue.thread: 'thread'
  };
  String get value => stringValues[this]!;
}
