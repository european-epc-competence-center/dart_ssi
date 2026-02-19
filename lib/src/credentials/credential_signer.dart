import 'dart:async';
import 'dart:typed_data';

import 'package:dart_ssi/did.dart';
import 'package:ed25519_edwards/ed25519_edwards.dart' as ed;
import 'package:sd_jwt/sd_jwt.dart' as sd_jwt;

import '../wallet/wallet_store.dart';

abstract class CredentialSigner {
  /// JWA alg value
  final String algValue;

  /// for JWKs this will be the kid
  final String verificationMethod;

  CredentialSigner(this.algValue, this.verificationMethod);

  FutureOr<Uint8List> sign(Uint8List data);

  FutureOr<bool> verify(Uint8List data, Uint8List signature);
}

class JwkCredentialSigner extends CredentialSigner {
  sd_jwt.Jwk jwk;
  JwkCredentialSigner(this.jwk) : super('', jwk.keyId ?? '');
  @override
  FutureOr<Uint8List> sign(Uint8List data) {
    // TODO: implement sign
    throw UnimplementedError();
  }

  @override
  FutureOr<bool> verify(Uint8List data, Uint8List signature) {
    if (jwk.key is sd_jwt.EdPublicKey) {
      return ed.verify(
          ed.PublicKey((jwk.key as sd_jwt.EdPublicKey).pubA), data, signature);
    } else if (jwk.key is sd_jwt.EcPublicKey) {
      var k = jwk.key as sd_jwt.EcPublicKey;
      var crypto =
          sd_jwt.PointyCastleCryptoProvider(jwk.key as sd_jwt.AsymmetricKey);
      sd_jwt.SigningAlgorithm algorithm;
      if (k.curve == sd_jwt.Curve.p256k) {
        algorithm = sd_jwt.SigningAlgorithm.ecdsaSha256Koblitz;
      } else if (k.curve == sd_jwt.Curve.p256) {
        algorithm = sd_jwt.SigningAlgorithm.ecdsaSha256Prime;
      } else if (k.curve == sd_jwt.Curve.p384) {
        algorithm = sd_jwt.SigningAlgorithm.ecdsaSha384Prime;
      } else if (k.curve == sd_jwt.Curve.p521) {
        algorithm = sd_jwt.SigningAlgorithm.ecdsaSha512Prime;
      } else {
        throw Exception('Unsupported Curve');
      }
      return crypto.verify(
          data: data,
          algorithm: algorithm,
          signature: sd_jwt.Signature.fromSignatureBytes(signature, algorithm));
    } else {
      throw Exception('Unsupported key type');
    }
  }
}

abstract class Signer {
  final String algValue = '';
  final String crvValue = '';
  final String typeName = '';

  /// Build a LinkedDataProof / DataIntegrityProof
  FutureOr<Map<String, dynamic>> buildProof(
      dynamic data, WalletStore wallet, String did,
      {String? challenge, String? domain, String? proofPurpose});

  /// Build a (detached) JWS
  ///
  /// Either using a combination of [wallet] and [did] **or** by using a private JsonWebKey [jwk].
  FutureOr<String> sign(
      {dynamic data,
      WalletStore? wallet,
      String? did,
      Map<String, dynamic>? jwk,
      bool detached = false,
      dynamic jwsHeader});

  /// Verifies a LinkedDataProof / DataIntegrityProof
  FutureOr<bool> verifyProof(dynamic proof, dynamic data, String did,
      {String? challenge,
      Map<String, dynamic>? jwk,
      Future<DidDocument> Function(String) didResolver});

  /// Verifies a (detached) JWS
  FutureOr<bool> verify(String jws,
      {String? did, Map<String, dynamic>? jwk, dynamic data});
}

// class EcdsaRecoverySignature implements Signer {
//   @override
//   final String typeName = 'EcdsaSecp256k1RecoverySignature2020';
//   @override
//   final String algValue = 'ES256K-R';
//   @override
//   final String crvValue = 'secp256k1';
//   final Function(Uri url, LoadDocumentOptions? options)? loadDocument;
//
//   EcdsaRecoverySignature(this.loadDocument);
//
//   @override
//   Future<Map<String, dynamic>> buildProof(data, WalletStore wallet, String did,
//       {String? challenge, String? domain, String? proofPurpose}) async {
//     var proofOptions = {
//       '@context': ecdsaRecoveryContextIri,
//       'type': typeName,
//       'proofPurpose': proofPurpose ?? 'assertionMethod',
//       'verificationMethod': '$did#controller',
//       'created': DateTime.now().toUtc().toIso8601String()
//     };
//     if (domain != null) {
//       proofOptions['domain'] = domain;
//     }
//     if (challenge != null) {
//       proofOptions['challenge'] = challenge;
//     }
//
//     List<int> hash = await _dataToHash(data);
//
//     var pOptionsHash = sha256
//         .convert(utf8.encode(await JsonLdProcessor.normalize(proofOptions,
//             options:
//                 JsonLdOptions(safeMode: true, documentLoader: loadDocument))))
//         .bytes;
//     var payload = pOptionsHash + hash;
//
//     var critical = <String, dynamic>{};
//     critical['b64'] = false;
//     var header = buildJwsHeader(alg: 'ES256K-R', extra: critical);
//     var headerEnc = removePaddingFromBase64(header);
//
//     var hashToSign = sha256.convert(utf8.encode('$headerEnc.') + payload).bytes;
//
//     //proofOptions.remove('@context');
//
//     var privateKeyHex = await wallet.getPrivateKeyForCredentialDid(did);
//     privateKeyHex ??= await wallet.getPrivateKeyForConnectionDid(did);
//     if (privateKeyHex == null) throw Exception('Could not find a private key');
//     var key = EthPrivateKey.fromHex(privateKeyHex);
//
//     var sigArray = _buildSignatureArray(Uint8List.fromList(hashToSign), key);
//     while (sigArray.length != 65) {
//       sigArray = _buildSignatureArray(Uint8List.fromList(hashToSign), key);
//     }
//
//     proofOptions['jws'] = '$headerEnc.'
//         '.${base64UrlEncode(sigArray)}';
//
//     return proofOptions;
//   }
//
//   FutureOr<List<int>> _dataToHash(dynamic data) async {
//     if (data is Uint8List) {
//       return data.toList();
//     } else if (data is List<int>) {
//       return data;
//     } else if (data is Map<String, dynamic>) {
//       return sha256
//           .convert(utf8.encode(await JsonLdProcessor.normalize(
//               Map<String, dynamic>.from(data),
//               options:
//                   JsonLdOptions(safeMode: true, documentLoader: loadDocument))))
//           .bytes;
//     } else if (data is String) {
//       return sha256.convert(utf8.encode(data)).bytes;
//     } else {
//       throw Exception('Unknown datatype for data');
//     }
//   }
//
//   @override
//   Future<String> sign(
//       {dynamic data,
//       WalletStore? wallet,
//       String? did,
//       Map<String, dynamic>? jwk,
//       bool detached = false,
//       dynamic jwsHeader}) async {
//     String header;
//     if (jwsHeader != null) {
//       Map<String, dynamic>? headerMap;
//       if (jwsHeader is String) {
//         headerMap = jsonDecode(jwsHeader);
//       } else {
//         headerMap = jwsHeader;
//       }
//       if (headerMap!['alg'] != 'ES256K-R') {
//         throw Exception('Unsupported signature algorithm ${headerMap['alg']}');
//       }
//       header = removePaddingFromBase64(
//           base64UrlEncode(utf8.encode(jsonEncode(headerMap))));
//     } else {
//       var critical = <String, dynamic>{};
//       critical['b64'] = false;
//       header = removePaddingFromBase64(
//           buildJwsHeader(alg: 'ES256K-R', extra: critical));
//     }
//
//     String signable = '';
//     if (data is String) {
//       signable = data;
//     } else if (data is Map<String, dynamic>) {
//       signable = jsonEncode(data);
//     } else {
//       throw Exception('Unexpected Datatype ${data.runtimeType} for toSign');
//     }
//
//     var payload =
//         removePaddingFromBase64(base64UrlEncode(utf8.encode(signable)));
//     var signingInput = '$header.$payload';
//     var hash = sha256.convert(ascii.encode(signingInput)).bytes;
//     String? privateKeyHex;
//
//     if (did != null && wallet != null) {
//       privateKeyHex = await wallet.getPrivateKeyForCredentialDid(did);
//       privateKeyHex ??= await wallet.getPrivateKeyForConnectionDid(did);
//       if (privateKeyHex == null) throw Exception('Could not find private key');
//     } else if (jwk != null) {
//       if (jwk['crv'] != 'secp256k1') {
//         throw Exception('Wrong crv value for private key');
//       }
//
//       if (jwk['d'] == null) {
//         throw Exception('This is no private key');
//       }
//
//       privateKeyHex = hexEncode(
//           Uint8List.fromList(base64Decode(addPaddingToBase64(jwk['d']))));
//     } else {
//       throw Exception('No private key given. Can\'t sign data');
//     }
//
//     var key = EthPrivateKey.fromHex(privateKeyHex);
//     var sigArray = _buildSignatureArray(hash as Uint8List, key);
//     while (sigArray.length != 65) {
//       sigArray = _buildSignatureArray(hash, key);
//     }
//
//     if (detached) {
//       return '$header.'
//           '.${removePaddingFromBase64(base64UrlEncode(sigArray))}';
//     } else {
//       return '$header.$payload'
//           '.${removePaddingFromBase64(base64UrlEncode(sigArray))}';
//     }
//   }
//
//   List<int> _buildSignatureArray(Uint8List hash, EthPrivateKey privateKey) {
//     web3_crypto.MsgSignature signature =
//         web3_crypto.sign(hash, privateKey.privateKey);
//     List<int> rList = web3_crypto.unsignedIntToBytes(signature.r);
//     if (rList.length < 32) {
//       List<int> rPad = List.filled(32 - rList.length, 0);
//       rList = rPad + rList;
//     }
//     List<int> sList = web3_crypto.unsignedIntToBytes(signature.s);
//     if (sList.length < 32) {
//       List<int> sPad = List.filled(32 - sList.length, 0);
//       sList = sPad + sList;
//     }
//     List<int> sigArray = rList + sList + [signature.v - 27];
//     return sigArray;
//   }
//
//   @override
//   Future<bool> verifyProof(proof, data, String did,
//       {String? challenge,
//       Map<String, dynamic>? jwk,
//       Future<DidDocument> Function(String) didResolver =
//           resolveDidDocument}) async {
//     //compare challenge
//     if (challenge != null) {
//       var containedChallenge = proof['challenge'];
//       if (containedChallenge == null) {
//         throw Exception('Expected challenge in this credential');
//       }
//       if (containedChallenge != challenge) {
//         throw Exception('a challenge do not match expected challenge');
//       }
//     }
//
//     //verify signature
//     var signature = _getSignatureFromJws(proof['jws']);
//
//     List<int> hash = await _dataToHash(data);
//
//     String jws = proof.remove('jws');
//     proof['@context'] = ecdsaRecoveryContextIri;
//
//     var proofHash = sha256
//         .convert(utf8.encode(await JsonLdProcessor.normalize(proof,
//             options:
//                 JsonLdOptions(safeMode: true, documentLoader: loadDocument))))
//         .bytes;
//     var payload = proofHash + hash;
//
//     proof['jws'] = jws;
//     proof.remove('@context');
//
//     var header = jws.split('.').first;
//
//     var hashToSign = sha256.convert(utf8.encode('$header.') + payload).bytes;
//
//     var pubKey = web3_crypto.ecRecover(hashToSign as Uint8List, signature);
//
//     if (did.startsWith('did:ethr')) {
//       var givenAddress = EthereumAddress.fromHex(did.split(':').last);
//
//       return EthereumAddress.fromPublicKey(pubKey).hexEip55 ==
//           givenAddress.hexEip55;
//     } else if (did.startsWith('did:key')) {
//       var c = el.getSecp256k1();
//       var compressed = c.publicKeyToCompressedHex(el.PublicKey(
//           c,
//           web3_crypto.bytesToInt(pubKey.sublist(0, 32)),
//           web3_crypto.bytesToInt(pubKey.sublist(32))));
//       var recoveredDid = 'did:key:z${base58Bitcoin.encode(Uint8List.fromList([
//             231,
//             1
//           ] + web3_crypto.hexToBytes(compressed)))}';
//       print(recoveredDid);
//       return did == recoveredDid;
//     } else if (did.startsWith('did:jwk')) {
//       var jwk = jsonDecode(utf8.decode(base64Decode(
//           addPaddingToBase64(did.split(':')[2].split('#').first))));
//       if (jwk['crv'] != 'secp256k1') {
//         throw Exception('curve does not match');
//       }
//
//       var recoveredX = pubKey.sublist(0, 32);
//       var recoveredY = pubKey.sublist(32);
//
//       return removePaddingFromBase64(base64UrlEncode(recoveredX)) == jwk['x'] &&
//           removePaddingFromBase64(base64UrlEncode(recoveredY)) == jwk['y'];
//     } else if (did.startsWith('did:example')) {
//       var recoveredX = pubKey.sublist(0, 32);
//       var recoveredY = pubKey.sublist(32);
//       print(base64Encode(recoveredX));
//       print(base64Encode(recoveredY));
//       print(EthereumAddress.fromPublicKey(pubKey).hexEip55);
//       return true;
//     } else {
//       throw Exception('unsupported did method');
//     }
//   }
//
//   web3_crypto.MsgSignature _getSignatureFromJws(String jws) {
//     var splitJws = jws.split('.');
//     Map<String, dynamic> header =
//         jsonDecode(utf8.decode(base64Decode(addPaddingToBase64(splitJws[0]))));
//     if (header['alg'] != 'ES256K-R') {
//       throw Exception('Unsupported signature Algorithm ${header['alg']}');
//     }
//     var sigArray = base64Decode(addPaddingToBase64(splitJws[2]));
//     if (sigArray.length != 65) throw Exception('wrong signature-length');
//     return web3_crypto.MsgSignature(
//         web3_crypto.bytesToUnsignedInt(sigArray.sublist(0, 32)),
//         web3_crypto.bytesToUnsignedInt(sigArray.sublist(32, 64)),
//         sigArray[64] + 27);
//   }
//
//   @override
//   FutureOr<bool> verify(String jws,
//       {String? did, Map<String, dynamic>? jwk, dynamic data}) {
//     var splitted = jws.split('.');
//     if (splitted.length != 3) throw Exception('Malformed JWS');
//     var signature = _getSignatureFromJws(jws);
//
//     String payload;
//     if (splitted[1] != '') {
//       payload = splitted[1];
//     } else if (data != null) {
//       String signable = '';
//       if (data is String) {
//         signable = data;
//       } else if (data is Map<String, dynamic>) {
//         signable = jsonEncode(data);
//       } else {
//         throw Exception('Unexpected Datatype ${data.runtimeType} for toSign');
//       }
//       payload = removePaddingFromBase64(base64UrlEncode(utf8.encode(signable)));
//     } else {
//       throw Exception('No payload given');
//     }
//
//     var signingInput = '${splitted[0]}.$payload';
//     var hashToSign = sha256.convert(ascii.encode(signingInput)).bytes;
//     var pubKey = web3_crypto.ecRecover(hashToSign as Uint8List, signature);
//
//     if (did != null) {
//       return EthereumAddress.fromPublicKey(pubKey).hexEip55 ==
//           did.split(':').last;
//     } else if (jwk != null) {
//       // TODO: Check if it works
//       return EthereumAddress.fromPublicKey(pubKey).hexEip55 ==
//           EthereumAddress.fromPublicKey(Uint8List.fromList(
//                   base64Decode(addPaddingToBase64(jwk['x']))))
//               .hexEip55;
//     } else {
//       throw Exception('Either did or jwk must be given');
//     }
//   }
// }
