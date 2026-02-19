import 'dart:convert';

import 'package:json_schema/json_schema.dart';
import 'package:sd_jwt/sd_jwt.dart' as sd_jwt;

import '../util/types.dart';
import '../util/utils.dart';
import 'didcomm_jwe.dart';
import 'didcomm_jwm.dart';
import 'types.dart';

var signedMessageSchema = JsonSchema.create({
  'type': 'object',
  'properties': {
    'payload': {'type': 'string'},
    'signatures': {
      'type': 'array',
      'contains': {
        'type': 'object',
        'properties': {
          'signature': {
            'type': 'string',
          },
          'header': {'type': 'object'},
          'protected': {'type': 'string'}
        },
        'required': ['signature']
      }
    }
  },
  'required': ['payload', 'signatures']
});

bool isSignedMessage(dynamic message) {
  var asMap = credentialToMap(message);
  return signedMessageSchema.validate(asMap).isValid;
}

/// A signed didcomm message
class DidcommSignedMessage extends DidcommMessage {
  late DidcommMessage payload;
  List<SignatureObject>? signatures;
  String? _base64Payload;

  DidcommSignedMessage({required this.payload, this.signatures});

  DidcommSignedMessage.fromJson(dynamic jsonObject) {
    var sig = credentialToMap(jsonObject);
    if (sig.containsKey('payload')) {
      _base64Payload = sig['payload'];
      var decodedPayload =
          utf8.decode(base64Decode(addPaddingToBase64(sig['payload'])));
      try {
        payload = DidcommSignedMessage.fromJson(decodedPayload);
      } catch (e) {
        try {
          payload = DidcommPlaintextMessage.fromJson(decodedPayload);
        } catch (e) {
          try {
            payload = DidcommEncryptedMessage.fromJson(decodedPayload);
          } catch (e) {
            throw Exception('Unknown message type');
          }
        }
      }
    } else {
      throw Exception('payload is needed in jws');
    }
    if (sig.containsKey('signatures')) {
      List tmp = sig['signatures'];
      if (tmp.isNotEmpty) {
        signatures = [];
        for (var s in tmp) {
          signatures!.add(SignatureObject.fromJson(s));
        }
      } else {
        throw Exception('Empty Signatures');
      }
    } else {
      throw Exception('signature property is needed in jws');
    }
  }

  Future<void> sign(List<Map<String, dynamic>> jwkToSignWith) async {
    signatures ??= [];
    for (var jwk in jwkToSignWith) {
      var castedJwk = sd_jwt.Jwk.fromJson(jwk);
      Map<String, dynamic> protected = {
        'typ': DidcommMessageTyp.signed.value,
      };
      sd_jwt.CryptoProvider provider;

      if (castedJwk.key is sd_jwt.EdPrivateKey) {
        provider = sd_jwt.Ed25519EdwardsCryptoProvider(
            castedJwk.key as sd_jwt.AsymmetricKey);
        protected['crv'] = 'Ed25519';
        protected['alg'] = 'EdDSA';
      } else if (castedJwk.key is sd_jwt.EcPrivateKey) {
        provider = sd_jwt.PointyCastleCryptoProvider(
            castedJwk.key as sd_jwt.AsymmetricKey);
        var k = castedJwk.key as sd_jwt.EcPrivateKey;
        if (k.curve == sd_jwt.Curve.p256k) {
          protected['crv'] = 'P-256k';
          protected['alg'] = 'ES256';
        } else if (k.curve == sd_jwt.Curve.p256) {
          protected['crv'] = 'P-256';
          protected['alg'] = 'ES256';
        } else if (k.curve == sd_jwt.Curve.p384) {
          protected['crv'] = 'P-384';
          protected['alg'] = 'ES384';
        } else if (k.curve == sd_jwt.Curve.p521) {
          protected['crv'] = 'P-521';
          protected['alg'] = 'ES512';
        } else {
          throw Exception('Unsupported curve');
        }
      } else {
        throw Exception('Unsupported KeyType');
      }
      var jwt = sd_jwt.Jwt(
          additionalClaims: _base64Payload != null
              ? jsonDecode(utf8.decode(base64Decode(_base64Payload!)))
              : payload.toJson());
      var jws = await jwt.sign(
          signer: provider,
          header:
              sd_jwt.JoseHeader.fromJson(protected) as sd_jwt.JwsJoseHeader);

      signatures!.add(SignatureObject(
          signature: jws.toCompactSerialization().split('.').last,
          protected: jws.toCompactSerialization().split('.').first));
    }
    return;
  }

  Future<bool> verify(Map<String, dynamic> publicKeyJwk) async {
    var crv = publicKeyJwk['crv'];
    if (crv == null) throw Exception('Jwk without crv parameter');
    bool valid = true;

    if (signatures == null || signatures!.isEmpty) {
      throw Exception('Nothing to verify');
    }

    for (var s in signatures!) {
      var encodedHeader = s.protected;
      var encodedPayload = _base64Payload ??
          removePaddingFromBase64(
              base64UrlEncode(utf8.encode(payload.toString())));
      var encodedSignature = s.signature;
      var jws = sd_jwt.Jws.fromCompactSerialization(
          '$encodedHeader.$encodedPayload.$encodedSignature');
      var jwk = sd_jwt.Jwk.fromJson(publicKeyJwk);
      sd_jwt.CryptoProvider provider;
      if (jwk.keyType == sd_jwt.KeyType.okp) {
        provider = sd_jwt.Ed25519EdwardsCryptoProvider(
            jwk.key as sd_jwt.AsymmetricKey);
      } else {
        provider =
            sd_jwt.PointyCastleCryptoProvider(jwk.key as sd_jwt.AsymmetricKey);
      }
      valid = await jws.verify(provider);
      if (!valid) {
        throw Exception('A Signature is wrong');
      }
    }
    return valid;
  }

  @override
  Map<String, dynamic> toJson() {
    Map<String, dynamic> jsonObject = {};
    jsonObject['payload'] = removePaddingFromBase64(
        base64UrlEncode(utf8.encode(payload.toString())));

    if (signatures != null) {
      List sigs = [];
      for (var s in signatures!) {
        sigs.add(s.toJson());
      }
      jsonObject['signatures'] = sigs;
    }

    return jsonObject;
  }
}

/// Signature of a didcomm signed message
class SignatureObject extends JsonObject {
  // base64Url encoded protected header
  String? protected;
  Map<String, dynamic>? header;
  late String signature;

  SignatureObject({this.protected, this.header, required this.signature});

  SignatureObject.fromJson(dynamic jsonObject) {
    var sig = credentialToMap(jsonObject);
    if (sig.containsKey('protected')) {
      protected = sig['protected'];
    }
    header = sig['header'];
    if (sig.containsKey('signature')) {
      signature = sig['signature'];
    } else {
      throw Exception('signature value is needed in SignatureObject');
    }
  }

  @override
  Map<String, dynamic> toJson() {
    Map<String, dynamic> jsonObject = {};
    if (protected != null) {
      jsonObject['protected'] = removePaddingFromBase64(
          base64UrlEncode(utf8.encode(jsonEncode(protected!))));
    }
    if (header != null) jsonObject['header'] = header;
    jsonObject['signature'] = signature;
    return jsonObject;
  }
}
