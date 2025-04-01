import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:dart_ssi/credentials.dart';
import 'package:iso_mdoc/iso_mdoc.dart';
import 'package:pointycastle/export.dart' as pc;
import 'package:sd_jwt/sd_jwt.dart';
import 'package:x25519/x25519.dart' as x25519;

import '../wallet/wallet_store.dart';
import 'private_util.dart';
import 'utils.dart';

class WalletCryptoProviderForSdJwt extends CryptoProvider {
  final WalletStore wallet;
  final String keyId;

  WalletCryptoProviderForSdJwt(this.wallet, this.keyId);

  @override
  Uint8List digest(
      {required Uint8List data, required DigestAlgorithm algorithm}) {
    // TODO: implement digest
    throw UnimplementedError();
  }

  @override
  FutureOr<Signature> sign(
      {required Uint8List data, required SigningAlgorithm algorithm}) async {
    var sig = await wallet.sign(keyId, data);
    return EcSignature(
        sig.sublist(0, sig.length ~/ 2), sig.sublist(sig.length ~/ 2));
  }

  @override
  FutureOr<bool> verify(
      {required Uint8List data,
      required SigningAlgorithm algorithm,
      required Signature signature}) {
    Uint8List sig;
    if (signature is EcSignature) {
      sig = Uint8List.fromList(signature.r + signature.s);
    } else {
      throw Exception('Unknown Signature');
    }
    return wallet.verify(keyId, data, sig) as bool;
  }

  @override
  Key generateKeyPair({required KeyParameters keyParameters}) {
    // TODO: implement generateKeyPair
    throw UnimplementedError();
  }
}

class WalletSignatureGeneratorForMdoc extends SignatureGenerator {
  WalletStore wallet;
  String keyId;

  WalletSignatureGeneratorForMdoc(
      super.supportedCoseAlgorithm, this.wallet, this.keyId);

  @override
  FutureOr<List<int>> generate(List<int> data) {
    return wallet.sign(keyId, Uint8List.fromList(data));
  }

  @override
  FutureOr<bool> verify(List<int> data, List<int> toVerify) {
    return wallet.verify(
        keyId, Uint8List.fromList(data), Uint8List.fromList(toVerify));
  }
}

class WalletCredentialSigner extends CredentialSigner {
  WalletStore wallet;
  String keyId;

  WalletCredentialSigner(
      this.wallet, this.keyId, super.algValue, super.verificationMethod);

  @override
  FutureOr<Uint8List> sign(Uint8List data) {
    return wallet.sign(keyId, data);
  }

  @override
  FutureOr<bool> verify(Uint8List data, Uint8List signature) {
    return wallet.verify(keyId, data, signature);
  }
}

class WalletKeyAgreementGenerator extends KeyAgreementGenerator {
  WalletStore wallet;
  String keyId;

  WalletKeyAgreementGenerator(this.wallet, this.keyId);

  @override
  FutureOr<Uint8List> generateAgreement(Map<String, dynamic> otherPublicKey) {
    return wallet.calculateKeyAgreement(keyId, otherPublicKey);
  }
}

class JwkKeyAgreementGenerator extends KeyAgreementGenerator {
  Map<String, dynamic> privateKey;

  JwkKeyAgreementGenerator(this.privateKey);

  @override
  FutureOr<Uint8List> generateAgreement(Map<String, dynamic> otherPublicKey) {
    List<int> z;
    // keys given as jwks
    var crv = privateKey['crv'];
    if (crv != otherPublicKey['crv']) {
      throw Exception('curves do not match ($crv != ${otherPublicKey['crv']}');
    }

    pc.ECDomainParameters curve;
    pc.ECPrivateKey private;
    int length;

    if (crv.startsWith('P') || crv.startsWith('secp256k1')) {
      if (crv == 'P-256') {
        length = 32;
        curve = pc.ECCurve_secp256r1();
      } else if (crv == 'P-384') {
        length = 48;
        curve = pc.ECCurve_secp384r1();
      } else if (crv == 'P-521') {
        length = 66;
        curve = pc.ECCurve_secp521r1();
      } else if (crv == 'secp256k1') {
        length = 32;
        curve = pc.ECCurve_secp256k1();
      } else {
        throw UnimplementedError("Curve `$crv` not supported");
      }

      var pubKey = pc.ECPublicKey(
          curve.curve.createPoint(
              bytesToUnsignedInt(
                  base64Decode(addPaddingToBase64(otherPublicKey['x']))),
              bytesToUnsignedInt(
                  base64Decode(addPaddingToBase64(otherPublicKey['y'])))),
          curve);
      private = pc.ECPrivateKey(
          bytesToUnsignedInt(base64Decode(addPaddingToBase64(privateKey['d']))),
          curve);
      var agree = pc.ECDHBasicAgreement();
      agree.init(private);
      var secret = agree.calculateAgreement(pubKey);
      var z1 = unsignedIntToBytes(secret);

      while (z1.length < length) {
        z1 = Uint8List.fromList([0] + z1);
      }
      return z1;
    } else if (crv.startsWith('X')) {
      var castedPrivate = base64Decode(addPaddingToBase64(privateKey['d']));
      var castedPublic = base64Decode(addPaddingToBase64(otherPublicKey['x']));
      z = x25519.X25519(castedPrivate, castedPublic);
      return Uint8List.fromList(z);
    } else {
      throw UnimplementedError("Curve `$crv` not supported");
    }
  }
}

abstract class KeyAgreementGenerator {
  FutureOr<Uint8List> generateAgreement(Map<String, dynamic> otherPublicKey);
}
