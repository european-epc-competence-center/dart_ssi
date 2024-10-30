import 'dart:async';
import 'dart:typed_data';

import 'package:dart_ssi/credentials.dart';
import 'package:iso_mdoc/iso_mdoc.dart';
import 'package:sd_jwt/sd_jwt.dart';

import '../wallet/wallet_store.dart';

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
  AsymmetricKey generateEcKeyPair({required Curve curve}) {
    // TODO: implement generateEcKeyPair
    throw UnimplementedError();
  }

  @override
  FutureOr<Uint8List> sign(
      {required Uint8List data, required SigningAlgorithm algorithm}) {
    return wallet.sign(keyId, data);
  }

  @override
  bool verify(
      {required Uint8List data,
      required SigningAlgorithm algorithm,
      required Signature signature}) {
    Uint8List sig;
    if (signature is EcSignature) {
      sig = Uint8List.fromList(signature.r + signature.s);
    } else {
      throw Exception('Unknown Signature');
    }

    //TODO: Verify in sd_jwt must be asynchronous
    return wallet.verify(keyId, data, sig) as bool;
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
