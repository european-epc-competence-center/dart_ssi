import 'dart:io';

import 'package:dart_ssi/credentials.dart';
import 'package:dart_ssi/src/credentials/jsonLdContext/json_web_signature_2020_context.dart';
import 'package:dart_ssi/src/util/crypto_provider.dart';
import 'package:dart_ssi/src/wallet/wallet_store.dart';
import 'package:test/test.dart';

void main() {
  group('Sign and verify credential', () {
    late WalletStore wallet;

    setUp(() async {
      var dir = Directory('tests');
      if (!dir.existsSync()) {
        wallet = WalletStore('tests');
        await wallet.openBoxes(password: 'password');
        await wallet.initializeIssuer();
      }
    });

    test('ed25519', () async {
      var issuer = await wallet.generateNewKey(keyType: KeyType.ed25519);
      var credential = VerifiableCredential(
          context: [credentialsV1Iri, schemaOrgIri],
          type: ['VerifiableCredential', 'NameCredential'],
          issuer: issuer,
          credentialSubject: {'name': 'Mustermann'},
          issuanceDate: DateTime.now());

      var signer = WalletCredentialSigner(wallet, issuer, 'EdDSA', issuer);
      await credential.sign(signer, LdpProofType.ed25519Signature2020);

      expect(credential.context.contains(ed25519ContextIri), true);
      expect(credential.proof, isNotNull);
      expect(credential.proof?.proofPurpose, 'assertionMethod');
      expect(credential.proof?.created, isNotNull);

      expect(await credential.verify(), true);
    });

    test('secp256k1', () async {
      var issuer = await wallet.generateNewKey(keyType: KeyType.secp256k1);
      var credential = VerifiableCredential(
          context: [credentialsV1Iri, schemaOrgIri],
          type: ['VerifiableCredential', 'NameCredential'],
          issuer: issuer,
          credentialSubject: {'name': 'Mustermann'},
          issuanceDate: DateTime.now());
      var signer = WalletCredentialSigner(wallet, issuer, 'ES256', issuer);
      await credential.sign(signer, LdpProofType.jsonWebSignature2020);

      expect(credential.context.contains(jsonWebSignature2020ContextIri), true);
      expect(credential.proof, isNotNull);
      expect(credential.proof?.proofPurpose, 'assertionMethod');
      expect(credential.proof?.created, isNotNull);

      expect(await credential.verify(), true);
    });

    test('p256', () async {
      var issuer = await wallet.generateNewKey(keyType: KeyType.p256);
      var credential = VerifiableCredential(
          context: [credentialsV1Iri, schemaOrgIri],
          type: ['VerifiableCredential', 'NameCredential'],
          issuer: issuer,
          credentialSubject: {'name': 'Mustermann'},
          issuanceDate: DateTime.now());
      var signer = WalletCredentialSigner(wallet, issuer, 'ES256', issuer);
      await credential.sign(signer, LdpProofType.jsonWebSignature2020);

      expect(credential.context.contains(jsonWebSignature2020ContextIri), true);
      expect(credential.proof, isNotNull);
      expect(credential.proof?.proofPurpose, 'assertionMethod');
      expect(credential.proof?.created, isNotNull);

      expect(await credential.verify(), true);
    });

    test('p384', () async {
      var issuer = await wallet.generateNewKey(keyType: KeyType.p384);
      var credential = VerifiableCredential(
          context: [credentialsV1Iri, schemaOrgIri],
          type: ['VerifiableCredential', 'NameCredential'],
          issuer: issuer,
          credentialSubject: {'name': 'Mustermann'},
          issuanceDate: DateTime.now());
      var signer = WalletCredentialSigner(wallet, issuer, 'ES384', issuer);
      await credential.sign(signer, LdpProofType.jsonWebSignature2020);

      expect(credential.context.contains(jsonWebSignature2020ContextIri), true);
      expect(credential.proof, isNotNull);
      expect(credential.proof?.proofPurpose, 'assertionMethod');
      expect(credential.proof?.created, isNotNull);

      expect(await credential.verify(), true);
    });

    test('p521', () async {
      var issuer = await wallet.generateNewKey(keyType: KeyType.p521);
      var credential = VerifiableCredential(
          context: [
            credentialsV1Iri,
            {'name': 'https://schema.org'}
          ],
          type: ['VerifiableCredential', 'NameCredential'],
          issuer: issuer,
          credentialSubject: {'name': 'Mustermann'},
          issuanceDate: DateTime.now());
      var signer = WalletCredentialSigner(wallet, issuer, 'ES512', issuer);
      await credential.sign(signer, LdpProofType.jsonWebSignature2020);

      expect(credential.context.contains(jsonWebSignature2020ContextIri), true);
      expect(credential.proof, isNotNull);
      expect(credential.proof?.proofPurpose, 'assertionMethod');
      expect(credential.proof?.created, isNotNull);

      expect(await credential.verify(), true);
    });

    tearDown(() {
      var dir = Directory('tests');
      if (dir.existsSync()) dir.delete(recursive: true);
    });
  });
}
