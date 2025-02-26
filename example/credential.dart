import 'package:dart_ssi/credentials.dart';
import 'package:dart_ssi/src/util/crypto_provider.dart';
import 'package:dart_ssi/wallet.dart';

void main() async {
  var issuer = WalletStore('exampleData/testIssuer');
  await issuer.openBoxes(password: 'password');
  await issuer.initializeIssuer();
  // when using the default keystore backend the keyIds are dids. This must not be the case with every backend
  var issuerDid = issuer.getStandardIssuerDid();

  var holder = WalletStore('exampleData/testHolder');
  await holder.openBoxes(password: 'holderPw');
  var holderDid = await holder.generateNewKey(keyType: KeyType.p256);
  var vc = VerifiableCredential(
      context: [credentialsV1Iri, schemaOrgIri],
      type: ['VerifiableCredential', 'TestCredential'],
      issuer: issuerDid,
      credentialSubject: {'id': holderDid, 'name': 'test'},
      issuanceDate: DateTime.now());

  var issuerSigner =
      WalletCredentialSigner(issuer, issuerDid!, 'EdDsa', issuerDid);
  await vc.buildProof(issuerSigner, LdpProofType.ed25519Signature2020);

  var holderSigner =
      WalletCredentialSigner(holder, holderDid, 'ES256', holderDid);
  print(await vc.verify());

  var vp = VerifiablePresentation(
      context: [credentialsV1Iri],
      type: ['VerifiablePresentation'],
      verifiableCredential: [vc]);

  await vp.addProof(holderSigner, LdpProofType.jsonWebSignature2020);

  print(vp.proof);

  print(await vp.verify());
}
