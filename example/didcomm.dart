/*
This Example demonstrates the usage of this library with the following story:
Alice would buy a discounted Annual ticket for the Art museum. She gets the
discount because she is a student at an university. So she has to present
her student card to the museum.
After this the museum issues the Annual Ticket to Alice.

On a high level the process looks like this:

  Alice                                       Museum
     <--request presentation (student-card)-------
     ---presentation (student card)-------------->
     <--propose-credential (annual ticket)--------
     ---request-credential (annual ticket)------->
     <--issue-credential (annual ticket)----------
 */

import 'dart:convert';

import 'package:dart_ssi/credentials.dart';
import 'package:dart_ssi/did.dart';
import 'package:dart_ssi/didcomm.dart';
import 'package:dart_ssi/util.dart';
import 'package:dart_ssi/wallet.dart';
import 'package:json_path/json_path.dart';
import 'package:json_schema/json_schema.dart';
import 'package:uuid/uuid.dart';

void main() async {
  var alice = WalletStore('exampleData/didcomm/alice');
  await alice.openBoxes(password: 'alicePassword');
  await _issueStudentCard(alice);

  var museum = WalletStore('exampleData/didcomm/museum');
  await museum.openBoxes(password: 'museumPassword');
  await museum.initializeIssuer(keyType: KeyType.ed25519);
  await _issueBusinessId(museum);

  // ****** Museum ********
  var museumDid = await museum.generateNewKey(keyType: KeyType.x25519);
  var presentationDefinition =
      PresentationDefinition(id: Uuid().v4(), inputDescriptors: [
    InputDescriptor(
        id: Uuid().v4(),
        name: 'Studentcard-Descriptor',
        constraints: InputDescriptorConstraints(fields: [
          InputDescriptorField(
              path: [JsonPath(r'$.type')],
              filter: JsonSchema.create({
                'type': 'array',
                'contains': {'type': 'string', 'pattern': 'StudentCard'}
              }))
        ])),
  ]);
  var requestPresentationStudentCard =
      RequestPresentation(presentationDefinition: [
    PresentationDefinitionWithOptions(
        domain: 'https://museum-of-modern-art.com',
        challenge: Uuid().v4(),
        presentationDefinition: presentationDefinition)
  ]);
  var oob = OutOfBandMessage(from: museumDid, attachments: [
    Attachment(
        data: AttachmentData(json: requestPresentationStudentCard.toJson()))
  ]);
  var oobUrl = oob.toUrl('http', 'museum-of-modern-art.com', 'somePath');
  print(oob.attachments![0].data.json);
  //This Message is rendered as QR-Code

  // ***** ALICE *****

  //Alice scans the QR-Code and decodes the message
  var decodedOOB = oobMessageFromUrl(oobUrl);
  //Alice resolves the Did-Document of the sender
  var ddoMuseum = await resolveDidDocument(decodedOOB.from!);
  //Alice converts the Did-Document in a form that is easier to use
  ddoMuseum = ddoMuseum.resolveKeyIds();
  ddoMuseum = ddoMuseum.convertAllKeysToJwk();
  // Alice checks the Attachment and notice, that it is request-Presentation Message
  RequestPresentation request;
  try {
    print(decodedOOB.attachments![0].data.json);
    request =
        RequestPresentation.fromJson(decodedOOB.attachments![0].data.json);
  } catch (e) {
    print('This is no RequestPresentation Message');
    throw Exception(e);
  }

  //Alice searches her Wallet for matching credentials
  var allCreds = alice.getAllCredentials();
  List<VerifiableCredential> allW3CCreds = [];
  for (var cred in allCreds.values) {
    if (cred.verifiableCredential != '') {
      allW3CCreds.add(VerifiableCredential.fromJson(cred.verifiableCredential));
    }
  }
  var searchResult = searchCredentialsForPresentationDefinition(
      request.presentationDefinition[0].presentationDefinition,
      credentials: allW3CCreds);

  //Alice realize, that she should show her Student card and build verifiable Presentation out of it
  var presentation = VerifiablePresentation.fromFilterResults(searchResult);
  for (var c in presentation.verifiableCredential!) {
    var did = c.credentialSubject['id'] as String;
    await presentation.addProof(
        WalletCredentialSigner(
            alice, did, 'EdDSA', '$did#${did.split(':').last}'),
        LdpProofType.ed25519Signature2020,
        challenge: request.presentationDefinition[0].challenge);
  }
  print(presentation);
  //Now she puts this in a Presentation Message
  var presentationMessage =
      Presentation(verifiablePresentation: [presentation]);
  //alice generates a did she encrypts the message with
  var connectionDidAlice = await alice.generateNewKey(keyType: KeyType.x25519);
  var encryptedMessage = await presentationMessage.encrypt(
      recipientPublicKeyJwk: [ddoMuseum.keyAgreement![0].publicKeyJwk],
      wallet: alice,
      keyId: connectionDidAlice,
      keyWrapAlgorithm: KeyWrapAlgorithm.ecdhES);

  //This message she could send to the museum

  //***** Museum *******

  //The museum receives the Message. Because its anoncrypted, the museum could encrypt it without looking up a did-Document
  var decrypted = await encryptedMessage.decrypt(wallet: museum);

  //To send message back, the museum looks for the sender in protected Header skid value
  Map<String, dynamic> decodedHeader = jsonDecode(utf8.decode(
      base64Decode(addPaddingToBase64(encryptedMessage.protectedHeader))));
  var senderKid = decodedHeader['skid'];
  var sender = senderKid.split('#')[0];
  print(sender);
  var senderDDO = await resolveDidDocument(sender);
  senderDDO = senderDDO.convertAllKeysToJwk();
  senderDDO = senderDDO.resolveKeyIds();

  //Normally a Wallet has to check which Type it gets here. For this example we know, that it is a plaintext-Massage
  decrypted = decrypted as DidcommPlaintextMessage;
  if (decrypted.type != 'https://didcomm.org/present-proof/3.0/presentation') {
    throw Exception('Presentation Message expected');
  }
  var presentationMessageReceived = Presentation.fromJson(decrypted.toJson());

  //verifyPresentation
  var verified = await presentationMessageReceived.verifiablePresentation.first
      .verify(
          expectedChallenge: requestPresentationStudentCard
              .presentationDefinition.first.challenge);
  if (!verified) throw Exception('Presentation could not been verified');

  //check if the credential inside matches the presentation Definition
  var result = searchCredentialsForPresentationDefinition(
    presentationDefinition,
    credentials: [
      presentationMessageReceived
          .verifiablePresentation[0].verifiableCredential![0]
    ],
  );
  if (result.length != 1) throw Exception('Credential dont match definition');

  //Now the Museum could start the issuance process for the annual ticket
  var museumIssuerDid = museum.getStandardIssuerDid(KeyType.ed25519);
  var credentialSubject = {
    'id': 'did:key:00000',
    'institution': 'Museum of modern Art',
    'ticketType': 'Discounted Annual Ticket'
  };
  var offer = OfferCredential(from: museumDid, detail: [
    LdProofVcDetail(
        credential: VerifiableCredential(
            context: ['https://www.w3.org/2018/credentials/v1', schemaOrgIri],
            type: ['VerifiableCredential', 'AnnualTicket'],
            credentialSubject: credentialSubject,
            issuanceDate: DateTime.now(),
            issuer: museumIssuerDid),
        options: LdProofVcDetailOptions(proofType: 'Ed25519Signature2020'))
  ]);

  var encryptedOffer = await offer.encrypt(
      recipientPublicKeyJwk: [senderDDO.keyAgreement![0].publicKeyJwk],
      wallet: museum,
      keyId: museumDid);

  //This authcrypted Message is sent to alice

  //**** Alice *******
  //Alice decrypts the message (she know, that it is from the museum)
  var decryptedOffer = await encryptedOffer.decrypt(
      wallet: alice,
      senderPublicKeyJwk: ddoMuseum.keyAgreement![0].publicKeyJwk);

  //Here as well we know that it is plaintext Message and has a type of offer-credential
  var receivedOffer = OfferCredential.fromJson(decryptedOffer.toJson());
  //Alice checks, if the did the credential should issued to is controlled by her
  var did = receivedOffer.detail![0].credential.credentialSubject['id'];
  print(did);

  if (!await alice.containsKey(did)) {
    print('I do not control this did');
  }
  // in this case alice must sent a propose credential with a correct did
  var vc = receivedOffer.detail![0].credential;
  var aliceCredDid = await alice.generateNewKey(keyType: KeyType.ed25519);
  vc.credentialSubject['id'] = aliceCredDid;
  var propose = ProposeCredential(from: connectionDidAlice, detail: [
    LdProofVcDetail(credential: vc, options: receivedOffer.detail![0].options)
  ]);

  var encryptedPropose = await propose.encrypt(
      recipientPublicKeyJwk: [ddoMuseum.keyAgreement![0].publicKeyJwk],
      wallet: alice,
      keyId: connectionDidAlice);
  //This message could be sent to the museum

  //***** Museum ****

  //decrypt message and see, that it is an credential propose that do not differ much from the previous offer
  // (not all checking steps are shown here because they are straight forward)
  var decryptedPropose = await encryptedPropose.decrypt(
      wallet: museum,
      senderPublicKeyJwk: senderDDO.keyAgreement![0].publicKeyJwk);
  var receivedPropose = ProposeCredential.fromJson(decryptedPropose.toJson());

  //Therefore the museum construct a offer out of it
  var offer2 = OfferCredential(detail: receivedPropose.detail!);
  //This offer is encrypted like all messages before (not shown to avoid too much duplicated code) and sent to alice

  //**** Alice ****

  //Alice receives the offer and notice, that everything is fine now. So she can construct and send a Request-credential Message
  var requestCredential = RequestCredential(detail: [
    LdProofVcDetail(
        credential: offer2.detail![0].credential,
        options: LdProofVcDetailOptions(
            proofType: 'Ed25519Signature2020', challenge: Uuid().v4()))
  ]);

  //This is encrypted and sent

  //**** Museum ****
  //Takes credential from Request, checks if everything is fine and signs it
  var museumCredentialSigner = WalletCredentialSigner(museum, museumIssuerDid!,
      'EdDSA', '$museumIssuerDid#${museumIssuerDid.split(':').last}');
  var credential = requestCredential.detail![0].credential;
  await credential.sign(
      museumCredentialSigner, LdpProofType.ed25519Signature2020,
      challenge: requestCredential.detail![0].options.challenge);
  print(credential);
  //construct a issue credential message and sent credential to alice
  var issueMessage = IssueCredential(credentials: [credential]);

  //***** Alice *****
  var receivedVC = issueMessage.credentials![0];
  //verify received credential
  print(await receivedVC.verify(
      expectedChallenge: requestCredential.detail![0].options.challenge));

  //store credential
  await alice.storeCredential(
    receivedVC.toString(),
    aliceCredDid,
  );

  //check if two creds are there
  var aliceAllCreds = alice.getAllCredentials();
  print(aliceAllCreds.length);
  print(aliceAllCreds);
}

Future<void> _issueStudentCard(WalletStore wallet) async {
  var someUniversity = WalletStore('example/didcomm/someUniversity');
  await someUniversity.openBoxes(password: 'password');
  await someUniversity.initializeIssuer(keyType: KeyType.ed25519);
  var issuerDid = someUniversity.getStandardIssuerDid(KeyType.ed25519);
  var holderDid = await wallet.generateNewKey(keyType: KeyType.ed25519);

  var studentCard = {
    'id': holderDid,
    'familyName': 'Schmidt',
    'givenName': 'Alice',
    'matriculationNumber': ' 5426745'
  };

  var cred = VerifiableCredential(
      context: ['https://www.w3.org/2018/credentials/v1', schemaOrgIri],
      type: ['VerifiableCredential', 'StudentCard'],
      issuer: issuerDid,
      credentialSubject: studentCard,
      issuanceDate: DateTime.now());

  var signer =
      WalletCredentialSigner(someUniversity, issuerDid!, 'EdDSA', issuerDid);
  await cred.sign(signer, LdpProofType.ed25519Signature2020);
  await wallet.storeCredential(
    cred.toString(),
    holderDid,
  );
}

Future<void> _issueBusinessId(WalletStore wallet) async {
  var someIssuer = WalletStore('example/didcomm/someIssuer');
  await someIssuer.openBoxes(password: 'password');
  await someIssuer.initializeIssuer(keyType: KeyType.ed25519);
  var issuerDid = someIssuer.getStandardIssuerDid(KeyType.ed25519);
  var holderDid = await wallet.generateNewKey(keyType: KeyType.ed25519);

  var businessId = {
    'id': holderDid,
    'name': 'Museum of modern Art',
    'address': {
      'streetAddress': 'Main Street 23',
      'postalCode': '63587',
      'addressLocality': 'Some City'
    }
  };

  var cred = VerifiableCredential(
      context: ['https://www.w3.org/2018/credentials/v1', schemaOrgIri],
      type: ['VerifiableCredential', 'BusinessID'],
      issuer: issuerDid,
      credentialSubject: businessId,
      issuanceDate: DateTime.now());

  var signer =
      WalletCredentialSigner(someIssuer, issuerDid!, 'EdDSA', issuerDid);
  await cred.sign(signer, LdpProofType.ed25519Signature2020);
  await wallet.storeCredential(
    cred.toString(),
    holderDid,
  );
}
