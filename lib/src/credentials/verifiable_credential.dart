import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:base_codecs/base_codecs.dart';
import 'package:crypto/crypto.dart';
import 'package:dart_ssi/did.dart';
import 'package:dart_ssi/oid.dart';
import 'package:dart_ssi/src/credentials/jsonLdContext/json_web_signature_2020_context.dart';
import 'package:json_ld_processor/json_ld_processor.dart';
import 'package:json_path/json_path.dart';
import 'package:sd_jwt/sd_jwt.dart';

import '../../credentials.dart';
import '../util/types.dart';
import '../util/utils.dart';

class VerifiableCredential extends JsonObject {
  late List<dynamic> context;
  String? id;
  late List<String> type;
  dynamic credentialSubject;
  dynamic issuer;
  late DateTime issuanceDate;
  LinkedDataProof? proof;
  DateTime? expirationDate;
  CredentialStatus? status;
  CredentialStatus? credentialSchema;
  String? _issuanceDateString, _expirationDateString;

  VerifiableCredential(
      {required this.context,
      required this.type,
      required this.issuer,
      required this.credentialSubject,
      this.id,
      DateTime? issuanceDate,
      this.status,
      this.credentialSchema,
      this.expirationDate,
      this.proof})
      : issuanceDate = issuanceDate ?? DateTime.now() {
    if (context.first != credentialsV1Iri) {
      throw FormatException(
          'The context-Array must start with $credentialsV1Iri');
    }
    for (var iri in context) {
      if (iri is String) {
        if (!isUri(iri)) {
          throw FormatException('$iri is no valid iri.');
        }
      }
    }
  }

  VerifiableCredential.fromJson(dynamic jsonObject) {
    var credential = credentialToMap(jsonObject);

    if (credential.containsKey('@context')) {
      context = credential['@context'];
    } else {
      throw FormatException(
          '@context property is needed in verifiable credential');
    }

    if (credential.containsKey('type')) {
      type = credential['type'].cast<String>();
    } else {
      throw FormatException('type property is needed in verifiable credential');
    }

    if (credential.containsKey('issuer')) {
      issuer = credential['issuer'];
    } else {
      throw FormatException(
          'issuer property is needed in verifiable credential');
    }

    if (credential.containsKey('credentialSubject')) {
      {
        credentialSubject = credential['credentialSubject'];
        if (credentialSubject is! Map<String, dynamic>) {
          if (credentialSubject is! List) {
            throw FormatException(
                'Credential subject property must be a Map or List (dart json Object)');
          }
        }
      }
    } else {
      throw FormatException(
          'credential subject property is needed in verifiable credential');
    }

    if (credential.containsKey('issuanceDate')) {
      _issuanceDateString = credential['issuanceDate'];
      issuanceDate = DateTime.parse(credential['issuanceDate']);
    } else {
      throw FormatException(
          'issuanceDate property is needed in verifiable credential');
    }

    id = credential['id'];

    if (credential.containsKey('expirationDate')) {
      _expirationDateString = credential['expirationDate'];
      expirationDate = DateTime.parse(credential['expirationDate']);
    }

    if (credential.containsKey('credentialStatus')) {
      status = CredentialStatus.fromJson(credential['credentialStatus']);
    }

    if (credential.containsKey('proof')) {
      proof = LinkedDataProof.fromJson(credential['proof']);
    }

    if (credential.containsKey('credentialSchema')) {
      credentialSchema =
          CredentialStatus.fromJson(credential['credentialSchema']);
    }
  }

  @override
  Map<String, dynamic> toJson() {
    Map<String, dynamic> jsonObject = _serializeWithoutProof();
    if (proof != null) jsonObject['proof'] = proof!.toJson();

    return jsonObject;
  }

  bool isOfSameType(VerifiableCredential other) {
    if (credentialSchema != null && other.credentialSchema != null) {
      return credentialSchema!.type == other.credentialSchema!.type &&
          credentialSchema!.id == other.credentialSchema!.id;
    } else {
      for (String typeValue in type) {
        if (!other.type.contains(typeValue)) return false;
      }
      return true;
    }
  }

  bool isSelfIssued() {
    if (issuer is String && credentialSubject is String) {
      return issuer == credentialSubject;
    } else if (issuer is String && credentialSubject is Map) {
      return issuer == credentialSubject['id'];
    } else if (issuer is Map && credentialSubject is String) {
      return issuer['id'] == credentialSubject;
    } else if (issuer is Map && credentialSubject is Map) {
      return issuer['id'] == credentialSubject['id'];
    } else {
      return false;
    }
  }

  Map<String, dynamic> _serializeWithoutProof() {
    Map<String, dynamic> jsonObject = {};
    jsonObject['@context'] = context;
    if (id != null) jsonObject['id'] = id;
    jsonObject['type'] = type;
    jsonObject['credentialSubject'] = credentialSubject;
    jsonObject['issuer'] = issuer;
    jsonObject['issuanceDate'] = _issuanceDateString ?? toXmlDate(issuanceDate);
    if (expirationDate != null) {
      jsonObject['expirationDate'] =
          _expirationDateString ?? toXmlDate(expirationDate!);
    }
    if (status != null) jsonObject['credentialStatus'] = status!.toJson();
    if (credentialSchema != null) {
      jsonObject['credentialSchema'] = credentialSchema!.toJson();
    }

    return jsonObject;
  }

  Future<List<int>> _generateSigningInput(LinkedDataProof proofOptions,
      Function(Uri url, LoadDocumentOptions? options) loadDocument) async {
    var normalizedData = await JsonLdProcessor.normalize(
        _serializeWithoutProof(),
        options: JsonLdOptions(documentLoader: loadDocument, safeMode: true));
    var hashedData = sha256.convert(utf8.encode(normalizedData)).bytes;

    var hashedProofOptions = sha256
        .convert(utf8.encode(await JsonLdProcessor.normalize(
            proofOptions.toJson(),
            options:
                JsonLdOptions(documentLoader: loadDocument, safeMode: true))))
        .bytes;

    return hashedProofOptions + hashedData;
  }

  FutureOr<void> sign(CredentialSigner signer, LdpProofType proofType,
      {String? challenge,
      String proofPurpose = 'assertionMethod',
      Function(Uri url, LoadDocumentOptions? options) loadDocument =
          loadDocumentStrict}) async {
    if (proofType == LdpProofType.ed25519Signature2020 &&
        !(context.contains(ed25519ContextIri))) {
      context.add(ed25519ContextIri);
    }
    if (proofType == LdpProofType.jsonWebSignature2020 &&
        !(context.contains(jsonWebSignature2020ContextIri))) {
      context.add(jsonWebSignature2020ContextIri);
    }

    var proofOptions = LinkedDataProof(
        type: proofType.value,
        proofPurpose: proofPurpose,
        verificationMethod: signer.verificationMethod,
        created: DateTime.now(),
        challenge: challenge,
        context: proofType == LdpProofType.ed25519Signature2020
            ? [ed25519ContextIri]
            : [jsonWebSignature2020ContextIri]);

    var signingInput = await _generateSigningInput(proofOptions, loadDocument);
    if (proofType == LdpProofType.jsonWebSignature2020) {
      var critical = <String, dynamic>{};
      critical['b64'] = false;
      var header = JwsJoseHeader(
          algorithm: SigningAlgorithm.eddsa25519Sha512,
          critical: ['b64'],
          additionalParameters: {'b64': false});

      var headerEnc = removePaddingFromBase64(
          base64UrlEncode(utf8.encode(jsonEncode(header.toJson()))));

      signingInput = utf8.encode('$headerEnc.') + signingInput;
    }

    var signature = await signer.sign(Uint8List.fromList(signingInput));

    proofOptions.context = null;
    if (proofType == LdpProofType.ed25519Signature2020) {
      proofOptions.proofValue = 'z${base58BitcoinEncode(signature)}';
    } else {
      var header = JwsJoseHeader(
          algorithm: SigningAlgorithm.eddsa25519Sha512,
          critical: ['b64'],
          additionalParameters: {'b64': false});

      var headerEnc = removePaddingFromBase64(
          base64UrlEncode(utf8.encode(jsonEncode(header.toJson()))));
      proofOptions.jws = '$headerEnc.'
          '.${base64UrlEncode(signature)}';
    }

    proof = proofOptions;
  }

  FutureOr<bool> verify(
      {String? expectedChallenge,
      Function(Uri url, LoadDocumentOptions? options) loadDocument =
          loadDocumentStrict}) async {
    if (proof == null) {
      throw Exception('No proof to verify');
    }

    var proofOptions = LinkedDataProof.fromJson(proof!.toJson());
    proofOptions.proofValue = null;
    proofOptions.jws = null;
    proofOptions.context = proof!.context != null && proof!.context!.isNotEmpty
        ? proof!.context
        : (proof!.type == LdpProofType.ed25519Signature2020.value
            ? [ed25519ContextIri]
            : [jsonWebSignature2020ContextIri]);
    // LinkedDataProof(
    //     challenge: proof!.challenge,
    //     domain: proof!.domain,
    //     type: proof!.type,
    //     proofPurpose: proof!.proofPurpose,
    //     verificationMethod: proof!.verificationMethod,
    //     created: proof!.createdString,
    //     context: proof!.context != null && proof!.context!.isNotEmpty
    //         ? proof!.context
    //         : (proof!.type == LdpProofType.ed25519Signature2020.value
    //             ? [ed25519ContextIri]
    //             : [jsonWebSignature2020ContextIri]));

    var signingInput = await _generateSigningInput(proofOptions, loadDocument);
    Uint8List signature;

    if (proofOptions.type == LdpProofType.jsonWebSignature2020.value) {
      if (proof!.jws == null) {
        throw Exception('Proof value missing');
      }
      var header = proof!.jws!.split('.').first;
      var decodedHeader =
          jsonDecode(utf8.decode(base64Decode(addPaddingToBase64(header))));
      var alg = decodedHeader['alg'];
      if (alg == null || alg is! String) {
        throw Exception('alg Header missing in jws-header');
      }

      signingInput = ascii.encode('$header.') + signingInput;
      signature = Uint8List.fromList(
          base64Decode(addPaddingToBase64(proof!.jws!.split('.').last)));
    } else {
      if (proof!.proofValue == null) {
        throw Exception('Proof value missing');
      }

      signature = base58BitcoinDecode(proof!.proofValue!.substring(1));
    }

    var did = proofOptions.verificationMethod.split('#').first;
    var ddo = await resolveDidDocument(did);
    ddo = ddo.resolveKeyIds().convertAllKeysToJwk();
    Jwk? jwk;
    for (var k in ddo.verificationMethod ?? <VerificationMethod>[]) {
      if (k.id == proofOptions.verificationMethod) {
        jwk = Jwk.fromJson(k.publicKeyJwk!);
        break;
      }
    }
    if (jwk == null) {
      throw Exception('Cannot find public key');
    }

    var verifier = JwkCredentialSigner(jwk);
    return verifier.verify(Uint8List.fromList(signingInput), signature);
  }
}

enum LdpProofType {
  ed25519Signature2020,
  jsonWebSignature2020;

  static const Map<LdpProofType, String> stringValues = {
    LdpProofType.ed25519Signature2020: 'Ed25519Signature2020',
    LdpProofType.jsonWebSignature2020: 'JsonWebSignature2020',
  };
  String get value => stringValues[this]!;
}

class LinkedDataProof extends JsonObject {
  late String type;
  late String proofPurpose;
  late String verificationMethod;
  late DateTime created;
  List<String>? context;
  String? proofValue;
  String? challenge;
  String? jws;
  String? domain;
  String? _createdString;

  LinkedDataProof(
      {required this.type,
      required this.proofPurpose,
      required this.verificationMethod,
      required this.created,
      this.proofValue,
      this.challenge,
      this.jws,
      this.domain,
      this.context});

  LinkedDataProof.fromJson(dynamic jsonObject) {
    var proof = credentialToMap(jsonObject);
    if (proof.containsKey('type')) {
      type = proof['type'];
    } else {
      throw FormatException('Type property is needed in proof object');
    }

    if (proof.containsKey('proofPurpose')) {
      proofPurpose = proof['proofPurpose'];
    } else {
      throw FormatException('proofPurpose property is needed in proof object');
    }

    if (proof.containsKey('verificationMethod')) {
      verificationMethod = proof['verificationMethod'];
    } else {
      throw FormatException('verification Method is needed in proof object');
    }

    if (proof.containsKey('created')) {
      _createdString = proof['created'];
      created = DateTime.parse(proof['created']);
    } else {
      throw FormatException('created is needed in proof object');
    }

    proofValue = proof['proofValue'];
    jws = proof['jws'];
    if (jws == null && proofValue == null) {
      throw FormatException('one of proofValue or jws must be present');
    }

    domain = proof['domain'];
    challenge = proof['challenge'];
  }

  String get createdString => _createdString ?? toXmlDate(created);

  @override
  Map<String, dynamic> toJson() {
    Map<String, dynamic> jsonObject = {};
    if (context != null) {
      jsonObject['@context'] = context!.length == 1 ? context!.first : context;
    }
    jsonObject['type'] = type;
    jsonObject['proofPurpose'] = proofPurpose;
    jsonObject['verificationMethod'] = verificationMethod;

    jsonObject['created'] = _createdString ?? toXmlDate(created);

    if (domain != null) jsonObject['domain'] = domain;
    if (challenge != null) jsonObject['challenge'] = challenge;
    if (proofValue != null) jsonObject['proofValue'] = proofValue;
    if (jws != null) jsonObject['jws'] = jws;
    return jsonObject;
  }
}

class CredentialStatus extends JsonObject {
  String id;
  String type;

  CredentialStatus(this.id, this.type);

  factory CredentialStatus.fromJson(dynamic jsonObject) {
    var status = credentialToMap(jsonObject);
    String id;
    if (status.containsKey('id')) {
      id = status['id'];
    } else {
      throw FormatException('id property is needed in Credential Status');
    }
    String type;
    if (status.containsKey('type')) {
      type = status['type'];
    } else {
      throw FormatException('type property is needed in credentialStatus');
    }

    if (type == 'RevocationList2020Status') {
      return RevocationList2020Status.fromJson(jsonObject);
    } else if (type == 'StatusList2021Entry') {
      return StatusList2021Entry.fromJson(jsonObject);
    } else {
      return CredentialStatus(id, type);
    }
  }

  FutureOr<bool> isRevoked(VerifiableCredential credential) {
    throw UnimplementedError();
  }

  @override
  Map<String, dynamic> toJson() {
    Map<String, dynamic> jsonObject = {};
    jsonObject['id'] = id;
    jsonObject['type'] = type;
    return jsonObject;
  }
}

//****** Presentation ******
class VerifiablePresentation extends JsonObject {
  late List<String> context;
  String? id;
  late List<String> type;
  List<VerifiableCredential>? verifiableCredential;
  String? holder;
  List<LinkedDataProof>? proof;
  PresentationSubmission? presentationSubmission;
  CredentialFulfillment? credentialFulfillment;
  CredentialApplication? credentialApplication;

  VerifiablePresentation(
      {List<String>? context,
      List<String>? type,
      this.verifiableCredential,
      this.id,
      this.holder,
      this.proof,
      this.presentationSubmission,
      this.credentialFulfillment,
      this.credentialApplication})
      : context = context ?? [credentialsV1Iri],
        type = type ?? ['VerifiablePresentation'] {
    if (presentationSubmission != null) {
      this.type.add('PresentationSubmission');
      this.context.add(presentationSubmissionContextIri);
    }
  }

  VerifiablePresentation.fromJson(dynamic jsonObject) {
    var presentation = credentialToMap(jsonObject);
    if (presentation.containsKey('@context')) {
      context = presentation['@context'].cast<String>();
    } else {
      throw FormatException(
          'context property is needed in verifiable presentation');
    }
    if (presentation.containsKey('type')) {
      type = presentation['type'].cast<String>();
    } else {
      throw FormatException(
          'type property is needed in verifiable presentation');
    }
    if (presentation.containsKey('verifiableCredential')) {
      verifiableCredential = [];
      List tmp = presentation['verifiableCredential'];
      for (var c in tmp) {
        verifiableCredential!.add(VerifiableCredential.fromJson(c));
      }
    }

    id = presentation['id'];
    holder = presentation['holder'];
    if (presentation.containsKey('proof')) {
      proof = [];
      var tmp = presentation['proof'];
      if (tmp is List) {
        for (var c in tmp) {
          proof!.add(LinkedDataProof.fromJson(c));
        }
      } else if (tmp is Map) {
        proof!.add(LinkedDataProof.fromJson(tmp));
      }
    }

    if (presentation.containsKey('presentation_submission')) {
      var tmp = presentation['presentation_submission'];
      presentationSubmission = PresentationSubmission.fromJson(tmp);
    }

    if (presentation.containsKey('credential_fulfillment')) {
      credentialFulfillment = CredentialFulfillment.fromJson(
          presentation['credential_fulfillment']);
    }

    if (presentation.containsKey('credential_application')) {
      credentialApplication = CredentialApplication.fromJson(
          presentation['credential_application']);
    }
  }

  factory VerifiablePresentation.fromFilterResults(
      List<FilterResult> filterResults) {
    List<InputDescriptorMappingObject> mapping = [];
    List<VerifiableCredential> vc = [];

    int index = 0;
    for (var result in filterResults) {
      if (result.credentials != null) {
        vc.addAll(result.credentials!);
        for (var _ in result.credentials!) {
          for (var descriptorId in result.matchingDescriptorIds) {
            mapping.add(InputDescriptorMappingObject(
                id: descriptorId,
                format: OidCredentialFormat.ldpVc,
                path: JsonPath('\$.verifiableCredential[$index]')));
          }
          index++;
        }
      } else {
        continue;
      }
    }

    return VerifiablePresentation(
        verifiableCredential: vc,
        presentationSubmission: PresentationSubmission(
            presentationDefinitionId:
                filterResults.first.presentationDefinitionId,
            descriptorMap: mapping));
  }

  Future<List<int>> _hashData(
      Function(Uri url, LoadDocumentOptions? options) loadDocument) async {
    var normalizedData = await JsonLdProcessor.normalize(
        _serializeWithoutProof(),
        options: JsonLdOptions(documentLoader: loadDocument, safeMode: true));
    var hashedData = sha256.convert(utf8.encode(normalizedData)).bytes;
    return hashedData;
  }

  Future<List<int>> _hashProofOptions(LinkedDataProof proofOptions,
      Function(Uri url, LoadDocumentOptions? options) loadDocument) async {
    var hashedProofOptions = sha256
        .convert(utf8.encode(await JsonLdProcessor.normalize(
            proofOptions.toJson(),
            options:
                JsonLdOptions(documentLoader: loadDocument, safeMode: true))))
        .bytes;

    return hashedProofOptions;
  }

  FutureOr<void> addProof(CredentialSigner signer, LdpProofType proofType,
      {String? challenge,
      String? domain,
      String proofPurpose = 'authentication',
      Function(Uri url, LoadDocumentOptions? options) loadDocument =
          loadDocumentStrict}) async {
    if (proofType == LdpProofType.ed25519Signature2020 &&
        !(context.contains(ed25519ContextIri))) {
      context.add(ed25519ContextIri);
    }
    if (proofType == LdpProofType.jsonWebSignature2020 &&
        !(context.contains(jsonWebSignature2020ContextIri))) {
      context.add(jsonWebSignature2020ContextIri);
    }

    var proofOptions = LinkedDataProof(
        type: proofType.value,
        proofPurpose: proofPurpose,
        domain: domain,
        verificationMethod: signer.verificationMethod,
        created: DateTime.now(),
        challenge: challenge,
        context: proofType == LdpProofType.ed25519Signature2020
            ? [ed25519ContextIri]
            : [jsonWebSignature2020ContextIri]);

    var signingInput = (await _hashProofOptions(proofOptions, loadDocument)) +
        (await _hashData(loadDocument));
    if (proofType == LdpProofType.jsonWebSignature2020) {
      var header = JwsJoseHeader(
          algorithm: SigningAlgorithm.eddsa25519Sha512,
          critical: ['b64'],
          additionalParameters: {'b64': false});

      var headerEnc = removePaddingFromBase64(
          base64UrlEncode(utf8.encode(jsonEncode(header.toJson()))));
      signingInput = utf8.encode('$headerEnc.') + signingInput;
    }

    var signature = await signer.sign(Uint8List.fromList(signingInput));

    proofOptions.context = null;
    if (proofType == LdpProofType.ed25519Signature2020) {
      proofOptions.proofValue = 'z${base58BitcoinEncode(signature)}';
    } else {
      var header = JwsJoseHeader(
          algorithm: SigningAlgorithm.eddsa25519Sha512,
          critical: ['b64'],
          additionalParameters: {'b64': false});

      var headerEnc = removePaddingFromBase64(
          base64UrlEncode(utf8.encode(jsonEncode(header.toJson()))));
      proofOptions.jws = '$headerEnc.'
          '.${base64UrlEncode(signature)}';
    }

    proof ??= [];
    proof!.add(proofOptions);
  }

  FutureOr<bool> verify(
      {String? expectedChallenge,
      Function(Uri url, LoadDocumentOptions? options) loadDocument =
          loadDocumentStrict}) async {
    if (proof == null || proof!.isEmpty) {
      throw Exception('No proof to verify');
    }

    var dataHash = await _hashData(loadDocument);

    for (var p in proof!) {
      var proofOptions = LinkedDataProof.fromJson(p.toJson());
      proofOptions.proofValue = null;
      proofOptions.jws = null;
      proofOptions.context = p.context != null && p.context!.isNotEmpty
          ? p.context
          : (p.type == LdpProofType.ed25519Signature2020.value
              ? [ed25519ContextIri]
              : [jsonWebSignature2020ContextIri]);

      var signingInput =
          (await _hashProofOptions(proofOptions, loadDocument)) + dataHash;
      Uint8List signature;

      if (proofOptions.type == LdpProofType.jsonWebSignature2020.value) {
        if (p.jws == null) {
          throw Exception('Proof value missing');
        }
        var header = p.jws!.split('.').first;
        var decodedHeader =
            jsonDecode(utf8.decode(base64Decode(addPaddingToBase64(header))));
        var alg = decodedHeader['alg'];
        if (alg == null || alg is! String) {
          throw Exception('alg Header missing in jws-header');
        }

        signingInput = ascii.encode('$header.') + signingInput;
        signature = Uint8List.fromList(
            base64Decode(addPaddingToBase64(p.jws!.split('.').last)));
      } else {
        if (p.proofValue == null) {
          throw Exception('Proof value missing');
        }

        signature = base58BitcoinDecode(p.proofValue!.substring(1));
      }

      var did = proofOptions.verificationMethod.split('#').first;
      var ddo = await resolveDidDocument(did);
      ddo = ddo.resolveKeyIds().convertAllKeysToJwk();
      var jwk = Jwk.fromJson(ddo.verificationMethod!.first.publicKeyJwk!);

      var verifier = JwkCredentialSigner(jwk);
      if (!(await verifier.verify(
          Uint8List.fromList(signingInput), signature))) {
        return false;
      }
    }
    return true;
  }

  Map<String, dynamic> _serializeWithoutProof() {
    Map<String, dynamic> jsonObject = {};
    jsonObject['@context'] = context;
    jsonObject['type'] = type;
    if (verifiableCredential != null) {
      List tmp = [];
      for (var c in verifiableCredential!) {
        tmp.add(c.toJson());
      }
      jsonObject['verifiableCredential'] = tmp;
    }
    if (id != null) jsonObject['id'] = id;
    if (holder != null) jsonObject['holder'] = holder;
    if (presentationSubmission != null) {
      jsonObject['presentation_submission'] = presentationSubmission!.toJson();
    }
    if (credentialFulfillment != null) {
      jsonObject['credential_fulfillment'] = credentialFulfillment!.toJson();
    }
    if (credentialApplication != null) {
      jsonObject['credential_application'] = credentialApplication!.toJson();
    }
    return jsonObject;
  }

  @override
  Map<String, dynamic> toJson() {
    Map<String, dynamic> jsonObject = _serializeWithoutProof();
    if (proof != null) {
      List tmp = [];
      for (var p in proof!) {
        tmp.add(p.toJson());
      }
      jsonObject['proof'] = tmp;
    }
    return jsonObject;
  }
}
