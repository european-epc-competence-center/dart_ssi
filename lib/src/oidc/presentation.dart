import 'dart:convert';

import 'package:dart_ssi/credentials.dart';
import 'package:dart_ssi/src/util/types.dart';
import 'package:dart_ssi/src/util/utils.dart';

class RequestObject implements JsonObject {
  String? responseType;
  String? responseUri;
  String? clientId;
  String? responseMode;
  String? redirectUri;
  String? nonce, state;
  String? clientMetaDataUri;
  PresentationDefinition? presentationDefinition;
  String? presentationDefinitionUri;
  ClientMetaData? clientMetaData;

  RequestObject(
      {this.clientId,
      this.responseUri,
      this.nonce,
      this.state,
      this.redirectUri,
      this.responseMode,
      this.responseType,
      this.presentationDefinition,
      this.clientMetaData,
      this.clientMetaDataUri,
      this.presentationDefinitionUri});

  RequestObject.fromJson(dynamic data) {
    var jsonObject = credentialToMap(data);

    responseType = jsonObject['response_type'];
    clientId = jsonObject['client_id'];
    responseMode = jsonObject['response_mode'];
    redirectUri = jsonObject['redirect_uri'];
    nonce = jsonObject['nonce'];
    presentationDefinitionUri = jsonObject['presentation_definition_uri'];
    clientMetaDataUri = jsonObject['client_metadata_uri'];
    responseUri = jsonObject['response_uri'];
    state = jsonObject['state'];

    if (jsonObject.containsKey('presentation_definition')) {
      presentationDefinition = PresentationDefinition.fromJson(
          jsonObject['presentation_definition']);
    }

    if (jsonObject.containsKey('client_metadata')) {
      clientMetaData = ClientMetaData.fromJson(jsonObject['client_metadata']);
    }
  }

  @override
  Map<String, dynamic> toJson() {
    Map<String, dynamic> jsonObject = {};
    if (clientId != null) {
      jsonObject['client_id'] = clientId;
    }
    if (responseType != null) {
      jsonObject['response_type'] = responseType;
    }
    if (responseUri != null) {
      jsonObject['response_uri'] = responseUri;
    }
    if (responseMode != null) {
      jsonObject['response_mode'] = responseMode;
    }

    if (redirectUri != null) {
      jsonObject['redirect_uri'] = redirectUri;
    }
    if (nonce != null) {
      jsonObject['nonce'] = nonce;
    }
    if (state != null) {
      jsonObject['state'] = state;
    }
    if (presentationDefinitionUri != null) {
      jsonObject['presentation_definition_uri'] = presentationDefinitionUri;
    }
    if (presentationDefinition != null) {
      jsonObject['presentation_definition'] = presentationDefinition!.toJson();
    }

    if (clientMetaData != null) {
      jsonObject['client_metadata'] = clientMetaData!.toJson();
    }
    if (clientMetaDataUri != null) {
      jsonObject['client_metadata_uri'] = clientMetaDataUri;
    }
    return jsonObject;
  }

  @override
  String toString() {
    return jsonEncode(toJson());
  }
}

class ClientMetaData implements JsonObject {
  List<Map<String, dynamic>>? jwks;
  String? jwksUri;
  String? authEncryptedResponseAlg,
      authEncryptedResponseEnc,
      authSignedResponseAlg;
  FormatProperty? vpFormats;

  ClientMetaData(
      {this.jwks,
      this.jwksUri,
      this.authEncryptedResponseAlg,
      this.authEncryptedResponseEnc,
      this.authSignedResponseAlg});

  ClientMetaData.fromJson(dynamic data) {
    var jsonData = credentialToMap(data);
    if (jsonData.containsKey('jwks')) {
      var tmp = jsonData['jwks'] as Map;
      var keys = tmp['keys'] as List<Map>;
      jwks = keys
          .map((e) => e.map((key, value) => MapEntry(key as String, value)))
          .toList();
    }

    if (jsonData.containsKey('jwks_uri')) {
      jwksUri = jsonData['jwks_uri'];
    }

    if (jsonData.containsKey('authorization_encrypted_response_alg')) {
      authEncryptedResponseAlg =
          jsonData['authorization_encrypted_response_alg'];
    }

    if (jsonData.containsKey('authorization_encrypted_response_enc')) {
      authEncryptedResponseEnc =
          jsonData['authorization_encrypted_response_enc'];
    }

    if (jsonData.containsKey('authorization_signed_response_alg')) {
      authSignedResponseAlg = jsonData['authorization_signed_response_alg'];
    }

    if (jsonData.containsKey('vp_formats')) {
      vpFormats = FormatProperty.fromJson(jsonData['vp_formats']);
    }
  }
  @override
  Map<String, dynamic> toJson() {
    var json = <String, dynamic>{};

    if (jwks != null) {
      json['jwks'] = {'keys': jwks};
    }
    if (jwksUri != null) {
      json['jwks_uri'] = jwksUri;
    }

    if (authEncryptedResponseEnc != null) {
      json['authorization_encrypted_response_enc'] = authEncryptedResponseEnc;
    }
    if (authEncryptedResponseAlg != null) {
      json['authorization_encrypted_response_alg'] = authEncryptedResponseAlg;
    }
    if (authSignedResponseAlg != null) {
      json['authorization_signed_response_alg'] = authSignedResponseAlg;
    }

    if (vpFormats != null) {
      json['vp_formats'] = vpFormats!.toJson();
    }

    return json;
  }

  @override
  String toString() {
    return jsonEncode(toJson());
  }
}
