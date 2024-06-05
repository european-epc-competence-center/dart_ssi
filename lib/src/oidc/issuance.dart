import 'dart:convert';

import '../util/types.dart';
import '../util/utils.dart';

class OidcCredentialOffer implements JsonObject {
  late String credentialIssuer;
  // draft 12: List of configuration ids; Draft 11 either configurationId or CredentialsSupportedObject
  List<dynamic>? credentials;

  /// Required in draft 13
  List<String>? credentialConfigurationIds;
  Map<String, GrantType>? grants;

  OidcCredentialOffer({
    required this.credentialIssuer,
    this.credentials,
    this.credentialConfigurationIds,
    this.grants,
  });

  OidcCredentialOffer.fromJson(dynamic data) {
    _parseJson(data);
  }

  OidcCredentialOffer.fromUri(String uri) {
    var asUri = Uri.parse(uri);
    var offer = asUri.queryParameters['credential_offer'];
    _parseJson(offer);
  }

  void _parseJson(dynamic data) {
    var jsonObject = credentialToMap(data);
    if (jsonObject.containsKey('credential_issuer')) {
      credentialIssuer = jsonObject['credential_issuer'];
    } else {
      throw Exception(
          'credential_issuer property is needed in OpenId Connect 4VC CredentialOffer');
    }

    if (jsonObject.containsKey('credentials')) {
      List tmp = jsonObject['credentials'];
      credentials = [];
      for (var o in tmp) {
        if (o is String) {
          credentials!.add(o);
        } else {
          credentials!.add(CredentialsSupportedObject.fromJson(o));
        }
      }
    }

    if (jsonObject.containsKey('credential_configuration_ids')) {
      credentialConfigurationIds =
          (jsonObject['credential_configuration_ids'] as List).cast<String>();
    }

    if (jsonObject.containsKey('grants')) {
      var grantsTmp = jsonObject['grants'] as Map<String, dynamic>;
      grants = grantsTmp.map((key, value) =>
          MapEntry(key, GrantType.fromTypeAndJson(key, value as Map)));
    }
  }

  @override
  Map<String, dynamic> toJson() {
    Map<String, dynamic> jsonObject = {'credential_issuer': credentialIssuer};

    if (credentialConfigurationIds != null) {
      jsonObject['credential_configuration_ids'] = credentialConfigurationIds;
    }

    if (credentials != null) {
      List tmp = [];
      for (var o in credentials!) {
        if (o is String) {
          tmp.add(o);
        } else {
          tmp.add(o.toJson());
        }
      }
      jsonObject['credentials'] = tmp;
    }

    if (grants != null) {
      jsonObject['grants'] =
          grants!.map((key, value) => MapEntry(key, value.toJson()));
    }

    return jsonObject;
  }

  @override
  String toString() {
    return jsonEncode(toJson());
  }
}

abstract class GrantType implements JsonObject {
  String get grantType;
  static final String preAuthType =
      'urn:ietf:params:oauth:grant-type:pre-authorized_code';
  static final String authType = 'authorization_code';

  GrantType();

  factory GrantType.fromTypeAndJson(String type, Map json) {
    if (type == authType) {
      return AuthorizationCodeGrant.fromJson(json);
    } else if (type == preAuthType) {
      return PreAuthCodeGrant.fromJson(json);
    } else {
      return UnsupportedGrant(
          grantType: type,
          values: json.map((key, value) => MapEntry(key as String, value)));
    }
  }
}

class UnsupportedGrant extends GrantType {
  @override
  String grantType;
  Map<String, dynamic> values;

  UnsupportedGrant({required this.grantType, required this.values});

  @override
  Map<String, dynamic> toJson() {
    return values;
  }

  @override
  String toString() {
    return jsonEncode(toJson());
  }
}

class AuthorizationCodeGrant extends GrantType {
  @override
  final String grantType = 'authorization_code';
  String? issuerState, authorizationServer;

  AuthorizationCodeGrant({this.authorizationServer, this.issuerState});

  AuthorizationCodeGrant.fromJson(dynamic json) {
    var tmp = credentialToMap(json);
    issuerState = tmp['issuer_state'];
    authorizationServer = tmp['authorization_server'];
  }
  @override
  Map<String, dynamic> toJson() {
    Map<String, dynamic> jsonObject = {};
    if (issuerState != null) {
      jsonObject['issuer_state'] = issuerState;
    }
    if (authorizationServer != null) {
      jsonObject['authorization_server'] = authorizationServer;
    }
    return jsonObject;
  }

  @override
  String toString() {
    return jsonEncode(toJson());
  }
}

class PreAuthCodeGrant extends GrantType {
  @override
  final String grantType =
      'urn:ietf:params:oauth:grant-type:pre-authorized_code';
  late String preAuthCode;

  /// This is for backwards compatibility with draft 11 and 12, where user_pin_required was used
  bool? txCode;
  String? txCodeInputMethod, txCodeDescription;
  int? txCodeLength;
  int? interval;
  String? authorizationServer;

  PreAuthCodeGrant(
      {required this.preAuthCode,
      this.txCodeDescription,
      this.authorizationServer,
      this.interval,
      this.txCode,
      this.txCodeInputMethod,
      this.txCodeLength});

  PreAuthCodeGrant.fromJson(dynamic json) {
    var tmp = credentialToMap(json);

    if (tmp.containsKey('pre-authorized_code')) {
      preAuthCode = tmp['pre-authorized_code'];
    } else {
      throw Exception('pre-auth code required');
    }

    authorizationServer = tmp['authorization_server'];
    interval = tmp['interval'];

    if (tmp.containsKey('tx_code')) {
      txCode = true;
      Map txCodeDetails = tmp['tx_code'];
      txCodeInputMethod = txCodeDetails['input_mode'];
      txCodeLength = txCodeDetails['length'];
      txCodeDescription = txCodeDetails['description'];
    } else {
      txCode = false;
    }

    if (tmp.containsKey('user_pin_required')) {
      txCode = tmp['user_pin_required'];
    } else {
      txCode ??= false;
    }
  }

  @override
  Map<String, dynamic> toJson() {
    Map<String, dynamic> json = {'pre-authorized_code': preAuthCode};
    if (authorizationServer != null) {
      json['authorization_server'] = authorizationServer;
    }
    if (interval != null) {
      json['interval'] = interval;
    }
    if (txCode != null) {
      if (txCode! ||
          txCodeDescription != null ||
          txCodeLength != null ||
          txCodeInputMethod != null) {
        var txMap = {};
        if (txCodeInputMethod != null) {
          txMap['input_mode'] = txCodeInputMethod;
        }
        if (txCodeLength != null) {
          txMap['length'] = txCodeLength;
        }
        if (txCodeDescription != null) {
          txMap['description'] = txCodeDescription;
        }

        json['tx_code'] = txMap;
      }
    }

    return json;
  }

  @override
  String toString() {
    return jsonEncode(toJson());
  }
}

class AuthorizationDetailsObject implements JsonObject {
  final String type = 'openid_credential';
  String? credentialConfigurationId;
  String? format;
  List<String>? credentialIdentifiers;
  // Common Data fields per RFC 9396 Sec 2.2
  List<String>? locations, actions, dataTypes, privileges;
  String? identifier;
  //credential specific
  List<String>? credentialType;
  Map<String, dynamic>? claims;
  List<String>? context;

  AuthorizationDetailsObject(
      {this.format,
      this.credentialConfigurationId,
      this.credentialIdentifiers,
      this.actions,
      this.dataTypes,
      this.identifier,
      this.locations,
      this.privileges,
      this.context,
      this.claims,
      this.credentialType});

  factory AuthorizationDetailsObject.fromJson(dynamic data) {
    var jsonObject = credentialToMap(data);
    var type = jsonObject['type'];
    if (type != 'openid_credential') {
      throw Exception('Unexpected type $type in Authorization details object');
    }

    var configId = jsonObject['credential_configuration_id'];
    var format = jsonObject['format'];

    List? actions = jsonObject['actions'],
        locations = jsonObject['locations'],
        dataTypes = jsonObject['datatypes'],
        privileges = jsonObject['privileges'];
    String? id = jsonObject['identifier'];

    List<String>? credentialIdentifiers;
    if (jsonObject.containsKey('credential_identifiers')) {
      credentialIdentifiers =
          (jsonObject['credential_identifiers'] as List).cast<String>();
    }
    if (format == OidcCredentialFormat.ldpVc ||
        format == OidcCredentialFormat.jwtVcJsonLd) {
      Map definition = jsonObject['credential_definition'];
      List? context = definition['@context'];
      List? vcType = definition['type'] ?? definition['types'];
      Map<String, dynamic>? subject;
      if (definition.containsKey('credentialSubject')) {
        subject = _parseStuff(definition['credentialSubject']);
      }

      return AuthorizationDetailsObject(
          format: format,
          context: context?.cast<String>(),
          credentialType: vcType?.cast<String>(),
          claims: subject,
          credentialIdentifiers: credentialIdentifiers,
          actions: actions?.cast<String>(),
          dataTypes: dataTypes?.cast<String>(),
          identifier: id,
          locations: locations?.cast<String>(),
          privileges: privileges?.cast<String>());
    } else if (format == OidcCredentialFormat.jwtVcJson) {
      Map definition = jsonObject['credential_definition'];
      List? vcType = definition['type'] ?? definition['types'];
      Map<String, dynamic>? subject;
      if (definition.containsKey('credentialSubject')) {
        subject = _parseStuff(definition['credentialSubject']);
      }
      return AuthorizationDetailsObject(
          format: format,
          credentialType: vcType?.cast<String>(),
          claims: subject,
          credentialIdentifiers: credentialIdentifiers,
          actions: actions?.cast<String>(),
          dataTypes: dataTypes?.cast<String>(),
          identifier: id,
          locations: locations?.cast<String>(),
          privileges: privileges?.cast<String>());
    } else if (format == OidcCredentialFormat.msoMdoc) {
      String? doctype = jsonObject['doctype'];
      Map<String, Map<String, CredentialSubjectMetadata>>? claims;
      if (jsonObject.containsKey('claims')) {
        Map tmp = jsonObject['claims'];
        claims = tmp.map((key, value) => MapEntry(
            key as String,
            (value as Map).map((key, value) => MapEntry(
                key as String, CredentialSubjectMetadata.fromJson(value)))));
      }

      return AuthorizationDetailsObject(
          format: format,
          claims: claims,
          credentialType: doctype == null ? null : [doctype],
          credentialIdentifiers: credentialIdentifiers,
          actions: actions?.cast<String>(),
          dataTypes: dataTypes?.cast<String>(),
          identifier: id,
          locations: locations?.cast<String>(),
          privileges: privileges?.cast<String>());
    } else if (format == OidcCredentialFormat.sdJwt) {
      String vct = jsonObject['vct'];
      Map<String, dynamic>? claims;
      if (jsonObject.containsKey('claims')) {
        claims = _parseStuff(jsonObject['claims']);
      }
      return AuthorizationDetailsObject(
          format: format,
          claims: claims,
          credentialType: [vct],
          credentialIdentifiers: credentialIdentifiers,
          actions: actions?.cast<String>(),
          dataTypes: dataTypes?.cast<String>(),
          identifier: id,
          locations: locations?.cast<String>(),
          privileges: privileges?.cast<String>());
    } else {
      return AuthorizationDetailsObject(
          credentialConfigurationId: configId,
          credentialIdentifiers: credentialIdentifiers,
          actions: actions?.cast<String>(),
          dataTypes: dataTypes?.cast<String>(),
          identifier: id,
          locations: locations?.cast<String>(),
          privileges: privileges?.cast<String>());
    }
  }

  @override
  Map<String, dynamic> toJson() {
    Map<String, dynamic> jsonObject = {'type': type};
    if (credentialConfigurationId != null) {
      jsonObject['credential_configuration_id'] = credentialConfigurationId;
    }
    if (locations != null) {
      jsonObject['locations'] = locations;
    }
    if (actions != null) {
      jsonObject['actions'] = actions;
    }
    if (dataTypes != null) {
      jsonObject['datatypes'] = dataTypes;
    }
    if (privileges != null) {
      jsonObject['privileges'] = privileges;
    }
    if (identifier != null) {
      jsonObject['identifier'] = identifier;
    }
    if (credentialIdentifiers != null) {
      jsonObject['credential_identifiers'] = credentialIdentifiers;
    }
    if (format != null) {
      jsonObject['format'] = format;

      if (format == OidcCredentialFormat.ldpVc ||
          format == OidcCredentialFormat.jwtVcJson ||
          format == OidcCredentialFormat.jwtVcJsonLd) {
        var definition = <String, dynamic>{};
        if (context != null) {
          definition['@context'] = context;
        }
        if (credentialType != null) {
          definition['type'] = credentialType;
        }
        if (claims != null) {
          definition['credentialSubject'] = _stuffToJson(claims!);
        }
        jsonObject['credential_definition'] = definition;
      } else if (format == OidcCredentialFormat.msoMdoc) {
        if (credentialType != null) {
          jsonObject['doctype'] = credentialType!.firstOrNull;
        }
        if (claims != null) {
          jsonObject['claims'] = _stuffToJson(claims!);
        }
      } else if (format == OidcCredentialFormat.sdJwt) {
        if (credentialType != null) {
          jsonObject['vct'] = credentialType!.firstOrNull;
        }
        if (claims != null) {
          jsonObject['claims'] = _stuffToJson(claims!);
        }
      }
    }

    return jsonObject;
  }

  @override
  String toString() {
    return jsonEncode(toJson());
  }
}

class OidcTokenResponse implements JsonObject {
  // Parameter from RFC 6749 OAuth 2.0
  String? accessToken, tokenType;
  String? refreshToken, scope;
  int? expiresIn;

  // Parameter from oid4vci draft 11 - 13
  String? cNonce;
  int? cNonceExpiresIn;
  // Parameter from oid4vci draft 11
  bool? authorizationPending;
  int? interval;
  // Parameter from oid4vci draft 12 - 13
  List<AuthorizationDetailsObject>? authorizationDetails;

  OidcTokenResponse(
      {this.accessToken,
      this.authorizationPending,
      this.cNonce,
      this.cNonceExpiresIn,
      this.interval,
      this.refreshToken,
      this.tokenType,
      this.scope,
      this.expiresIn,
      this.authorizationDetails});

  OidcTokenResponse.fromJson(dynamic data) {
    var jsonObject = credentialToMap(data);
    accessToken = jsonObject['access_token'];
    refreshToken = jsonObject['refresh_token'];
    tokenType = jsonObject['token_type'];
    expiresIn = jsonObject['expires_in'];
    scope = jsonObject['scope'];

    cNonce = jsonObject['c_nonce'];
    cNonceExpiresIn = jsonObject['c_nonce_expires_in'];
    authorizationPending = jsonObject['authorization_pending'];
    interval = jsonObject['interval'];

    if (jsonObject.containsKey('authorization_details')) {
      List details = jsonObject['authorization_details'];
      authorizationDetails =
          details.map((e) => AuthorizationDetailsObject.fromJson(e)).toList();
    }
  }
  @override
  Map<String, dynamic> toJson() {
    Map<String, dynamic> jsonObject = {};
    if (accessToken != null) {
      jsonObject['access_token'] = accessToken;
    }
    if (tokenType != null) {
      jsonObject['token_type'] = tokenType;
    }
    if (refreshToken != null) {
      jsonObject['refresh_token'] = refreshToken;
    }
    if (scope != null) {
      jsonObject['scope'] = scope;
    }
    if (expiresIn != null) {
      jsonObject['expires_in'] = expiresIn;
    }

    if (cNonce != null) {
      jsonObject['c_nonce'] = cNonce;
    }
    if (cNonceExpiresIn != null) {
      jsonObject['c_nonce_expires_in'] = cNonceExpiresIn;
    }
    if (authorizationPending != null) {
      jsonObject['authorization_pending'] = authorizationPending;
    }
    if (interval != null) {
      jsonObject['interval'] = interval;
    }

    if (authorizationDetails != null) {
      jsonObject['authorization_details'] =
          authorizationDetails!.map((e) => e.toJson()).toList();
    }
    return jsonObject;
  }

  @override
  String toString() {
    return jsonEncode(toJson());
  }
}

class CredentialIssuerMetaData implements JsonObject {
  late String credentialIssuer;
  List<String>? authorizationServer,
      credentialResponseEncryptionAlgSupported,
      credentialResponseEncryptionEncSupported;
  late String credentialEndpoint;
  String? batchCredentialEndpoint,
      deferredCredentialEndpoint,
      notificationEndpoint;
  bool? credentialResponseEncryptionRequired, credentialIdentifiersSupported;
  late Map<String, CredentialsSupportedObject> credentialsSupported;
  List<OidcDisplayObject>? display;

  CredentialIssuerMetaData(
      {required this.credentialIssuer,
      this.authorizationServer,
      required this.credentialEndpoint,
      this.batchCredentialEndpoint,
      required this.credentialsSupported,
      this.display});

  CredentialIssuerMetaData.fromJson(dynamic data) {
    var jsonObject = credentialToMap(data);
    if (jsonObject.containsKey('credential_issuer')) {
      credentialIssuer = jsonObject['credential_issuer'];
    } else {
      throw Exception('credential_issuer property is needed');
    }

    if (jsonObject.containsKey('credential_endpoint')) {
      credentialEndpoint = jsonObject['credential_endpoint'];
    } else {
      throw Exception('credential_endpoint property is needed');
    }

    if (jsonObject.containsKey('authorization_servers')) {
      authorizationServer =
          (jsonObject['authorization_servers'] as List).cast<String>();
    }

    batchCredentialEndpoint = jsonObject['batch_credential_endpoint'];
    deferredCredentialEndpoint = jsonObject['deferred_credential_endpoint'];
    notificationEndpoint = jsonObject['notification_endpoint'];

    // encryption stuff as per draft 12
    if (jsonObject
        .containsKey('credential_response_encryption_alg_values_supported')) {
      credentialResponseEncryptionAlgSupported =
          (jsonObject['credential_response_encryption_alg_values_supported']
                  as List)
              .cast<String>();
    }
    if (jsonObject
        .containsKey('credential_response_encryption_enc_values_supported')) {
      credentialResponseEncryptionEncSupported =
          (jsonObject['credential_response_encryption_enc_values_supported']
                  as List)
              .cast<String>();
    }
    if (jsonObject.containsKey('require_credential_response_encryption')) {
      credentialResponseEncryptionRequired =
          jsonObject['require_credential_response_encryption'];
    }

    // encryption stuff as per draft 13
    if (jsonObject.containsKey('credential_response_encryption')) {
      var tmp = jsonObject['credential_response_encryption'] as Map;
      credentialResponseEncryptionAlgSupported =
          (tmp['alg_values_supported'] as List).cast<String>();
      credentialResponseEncryptionEncSupported =
          (tmp['enc_values_supported'] as List).cast<String>();
      credentialResponseEncryptionRequired = tmp['encryption_required'];
    }

    credentialIdentifiersSupported =
        jsonObject['credential_identifiers_supported'];

    if (jsonObject.containsKey('display')) {
      display = [];
      List tmp = jsonObject['display'];
      for (var d in tmp) {
        display!.add(OidcDisplayObject.fromJson(d));
      }
    }

    // draft 12 / 11
    if (jsonObject.containsKey('credentials_supported')) {
      credentialsSupported = {};
      var tmp = jsonObject['credentials_supported'];
      if (tmp is Map) {
        // draft 12
        for (var s in tmp.keys) {
          print(tmp[s]);
          var support = CredentialsSupportedObject.fromJson(tmp[s]);
          support.credentialId = s;
          credentialsSupported[s] = support;
        }
      } else {
        // draft 11
        tmp as List;
        int c = 0;
        for (Map s in tmp) {
          var id = s['id'];
          var support = CredentialsSupportedObject.fromJson(s);
          support.credentialId = id;
          credentialsSupported[id ?? c.toString()] = support;
          c++;
        }
      }
    }
    // draft 13
    if (jsonObject.containsKey('credential_configurations_supported')) {
      credentialsSupported = {};
      Map tmp = jsonObject['credential_configurations_supported'];
      for (var s in tmp.keys) {
        credentialsSupported[s] = CredentialsSupportedObject.fromJson(tmp[s]);
      }
    }
  }

  @override
  Map<String, dynamic> toJson() {
    var jsonObject = <String, dynamic>{
      'credential_issuer': credentialIssuer,
      'credential_endpoint': credentialEndpoint
    };
    if (batchCredentialEndpoint != null) {
      jsonObject['batch_credential_endpoint'] = batchCredentialEndpoint;
    }
    if (deferredCredentialEndpoint != null) {
      jsonObject['deferred_credential_endpoint'] = deferredCredentialEndpoint;
    }
    if (authorizationServer != null) {
      jsonObject['authorization_servers'] = authorizationServer;
    }
    if (notificationEndpoint != null) {
      jsonObject['notification_endpoint'];
    }
    if (credentialResponseEncryptionEncSupported != null &&
        credentialResponseEncryptionAlgSupported != null &&
        credentialResponseEncryptionRequired != null) {
      Map<String, dynamic> tmp = {};
      tmp['alg_values_supported'] = credentialResponseEncryptionAlgSupported;
      tmp['enc_values_supported'] = credentialResponseEncryptionEncSupported;
      tmp['encryption_required'] = credentialResponseEncryptionRequired;
      jsonObject['credential_response_encryption'] = tmp;
    }
    if (credentialIdentifiersSupported != null) {
      jsonObject['credential_identifiers_supported'] =
          credentialIdentifiersSupported;
    }
    if (display != null && display!.isNotEmpty) {
      var tmp = [];
      for (var d in display!) {
        tmp.add(d.toJson());
      }
      jsonObject['display'] = tmp;
    }

    if (credentialsSupported.isNotEmpty) {
      jsonObject['credential_configurations_supported'] = credentialsSupported
          .map((key, value) => MapEntry(key, value.toJson()));
    }

    return jsonObject;
  }

  @override
  String toString() {
    return jsonEncode(toJson());
  }
}

class CredentialsSupportedObject implements JsonObject {
  late String format;
  String? scope;
  List<String>? cryptographicBindingMethods,
      //in draft 11 and 12 called cryptographic_suites_supported
      credentialSigningAlgValues,
      order;
  // in draft 12 this is only a list of the proof types,
  // therefor the List of supported algs is always empty
  Map<String, List<String>>? proofTypesSupported;
  List<OidcDisplayObject>? display;
  // credential specific
  Map<String, dynamic>? claims;
  List<String>? credentialType;
  List<String>? context;
  String? credentialId;

  CredentialsSupportedObject(
      {required this.format,
      this.order,
      this.scope,
      this.display,
      this.cryptographicBindingMethods,
      this.credentialSigningAlgValues,
      this.proofTypesSupported,
      this.credentialType,
      this.claims,
      this.context,
      this.credentialId});

  factory CredentialsSupportedObject.fromJson(dynamic data) {
    var jsonObject = credentialToMap(data);
    var format = jsonObject['format'];
    String? scope = jsonObject['scope'];
    List<String>? cbm, cs, o;
    Map<String, List<String>>? pt;
    List<OidcDisplayObject>? display;
    if (jsonObject.containsKey('cryptographic_binding_methods_supported')) {
      cbm = (jsonObject['cryptographic_binding_methods_supported'] as List)
          .cast<String>();
    }
    if (jsonObject.containsKey('proof_types_supported')) {
      var tmp = jsonObject['proof_types_supported'];
      pt = {};
      if (tmp is Map) {
        //draft 13
        for (var k in tmp.keys) {
          Map v = tmp[k];
          var l =
              (v['proof_signing_alg_values_supported'] as List).cast<String>();
          pt[k] = l;
        }
      } else {
        tmp as List;
        for (var k in tmp) {
          pt[k] = [];
        }
      }
    }
    if (jsonObject.containsKey('credential_signing_alg_values_supported')) {
      cs = (jsonObject['credential_signing_alg_values_supported'] as List)
          .cast<String>();
    }
    if (jsonObject.containsKey('cryptographic_suites_supported')) {
      cs =
          (jsonObject['cryptographic_suites_supported'] as List).cast<String>();
    }
    if (jsonObject.containsKey('order')) {
      o = (jsonObject['order'] as List).cast<String>();
    }
    if (jsonObject.containsKey('display')) {
      List tmp = jsonObject['display'];
      display = tmp.map((e) => OidcDisplayObject.fromJson(e)).toList();
    }

    if (format == OidcCredentialFormat.msoMdoc) {
      Map<String, dynamic>? claims;
      if (jsonObject.containsKey('claims')) {
        Map tmp = jsonObject['claims'];
        claims = _parseStuff(tmp);
      }
      return CredentialsSupportedObject(
          credentialType: [jsonObject['doctype']!],
          claims: claims,
          order: o,
          format: format,
          scope: scope,
          proofTypesSupported: pt,
          display: display,
          cryptographicBindingMethods: cbm,
          credentialSigningAlgValues: cs);
    } else if (format == OidcCredentialFormat.sdJwt) {
      Map<String, dynamic>? claims;
      String cType;
      // draft 11 and 12 do not mention sd-jwt, therefor we assume it is handled as other jwt types
      if (jsonObject.containsKey('credential_definition')) {
        Map definition = jsonObject['credential_definition'];
        cType = definition['type'];
        if (definition.containsKey('claims')) {
          claims = _parseStuff(definition['claims']);
        }
        if (definition.containsKey('credentialSubject')) {
          claims = _parseStuff(definition['credentialSubject']);
        }
      } else {
        // draft 13
        cType = jsonObject['vct'];
        if (jsonObject.containsKey('claims')) {
          claims = _parseStuff(jsonObject['claims']);
        }
      }
      return CredentialsSupportedObject(
          credentialType: [cType],
          claims: claims,
          order: o,
          format: format,
          scope: scope,
          proofTypesSupported: pt,
          display: display,
          cryptographicBindingMethods: cbm,
          credentialSigningAlgValues: cs);
    } else if (format == OidcCredentialFormat.ldpVc ||
        format == OidcCredentialFormat.jwtVcJsonLd) {
      List? context, type;
      Map<String, dynamic>? claims;
      if (jsonObject.containsKey('credential_definition')) {
        Map definition = jsonObject['credential_definition'];
        context = definition['@context'];
        type = definition['type'];

        if (definition.containsKey('credentialSubject')) {
          claims = _parseStuff(definition['credentialSubject']);
        }
      } else {
        type = jsonObject['types'];
        context = jsonObject['@context'];
        if (jsonObject.containsKey('credentialSubject')) {
          claims = _parseStuff(jsonObject['credentialSubject']);
        }
      }
      return CredentialsSupportedObject(
          claims: claims,
          order: o,
          credentialSigningAlgValues: cs,
          cryptographicBindingMethods: cbm,
          display: display,
          proofTypesSupported: pt,
          scope: scope,
          format: format,
          context: context?.cast<String>(),
          credentialType: type?.cast<String>());
    } else if (format == OidcCredentialFormat.jwtVcJson) {
      Map<String, dynamic>? claims;
      List type;
      if (jsonObject.containsKey('credential_definition')) {
        Map definition = jsonObject['credential_definition'];
        type = definition['type'];

        if (definition.containsKey('credentialSubject')) {
          claims = _parseStuff(definition['credentialSubject']);
        }
      } else {
        type = jsonObject['types'];
        if (jsonObject.containsKey('credentialSubject')) {
          claims = _parseStuff(jsonObject['credentialSubject']);
        }
      }
      return CredentialsSupportedObject(
          claims: claims,
          order: o,
          credentialSigningAlgValues: cs,
          cryptographicBindingMethods: cbm,
          display: display,
          proofTypesSupported: pt,
          scope: scope,
          format: format,
          credentialType: type.cast<String>());
    } else {
      return CredentialsSupportedObject(
          format: format,
          credentialSigningAlgValues: cs,
          cryptographicBindingMethods: cbm,
          display: display,
          proofTypesSupported: pt,
          scope: scope);
    }
  }

  @override
  Map<String, dynamic> toJson() {
    Map<String, dynamic> jsonObject = {'format': format};
    if (scope != null) {
      jsonObject['scope'] = scope;
    }

    if (cryptographicBindingMethods != null) {
      jsonObject['cryptographic_binding_methods_supported'] =
          cryptographicBindingMethods;
    }
    if (credentialSigningAlgValues != null) {
      jsonObject['credential_signing_alg_values_supported'] =
          credentialSigningAlgValues;
    }
    if (proofTypesSupported != null) {
      jsonObject['proof_types_supported'] = proofTypesSupported!.map(
          (key, value) =>
              MapEntry(key, {'proof_signing_alg_values_supported': value}));
    }

    if (display != null && display!.isNotEmpty) {
      var tmp = [];
      for (var d in display!) {
        tmp.add(d.toJson());
      }
      jsonObject['display'] = tmp;
    }

    if (order != null) {
      jsonObject['order'] = order;
    }

    if (format == OidcCredentialFormat.msoMdoc) {
      if (credentialType != null) {
        jsonObject['doctype'] = credentialType!.firstOrNull;
      }
      if (claims != null) {
        jsonObject['claims'] = _stuffToJson(claims!);
      }
    } else if (format == OidcCredentialFormat.ldpVc ||
        format == OidcCredentialFormat.jwtVcJsonLd ||
        format == OidcCredentialFormat.jwtVcJson) {
      var definition = <String, dynamic>{};
      if (context != null) {
        definition['@context'] = context;
      }
      definition['type'] = credentialType;
      if (claims != null) {
        definition['credentialSubject'] = _stuffToJson(claims!);
      }
      jsonObject['credential_definition'] = definition;
    } else if (format == OidcCredentialFormat.sdJwt) {
      if (credentialType != null) {
        jsonObject['vct'] = credentialType!.firstOrNull;
      }
      if (claims != null) {
        jsonObject['claims'] = _stuffToJson(claims!);
      }
    }

    return jsonObject;
  }

  @override
  String toString() {
    return jsonEncode(toJson());
  }
}

class CredentialSubjectMetadata implements JsonObject {
  bool mandatory = false;
  String? valueType;
  List<OidcDisplayObject>? display;

  CredentialSubjectMetadata(
      {this.mandatory = false, this.valueType, this.display});

  CredentialSubjectMetadata.fromJson(dynamic data) {
    var jsonObject = credentialToMap(data);
    mandatory = jsonObject['mandatory'] ?? false;
    valueType = jsonObject['value_type'];

    if (jsonObject.containsKey('display')) {
      List tmp = jsonObject['display'];
      display = [];
      for (var e in tmp) {
        display!.add(OidcDisplayObject.fromJson(e));
      }
    }
  }

  static bool isCredentialSubjectMetadata(Map candidate) {
    return candidate.containsKey('display') ||
        candidate.containsKey('mandatory') ||
        candidate.containsKey('value_type') ||
        candidate.isEmpty;
  }

  @override
  Map<String, dynamic> toJson() {
    Map<String, dynamic> jsonObject = {};
    if (mandatory) {
      jsonObject['mandatory'] = mandatory;
    }
    if (valueType != null) {
      jsonObject['value_type'] = valueType;
    }
    if (display != null && display!.isNotEmpty) {
      var tmp = [];
      for (var d in display!) {
        tmp.add(d.toJson());
      }
      jsonObject['display'] = tmp;
    }
    return jsonObject;
  }
}

class OidcDisplayObject implements JsonObject {
  String? name;
  String? locale;
  UrlData? logo;
  String? description;
  String? backgroundColor;
  String? textColor;

  OidcDisplayObject(
      {this.name,
      this.locale,
      this.logo,
      this.backgroundColor,
      this.description,
      this.textColor});

  OidcDisplayObject.fromJson(dynamic data) {
    var jsonData = credentialToMap(data);
    name = jsonData['name'];
    locale = jsonData['locale'];
    description = jsonData['description'];
    backgroundColor = jsonData['background_color'];
    textColor = jsonData['text_color'];

    if (jsonData.containsKey('logo')) {
      logo = UrlData.fromJson(jsonData['logo']);
    }
  }

  @override
  Map<String, dynamic> toJson() {
    Map<String, dynamic> jsonObject = {};
    if (name != null) {
      jsonObject['name'] = name;
    }
    if (locale != null) {
      jsonObject['locale'] = locale;
    }
    if (logo != null) {
      jsonObject['logo'] = logo!.toJson();
    }
    if (description != null) {
      jsonObject['description'] = description;
    }
    if (backgroundColor != null) {
      jsonObject['background_color'];
    }
    if (textColor != null) {
      jsonObject['text_color'] = textColor;
    }
    return jsonObject;
  }

  @override
  String toString() {
    return jsonEncode(toJson());
  }
}

class UrlData implements JsonObject {
  String? url;
  String? altText;

  UrlData({this.url, this.altText});

  UrlData.fromJson(dynamic data) {
    var jsonData = credentialToMap(data);
    url = jsonData['url'];
    altText = jsonData['alt_text'];
  }
  @override
  Map<String, dynamic> toJson() {
    Map<String, dynamic> jsonObject = {};
    if (url != null) {
      jsonObject['url'] = url;
    }
    if (altText != null) {
      jsonObject['alt_text'] = altText;
    }
    return jsonObject;
  }

  @override
  String toString() {
    return jsonEncode(toJson());
  }
}

class OidcCredentialRequest implements JsonObject {
  String? format, credentialIdentifier;
  Map<String, dynamic>? responseEncryptionJwk;
  String? responseEncryptionAlg, responseEncryptionEnc;
  CredentialRequestProof? proof;
  // credential specific
  List<String>? credentialType;
  List<String>? context;
  Map<String, dynamic>? claims;

  OidcCredentialRequest(
      {this.format,
      this.credentialIdentifier,
      this.proof,
      this.responseEncryptionAlg,
      this.responseEncryptionEnc,
      this.responseEncryptionJwk,
      this.credentialType,
      this.claims,
      this.context});

  factory OidcCredentialRequest.fromJson(dynamic data) {
    var jsonObject = credentialToMap(data);
    String? format = jsonObject['format'],
        credentialIdentifier = jsonObject['credential_identifier'];
    if (format == null && credentialIdentifier == null) {
      throw Exception(
          'Invalid Credential Request: format and credentialIdentifier null');
    }
    CredentialRequestProof? proof;
    if (jsonObject.containsKey('proof')) {
      proof = CredentialRequestProof.fromJson(jsonObject['proof']);
    }
    Map? jwk = jsonObject['credential_encryption_jwk'];
    String? enc = jsonObject['credential_response_encryption_enc'],
        alg = jsonObject['credential_response_encryption_alg'];

    if (jsonObject.containsKey('credential_response_encryption')) {
      Map tmp = jsonObject['credential_response_encryption'];
      jwk = tmp['jwk'];
      alg = tmp['alg'];
      enc = tmp['enc'];
    }
    if (format == OidcCredentialFormat.ldpVc ||
        format == OidcCredentialFormat.jwtVcJsonLd) {
      Map definition = jsonObject['credential_definition'];
      List? context = definition['@context'];
      List? vcType = definition['type'] ?? definition['types'];
      Map<String, dynamic>? subject;
      if (definition.containsKey('credentialSubject')) {
        subject = _parseStuff(definition['credentialSubject']);
      }

      return OidcCredentialRequest(
          format: format,
          context: context?.cast<String>(),
          credentialType: vcType?.cast<String>(),
          claims: subject,
          credentialIdentifier: credentialIdentifier,
          proof: proof,
          responseEncryptionAlg: alg,
          responseEncryptionEnc: enc,
          responseEncryptionJwk:
              jwk?.map((key, value) => MapEntry(key as String, value)));
    } else if (format == OidcCredentialFormat.jwtVcJson) {
      List vcType;
      Map<String, dynamic>? subject;
      if (jsonObject.containsKey('credential_definition')) {
        Map definition = jsonObject['credential_definition'];
        vcType = definition['type'] ?? definition['types'];

        if (definition.containsKey('credentialSubject')) {
          subject = _parseStuff(definition['credentialSubject']);
        }
      } else {
        vcType = jsonObject['type'] ?? jsonObject['types'];
        if (jsonObject.containsKey('credentialSubject')) {
          subject = _parseStuff(jsonObject['credentialSubject']);
        }
      }

      return OidcCredentialRequest(
          format: format,
          credentialType: vcType.cast<String>(),
          claims: subject,
          credentialIdentifier: credentialIdentifier,
          proof: proof,
          responseEncryptionAlg: alg,
          responseEncryptionEnc: enc,
          responseEncryptionJwk:
              jwk?.map((key, value) => MapEntry(key as String, value)));
    } else if (format == OidcCredentialFormat.msoMdoc) {
      String? doctype = jsonObject['doctype'];
      Map<String, dynamic>? claims;
      if (jsonObject.containsKey('claims')) {
        Map tmp = jsonObject['claims'];
        claims = _parseStuff(tmp);
      }

      return OidcCredentialRequest(
          format: format,
          claims: claims,
          credentialType: doctype != null ? [doctype] : null,
          credentialIdentifier: credentialIdentifier,
          proof: proof,
          responseEncryptionAlg: alg,
          responseEncryptionEnc: enc,
          responseEncryptionJwk:
              jwk?.map((key, value) => MapEntry(key as String, value)));
    } else if (format == OidcCredentialFormat.sdJwt) {
      String vct = jsonObject['vct'];
      Map<String, dynamic>? claims;
      if (jsonObject.containsKey('claims')) {
        claims = _parseStuff(jsonObject['claims']);
      }
      return OidcCredentialRequest(
          format: format,
          claims: claims,
          credentialType: [vct],
          credentialIdentifier: credentialIdentifier,
          proof: proof,
          responseEncryptionAlg: alg,
          responseEncryptionEnc: enc,
          responseEncryptionJwk:
              jwk?.map((key, value) => MapEntry(key as String, value)));
    } else {
      return OidcCredentialRequest(
          credentialIdentifier: credentialIdentifier,
          proof: proof,
          responseEncryptionAlg: alg,
          responseEncryptionEnc: enc,
          responseEncryptionJwk:
              jwk?.map((key, value) => MapEntry(key as String, value)));
    }
  }

  @override
  Map<String, dynamic> toJson() {
    Map<String, dynamic> jsonObject = {};
    if (credentialIdentifier != null) {
      jsonObject['credential_identifier'] = credentialIdentifier;
    }
    if (format != null) {
      jsonObject['format'] = format;
    }
    if (proof != null) {
      jsonObject['proof'] = proof!.toJson();
    }
    if (responseEncryptionJwk != null && responseEncryptionAlg != null) {
      Map<String, dynamic> tmp = {};
      tmp['jwk'] = responseEncryptionJwk;
      tmp['alg'] = responseEncryptionAlg;
      tmp['enc'] = responseEncryptionEnc;
      jsonObject['credential_response_encryption'] = tmp;
    }

    if (format == OidcCredentialFormat.ldpVc ||
        format == OidcCredentialFormat.jwtVcJsonLd ||
        format == OidcCredentialFormat.jwtVcJson) {
      var definition = <String, dynamic>{};
      if (context != null) {
        definition['@context'] = context;
      }
      if (credentialType != null) {
        definition['type'] = credentialType;
      }
      if (claims != null) {
        definition['credentialSubject'] = _stuffToJson(claims!);
      }
      jsonObject['credential_definition'] = definition;
    } else if (format == OidcCredentialFormat.sdJwt) {
      if (credentialType != null) {
        jsonObject['vct'] = credentialType;
      }
      if (claims != null) {
        jsonObject['claims'] = _stuffToJson(claims!);
      }
    } else if (format == OidcCredentialFormat.msoMdoc) {
      if (credentialType != null) {
        jsonObject['doctype'] = credentialType!.firstOrNull;
      }
      if (claims != null) {
        jsonObject['claims'] = _stuffToJson(claims!);
      }
    }

    return jsonObject;
  }

  @override
  String toString() {
    return jsonEncode(toJson());
  }
}

class CredentialRequestProof implements JsonObject {
  String proofType;
  dynamic proofValue;

  CredentialRequestProof({required this.proofType, this.proofValue});

  factory CredentialRequestProof.fromJson(dynamic jsonData) {
    var jsonObject = credentialToMap(jsonData);
    var type = jsonObject['proof_type'];

    if (type == 'jwt') {
      return CredentialRequestProof(
          proofValue: jsonObject['jwt'], proofType: type);
    } else if (type == 'cwt') {
      return CredentialRequestProof(
          proofValue: jsonObject['cwt'], proofType: type);
    } else if (type == 'ldp_vp') {
      return CredentialRequestProof(
          proofValue: jsonObject['ldp_vp'], proofType: type);
    } else {
      jsonObject.remove('proof_type');
      return CredentialRequestProof(proofType: type, proofValue: jsonObject);
    }
  }

  @override
  Map<String, dynamic> toJson() {
    Map<String, dynamic> jsonObject = {'proof_type': proofType};
    if (proofType == 'jwt') {
      jsonObject['jwt'] = proofValue;
    } else if (proofType == 'cwt') {
      jsonObject['cwt'] = proofValue;
    } else if (proofType == 'ldp_vp') {
      jsonObject['ldp_vp'] = proofValue;
    }

    return jsonObject;
  }

  @override
  String toString() {
    return jsonEncode(toJson());
  }
}

class OidcCredentialResponse implements JsonObject {
  dynamic credential;
  String? transactionId,
      cNonce,
      notificationId,

      /// Required in draft 11 and 12, removed in draft 13
      format;
  int? cNonceExpiresIn;

  OidcCredentialResponse(
      {this.credential,
      this.transactionId,
      this.cNonce,
      this.cNonceExpiresIn,
      this.notificationId,
      this.format});

  OidcCredentialResponse.fromJson(dynamic jsonData) {
    var jsonObject = credentialToMap(jsonData);
    credential = jsonObject['credential'];
    transactionId = jsonObject['transaction_id'];
    cNonce = jsonObject['c_nonce'];
    cNonceExpiresIn = jsonObject['c_nonce_expires_in'];
    notificationId = jsonObject['notification_id'];
    format = jsonObject['format'];
    if (jsonObject.containsKey('acceptance_token')) {
      transactionId = jsonObject['acceptance_token'];
    }
  }

  @override
  Map<String, dynamic> toJson() {
    Map<String, dynamic> jsonObject = {};
    if (credential != null) {
      jsonObject['credential'] = credential;
    }
    if (format != null) {
      jsonObject['format'] = format;
    }
    if (transactionId != null) {
      jsonObject['transaction_id'] = transactionId;
    }
    if (cNonce != null) {
      jsonObject['c_nonce'] = cNonce;
    }
    if (cNonceExpiresIn != null) {
      jsonObject['c_nonce_expires_in'] = cNonceExpiresIn;
    }
    if (notificationId != null) {
      jsonObject['notification_id'] = notificationId;
    }

    return jsonObject;
  }

  @override
  String toString() {
    return jsonEncode(toJson());
  }
}

class OidcCredentialFormat {
  static final String sdJwt = 'vc+sd-jwt';
  static final String msoMdoc = 'mso_mdoc';
  static final String ldpVc = 'ldp_vc';
  static final String jwtVcJson = 'jwt_vc_json';
  static final String jwtVcJsonLd = 'jwt_vc_json-ld';
}

Map<String, dynamic> _parseStuff(Map toParse) {
  Map<String, dynamic> f = {};
  for (var k in toParse.keys) {
    var v = toParse[k];
    if (v is List) {
      var parsed = [];
      for (var e in v) {
        parsed.add(_parseStuff(e));
      }
      f[k] = parsed;
    } else if (v is Map &&
        CredentialSubjectMetadata.isCredentialSubjectMetadata(v)) {
      f[k] = CredentialSubjectMetadata.fromJson(v);
    } else {
      var d = _parseStuff(v);
      f[k] = d;
    }
  }

  return f;
}

Map<String, dynamic> _stuffToJson(Map<String, dynamic> toParse) {
  Map<String, dynamic> f = {};
  for (var k in toParse.keys) {
    var v = toParse[k];
    if (v is List) {
      List parsed = [];
      for (var entry in v) {
        if (entry is CredentialSubjectMetadata) {
          parsed.add(entry.toJson());
        } else {
          parsed.add(_stuffToJson(entry));
        }
      }
      f[k] = parsed;
    } else if (v is CredentialSubjectMetadata) {
      f[k] = v.toJson();
    } else {
      f[k] = _stuffToJson(v);
    }
  }

  return f;
}
