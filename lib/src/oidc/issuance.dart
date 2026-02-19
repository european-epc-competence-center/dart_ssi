import 'dart:convert';

import '../util/types.dart';
import '../util/utils.dart';

class OidcCredentialOffer implements JsonObject {
  late String credentialIssuer;
  late List<dynamic> credentials;
  /// OpenID4VCI 1.0 §4.1.1: credential_configuration_ids (array of strings).
  List<String>? credentialConfigurationIds;
  Map<String, dynamic>? grants;

  OidcCredentialOffer(
      {required this.credentialIssuer,
      required this.credentials,
      this.credentialConfigurationIds,
      this.grants});

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

    // OpenID4VCI 1.0 §4.1.1: credential_configuration_ids (primary)
    if (jsonObject.containsKey('credential_configuration_ids')) {
      final ids = jsonObject['credential_configuration_ids'];
      credentialConfigurationIds =
          ids is List ? ids.map((e) => e.toString()).toList() : null;
    } else {
      credentialConfigurationIds = null;
    }

    if (jsonObject.containsKey('credentials')) {
      credentials = jsonObject['credentials'];
    } else if (credentialConfigurationIds != null) {
      credentials = credentialConfigurationIds!;
    } else {
      throw Exception(
          'credentials or credential_configuration_ids is needed in OpenId Connect 4VC CredentialOffer');
    }

    if (jsonObject.containsKey('grants')) {
      grants = jsonObject['grants'] as Map<String, dynamic>;
    } else {
      grants = null;
    }
  }

  @override
  Map<String, dynamic> toJson() {
    Map<String, dynamic> jsonObject = {
      'credential_issuer': credentialIssuer,
      'credentials': credentials
    };
    if (credentialConfigurationIds != null) {
      jsonObject['credential_configuration_ids'] = credentialConfigurationIds;
    }
    if (grants != null) {
      jsonObject['grants'] = grants;
    }
    return jsonObject;
  }

  @override
  String toString() {
    return jsonEncode(toJson());
  }
}

class OidcTokenResponse implements JsonObject {
  String? accessToken;
  String? refreshToken;
  String? cNonce;
  int? cNonceExpiresIn;
  bool? authorizationPending;
  int? interval;

  OidcTokenResponse(
      {this.accessToken,
      this.authorizationPending,
      this.cNonce,
      this.cNonceExpiresIn,
      this.interval,
      this.refreshToken});

  OidcTokenResponse.fromJson(dynamic data) {
    var jsonObject = credentialToMap(data);
    accessToken = jsonObject['access_token'];
    refreshToken = jsonObject['refresh_token'];
    cNonce = jsonObject['c_nonce'];
    cNonceExpiresIn = jsonObject['c_nonce_expires_in'];
    authorizationPending = jsonObject['authorization_pending'];
    interval = jsonObject['interval'];
  }
  @override
  Map<String, dynamic> toJson() {
    Map<String, dynamic> jsonObject = {};
    if (accessToken != null) {
      jsonObject['access_token'] = accessToken;
    }
    if (refreshToken != null) {
      jsonObject['refresh_token'] = refreshToken;
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
    return jsonObject;
  }

  @override
  String toString() {
    return jsonEncode(toJson());
  }
}

/// OpenID4VCI authorization_details entry (type openid_credential).
class AuthorizationDetailsObject implements JsonObject {
  String? format;
  String? credentialConfigurationId;
  List<String>? credentialType;

  AuthorizationDetailsObject(
      {this.format,
      this.credentialConfigurationId,
      this.credentialType});

  @override
  Map<String, dynamic> toJson() {
    final m = <String, dynamic>{'type': 'openid_credential'};
    if (credentialConfigurationId != null) {
      m['credential_configuration_id'] = credentialConfigurationId;
    }
    if (format != null) m['format'] = format;
    return m;
  }

  @override
  String toString() => jsonEncode(toJson());
}

class CredentialIssuerMetaData implements JsonObject {
  late String credentialIssuer;
  /// Single AS identifier. From metadata: first of [authorization_servers] or [authorization_server].
  String? authorizationServer;
  late String credentialEndpoint;
  String? batchCredentialEndpoint;
  String? nonceEndpoint;
  /// Map keyed by credential configuration id (OpenID4VCI 1.0 §12.2.4).
  late Map<String, CredentialsSupportedObject> credentialsSupported;
  List<OidcDisplayObject>? display;

  CredentialIssuerMetaData(
      {required this.credentialIssuer,
      this.authorizationServer,
      required this.credentialEndpoint,
      this.batchCredentialEndpoint,
      this.nonceEndpoint,
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

    // Metadata: authorization_servers (array) §12.2.4; legacy: authorization_server (single string)
    if (jsonObject.containsKey('authorization_servers')) {
      final list = jsonObject['authorization_servers'];
      if (list is List && list.isNotEmpty) {
        authorizationServer = list.first.toString();
      } else {
        authorizationServer = null;
      }
    } else if (jsonObject.containsKey('authorization_server')) {
      final v = jsonObject['authorization_server'];
      authorizationServer = v?.toString();
    } else {
      authorizationServer = null;
    }
    batchCredentialEndpoint = jsonObject['batch_credential_endpoint'];
    nonceEndpoint = jsonObject['nonce_endpoint']?.toString();

    if (jsonObject.containsKey('display')) {
      display = [];
      List tmp = jsonObject['display'];
      for (var d in tmp) {
        display!.add(OidcDisplayObject.fromJson(d));
      }
    }

    credentialsSupported = {};
    // OpenID4VCI 1.0 §12.2.4: primary is credential_configurations_supported (object)
    if (jsonObject.containsKey('credential_configurations_supported')) {
      final ccs = jsonObject['credential_configurations_supported'];
      if (ccs is Map) {
        for (final e in ccs.entries) {
          final id = e.key.toString();
          final config = e.value;
          if (config is! Map<String, dynamic>) continue;
          final clone = Map<String, dynamic>.from(config);
          clone['id'] = id;
          credentialsSupported[id] = CredentialsSupportedObject.fromJson(clone);
        }
      }
    }
    // Legacy: credentials_supported (array), keyed by each entry's id
    if (credentialsSupported.isEmpty &&
        jsonObject.containsKey('credentials_supported')) {
      var tmp = jsonObject['credentials_supported'];
      if (tmp is List) {
        for (var s in tmp) {
          final obj = CredentialsSupportedObject.fromJson(s);
          final id = obj.id;
          if (id != null && id.isNotEmpty) {
            credentialsSupported[id] = obj;
          }
        }
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
    if (nonceEndpoint != null) {
      jsonObject['nonce_endpoint'] = nonceEndpoint;
    }
    if (authorizationServer != null && authorizationServer!.isNotEmpty) {
      jsonObject['authorization_server'] = authorizationServer;
    }
    if (display != null && display!.isNotEmpty) {
      var tmp = [];
      for (var d in display!) {
        tmp.add(d.toJson());
      }
      jsonObject['display'] = tmp;
    }

    if (credentialsSupported.isNotEmpty) {
      var tmp = [];
      for (var s in credentialsSupported.values) {
        tmp.add(s.toJson());
      }
      jsonObject['credentials_supported'] = tmp;
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
  String? id;
  late List<String> type;
  List<String>? context;
  List<String>? cryptographicBindingMethods;
  List<String>? cryptographicSuitesSupported;
  List<OidcDisplayObject>? display;
  List<String>? order;
  Map<String, CredentialSubjectMetadata>? credentialSubject;
  String? scope;

  CredentialsSupportedObject(
      {required this.format,
      required this.type,
      this.id,
      this.context,
      this.display,
      this.credentialSubject,
      this.cryptographicBindingMethods,
      this.cryptographicSuitesSupported,
      this.order,
      this.scope});

  /// Alias for [type] (OpenID4VCI credential type array).
  List<String> get credentialType => type;

  /// Alias for [id] (credential configuration id).
  String? get credentialId => id;
  set credentialId(String? v) => id = v;

  /// Alias for [credentialSubject] for wallet display (claims description map).
  Map<String, CredentialSubjectMetadata>? get claims => credentialSubject;

  CredentialsSupportedObject.fromJson(dynamic data) {
    var jsonObject = credentialToMap(data);
    if (jsonObject.containsKey('format')) {
      format = jsonObject['format'];
    } else {
      throw Exception('format property is needed');
    }

    id = jsonObject['id'];

    // OpenID4VCI 1.0 Appendix A: credential_definition.type (and @context for ldp_vc)
    final credDef = jsonObject['credential_definition'];
    if (credDef is Map && credDef.containsKey('type')) {
      final t = credDef['type'];
      type = t is List ? t.cast<String>() : [t.toString()];
    } else if (jsonObject.containsKey('types')) {
      type = jsonObject['types'].cast<String>();
    } else if (jsonObject.containsKey('type')) {
      final t = jsonObject['type'];
      type = t is List ? t.cast<String>() : [t.toString()];
    } else {
      type = [];
    }

    if (credDef is Map && credDef.containsKey('@context')) {
      final c = credDef['@context'];
      context = c is List ? c.cast<String>() : (c != null ? [c.toString()] : null);
    } else if (jsonObject.containsKey('@context')) {
      final c = jsonObject['@context'];
      context = c is List ? c.cast<String>() : (c != null ? [c.toString()] : null);
    } else {
      context = null;
    }

    if (jsonObject.containsKey('cryptographic_binding_methods_supported')) {
      cryptographicBindingMethods =
          jsonObject['cryptographic_binding_methods_supported'].cast<String>();
    }

    if (jsonObject.containsKey('credential_signing_alg_values_supported')) {
      cryptographicSuitesSupported =
          jsonObject['credential_signing_alg_values_supported'].cast<String>();
    } else if (jsonObject.containsKey('cryptographic_suites_supported')) {
      cryptographicSuitesSupported =
          jsonObject['cryptographic_suites_supported'].cast<String>();
    } else {
      cryptographicSuitesSupported = null;
    }

    if (jsonObject.containsKey('order')) {
      order = jsonObject['order'].cast<String>();
    }

    scope = jsonObject['scope']?.toString();

    if (jsonObject.containsKey('display')) {
      List tmp = jsonObject['display'];
      display = [];
      for (var d in tmp) {
        display!.add(OidcDisplayObject.fromJson(d));
      }
    } else {
      display = null;
    }

    if (jsonObject.containsKey('credentialSubject')) {
      credentialSubject = {};
      Map<String, dynamic> tmp = jsonObject['credentialSubject'];
      tmp.forEach((key, value) {
        credentialSubject![key] = CredentialSubjectMetadata.fromJson(value);
      });
    } else {
      credentialSubject = null;
    }
  }

  @override
  Map<String, dynamic> toJson() {
    Map<String, dynamic> jsonObject = {'format': format, 'type': type};
    if (id != null) {
      jsonObject['id'] = id;
    }
    if (scope != null) {
      jsonObject['scope'] = scope;
    }
    if (cryptographicSuitesSupported != null) {
      jsonObject['cryptographic_suites_supported'] =
          cryptographicSuitesSupported;
    }
    if (cryptographicBindingMethods != null) {
      jsonObject['cryptographic_binding_methods_supported'] =
          cryptographicBindingMethods;
    }
    if (context != null) {
      jsonObject['@context'] = context;
    }
    if (order != null) {
      jsonObject['order'] = order;
    }
    if (display != null && display!.isNotEmpty) {
      var tmp = [];
      for (var d in display!) {
        tmp.add(d.toJson());
      }
      jsonObject['display'] = tmp;
    }
    if (credentialSubject != null) {
      var tmp = <String, dynamic>{};
      credentialSubject!.forEach((key, value) {
        tmp[key] = value.toJson();
      });
      jsonObject['credentialSubject'] = tmp;
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
  @override
  Map<String, dynamic> toJson() {
    Map<String, dynamic> jsonObject = {'mandatory': mandatory};
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

/// Alias for [OidcDisplayObject] (used by id_ideal_wallet).
typedef OidDisplayObject = OidcDisplayObject;
