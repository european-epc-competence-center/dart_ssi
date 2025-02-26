import 'dart:convert';

import 'package:dart_ssi/credentials.dart';
import 'package:dart_ssi/oid.dart';
import 'package:dart_ssi/src/util/types.dart';
import 'package:dart_ssi/src/util/utils.dart';
import 'package:iso_mdoc/iso_mdoc.dart';
import 'package:json_path/json_path.dart';
import 'package:sd_jwt/sd_jwt.dart';
import 'package:uuid/uuid.dart';

class ClaimPathPointer {
  List<dynamic> pointer;

  ClaimPathPointer(this.pointer);

  factory ClaimPathPointer.fromJson(dynamic json) {
    var parsed = json is String ? jsonDecode(json) : json;
    if (parsed is! List) {
      throw Exception('Invalid pointer');
    }
    return ClaimPathPointer(parsed);
  }

  JsonPath toJsonPath() {
    var pathString = r'$';
    for (var part in pointer) {
      if (part is String) {
        pathString += '["$part"]';
      } else if (part is int) {
        pathString += '[$part]';
      } else if (part == null) {
        pathString += '[*]';
      }
    }

    return JsonPath(pathString);
  }

  dynamic getValueForPath(dynamic jsonData) {
    var start = pointer.first;
    if (start == null) {
      if (jsonData is! List) {
        throw Exception('null is only supported for Lists');
      }
      if (pointer.length == 1) {
        return jsonData;
      }
      var newPointer = ClaimPathPointer(pointer.sublist(1));
      var resultList = [];
      for (var element in jsonData) {
        resultList.add(newPointer.getValueForPath(element));
      }
      return resultList;
    }
    if (pointer.length == 1) {
      try {
        return jsonData[start];
      } on RangeError catch (_) {
        return null;
      }
    } else {
      var newPointer = ClaimPathPointer(pointer.sublist(1));
      return newPointer.getValueForPath(jsonData[start]);
    }
  }

  List<dynamic> toJson() {
    return pointer;
  }

  @override
  String toString() {
    return jsonEncode(toJson());
  }
}

class DcqlQuery extends JsonObject {
  List<CredentialQuery> credentials;
  List<CredentialSetQuery>? credentialSets;

  DcqlQuery({required this.credentials, this.credentialSets});

  factory DcqlQuery.fromJson(dynamic json) {
    var data = credentialToMap(json);
    List<CredentialQuery> c;
    if (data.containsKey('credentials')) {
      var tmp = data['credentials'] as List;
      c = tmp.map((e) => CredentialQuery.fromJson(e)).toList();
    } else {
      throw Exception('credentials parameter needed');
    }

    List<CredentialSetQuery>? cs;
    if (data.containsKey('credential_sets')) {
      var tmp = data['credential_sets'] as List;
      cs = tmp.map((e) => CredentialSetQuery.fromJson(e)).toList();
    }

    return DcqlQuery(credentials: c, credentialSets: cs);
  }

  @override
  Map<String, dynamic> toJson() {
    var data = <String, dynamic>{
      'credentials': credentials.map((e) => e.toJson()).toList()
    };

    if (credentialSets != null) {
      data['credential_sets'] = credentialSets!.map((e) => e.toJson()).toList();
    }

    return data;
  }
}

class CredentialQuery extends JsonObject {
  String id, format;
  CredentialQueryMetadata? meta;
  List<ClaimsQuery>? claims;
  List<List<String>>? claimSets;

  CredentialQuery(
      {String? id,
      required this.format,
      this.claims,
      this.meta,
      this.claimSets})
      : id = id ?? Uuid().v4();

  factory CredentialQuery.fromJson(dynamic json) {
    var data = credentialToMap(json);

    CredentialQueryMetadata? m;
    if (data.containsKey('meta')) {
      m = CredentialQueryMetadata.fromJson(data['meta']);
    }

    List<ClaimsQuery>? c;
    if (data.containsKey('claims')) {
      var tmp = data['claims'] as List;
      c = tmp.map((e) => ClaimsQuery.fromJson(e)).toList();
    }

    List<List<String>>? cs = (data['claim_sets'] as List?)
        ?.map((e) => (e as List).cast<String>())
        .toList();

    return CredentialQuery(
        format: data['format']!,
        id: data['id']!,
        claims: c,
        meta: m,
        claimSets: cs);
  }

  @override
  Map<String, dynamic> toJson() {
    var data = <String, dynamic>{'id': id, 'format': format};
    if (meta != null) {
      data['meta'] = meta!.toJson();
    }
    if (claims != null) {
      data['claims'] = claims!.map((e) => e.toJson()).toList();
    }
    if (claimSets != null) {
      data['claim_sets'] = claimSets;
    }

    return data;
  }
}

class CredentialSetQuery extends JsonObject {
  List<List<String>> options;
  bool required;
  String? purpose;

  CredentialSetQuery(
      {required this.options, this.required = true, this.purpose});

  factory CredentialSetQuery.fromJson(dynamic json) {
    var data = credentialToMap(json);
    List<List<String>> opt = [];
    if (data.containsKey('options')) {
      var optTmp = (data['options'] as List);
      opt = optTmp.map((e) => (e as List).cast<String>()).toList();
    } else {
      throw Exception('options field is required');
    }

    return CredentialSetQuery(
        options: opt,
        required: data['required'] ?? true,
        purpose: data['purpose']);
  }

  @override
  Map<String, dynamic> toJson() {
    var data = {'options': options, 'required': required};
    if (purpose != null) {
      data['purpose'] = purpose!;
    }
    return data;
  }
}

class CredentialQueryMetadata extends JsonObject {
  CredentialQueryMetadata();

  factory CredentialQueryMetadata.fromJson(dynamic json) {
    var data = credentialToMap(json);

    if (data.containsKey('vct_values')) {
      return CredentialQueryMetadataSdJwt(
          vctValues: (data['vct_values'] as List).cast<String>());
    } else if (data.containsKey('doctype_value')) {
      return CredentialQueryMetadataMsoMdoc(doctype: data['doctype_value']);
    } else {
      return CredentialQueryMetadata();
    }
  }

  @override
  Map<String, dynamic> toJson() {
    return {};
  }
}

class CredentialQueryMetadataSdJwt extends CredentialQueryMetadata {
  List<String> vctValues;

  CredentialQueryMetadataSdJwt({required this.vctValues});

  @override
  toJson() {
    return {'vct_values': vctValues};
  }
}

class CredentialQueryMetadataMsoMdoc extends CredentialQueryMetadata {
  String doctype;

  CredentialQueryMetadataMsoMdoc({required this.doctype});

  @override
  toJson() {
    return {'doctype_value': doctype};
  }
}

class ClaimsQuery extends JsonObject {
  String? id;
  ClaimPathPointer path;
  List<dynamic>? values;
  bool? intentToRetain;

  ClaimsQuery({this.id, required this.path, this.values, this.intentToRetain});

  factory ClaimsQuery.fromJson(dynamic json) {
    var data = credentialToMap(json);
    ClaimPathPointer p;
    if (data.containsKey('path')) {
      p = ClaimPathPointer.fromJson(data['path']);
    } else {
      throw Exception('path field is required');
    }

    return ClaimsQuery(
        path: p,
        id: data['id'],
        values: data['values'],
        intentToRetain: data['intent_to_retain']);
  }

  @override
  Map<String, dynamic> toJson() {
    var data = <String, dynamic>{'path': path.toJson()};
    if (id != null) {
      data['id'] = id!;
    }
    if (values != null) {
      data['values'] = values;
    }
    if (intentToRetain != null) {
      data['intent_to_retain'] = intentToRetain;
    }

    return data;
  }
}

List<FilterResult> searchCredentialsForDcqlQuery(DcqlQuery query,
    {List<VerifiableCredential>? w3cCredentials,
    List<SdJws>? sdJwtCredentials,
    List<IssuerSignedObject>? mdocCredentials}) {
  List<FilterResult> result = [];
  for (var cQuery in query.credentials) {
    result.add(_findCredentialsForCredentialQuery(cQuery,
        w3cCredentials: w3cCredentials,
        sdJwtCredentials: sdJwtCredentials,
        mdocCredentials: mdocCredentials));
  }

  if (query.credentialSets != null && query.credentialSets!.isNotEmpty) {
    List<FilterResult> setQueryFiltering = [];
    for (var sQuery in query.credentialSets!) {
      setQueryFiltering.add(_handleSetQuery(sQuery, result));
    }
    return setQueryFiltering;
  } else {
    // every credential query must be fulfilled, but can be fulfilled by different credentials
    return result;
  }
}

FilterResult _handleSetQuery(
    CredentialSetQuery query, List<FilterResult> credentials) {
  List<FilterResult> results = [];
  for (var o in query.options) {
    results.add(_handleSetQueryOption(o, credentials));
  }

  if (results.length == 1) {
    results.first.required = query.required;
    return results.first;
  } else {
    bool fulfilled = false;
    for (var r in results) {
      if (r.fulfilled) {
        fulfilled = true;
        break;
      }
    }
    return FilterResult(
        matchingDescriptorIds: [],
        presentationDefinitionId: 'dcql',
        fulfilled: fulfilled,
        required: query.required,
        nestedResults: results);
  }
}

FilterResult _handleSetQueryOption(
    List<String> option, List<FilterResult> credentials) {
  List<FilterResult> result = [];
  for (var identifier in option) {
    result.add(credentials.firstWhere(
        (e) => e.matchingDescriptorIds.contains(identifier),
        orElse: () => FilterResult(
            matchingDescriptorIds: [identifier],
            presentationDefinitionId: 'dcql',
            fulfilled: false)));
  }

  List<String> descriptorIds = [];
  List<VerifiableCredential> w3c = [];
  List<SdJws> sdJwt = [];
  List<IssuerSignedObject> mdoc = [];
  bool fulfilled = true;

  for (var r in result) {
    fulfilled = fulfilled && r.fulfilled;
    descriptorIds.addAll(r.matchingDescriptorIds);
    if (r.credentials != null) {
      w3c.addAll(r.credentials!);
    }
    if (r.sdJwtCredentials != null) {
      sdJwt.addAll(r.sdJwtCredentials!);
    }
    if (r.isoMdocCredentials != null) {
      mdoc.addAll(r.isoMdocCredentials!);
    }
  }
  return FilterResult(
      matchingDescriptorIds: descriptorIds,
      presentationDefinitionId: 'dcql',
      credentials: w3c.isEmpty ? null : w3c,
      sdJwtCredentials: sdJwt.isEmpty ? null : sdJwt,
      isoMdocCredentials: mdoc.isEmpty ? null : mdoc,
      fulfilled: fulfilled);
}

FilterResult _findCredentialsForCredentialQuery(CredentialQuery query,
    {List<VerifiableCredential>? w3cCredentials,
    List<SdJws>? sdJwtCredentials,
    List<IssuerSignedObject>? mdocCredentials}) {
  if (query.format == OidCredentialFormat.sdJwtDc ||
      query.format == OidCredentialFormat.sdJwt) {
    if (sdJwtCredentials == null || sdJwtCredentials.isEmpty) {
      return FilterResult(
          matchingDescriptorIds: [query.id],
          presentationDefinitionId: 'dcql',
          fulfilled: false);
    }

    List<SdJws> candidates = [];
    for (var cred in sdJwtCredentials) {
      if (query.meta != null && query.meta is CredentialQueryMetadataSdJwt) {
        var vct = cred.toSdJwt().additionalClaims?['vct'];
        if (vct != null) {
          var meta = query.meta as CredentialQueryMetadataSdJwt;
          if (!meta.vctValues.contains(vct)) continue;
        }
      }
      if (query.claims == null && query.claimSets == null) {
        candidates.add(cred);
      }
      bool isCandidate = false;
      List<String> containingClaims = [];
      if (query.claims != null) {
        (isCandidate, containingClaims) = _hasClaims(query.claims!,
            cred.toSdJwt().additionalClaims, query.claimSets != null);
      }
      if (query.claimSets != null) {
        if (containingClaims.isNotEmpty) {
          for (var c in query.claimSets!) {
            var intersect = c.toSet().intersection(containingClaims.toSet());
            if (intersect.length == c.length) {
              List<JsonPath> toDisclose = [];
              for (var id in c) {
                var cq =
                    query.claims!.firstWhere((element) => element.id == id);
                toDisclose.add(cq.path.toJsonPath());
              }
              candidates.add(cred.disclose(toDisclose));
            }
          }
        }
      } else {
        if (isCandidate) {
          List<JsonPath> toDisclose = [];
          for (var c in query.claims!) {
            toDisclose.add(c.path.toJsonPath());
          }

          candidates.add(cred.disclose(toDisclose));
        }
      }
    }

    if (candidates.isEmpty) {
      return FilterResult(
          matchingDescriptorIds: [query.id],
          presentationDefinitionId: 'dcql',
          fulfilled: false);
    } else {
      return FilterResult(
          matchingDescriptorIds: [query.id],
          presentationDefinitionId: 'dcql',
          fulfilled: true,
          sdJwtCredentials: candidates);
    }
  } else if (query.format == OidCredentialFormat.msoMdoc) {
    if (mdocCredentials == null || mdocCredentials.isEmpty) {
      return FilterResult(
          matchingDescriptorIds: [query.id],
          presentationDefinitionId: 'dcql',
          fulfilled: false);
    }

    List<IssuerSignedObject> candidates = [];
    for (var cred in mdocCredentials) {
      var mso = MobileSecurityObject.fromCbor(cred.issuerAuth.payload);

      if (query.meta != null && query.meta is CredentialQueryMetadataMsoMdoc) {
        var docType = mso.docType;
        var meta = query.meta as CredentialQueryMetadataMsoMdoc;
        if (meta.doctype != docType) continue;
      }

      if (query.claims == null && query.claimSets != null) {
        candidates.add(cred);
      }

      Map<String, dynamic> mapped = {};
      for (var nameSpace in cred.items.keys) {
        var data = cred.items[nameSpace]!;
        var mapPerNS = <String, dynamic>{};
        for (var i in data) {
          mapPerNS[i.dataElementIdentifier] = i.dataElementValue;
        }
        mapped[nameSpace] = mapPerNS;
      }

      bool isCandidate = false;
      List<String> containingClaims = [];
      if (query.claims != null) {
        (isCandidate, containingClaims) =
            _hasClaims(query.claims!, mapped, query.claimSets != null);
      }
      if (query.claimSets != null) {
        if (containingClaims.isNotEmpty) {
          for (var c in query.claimSets!) {
            var intersect = c.toSet().intersection(containingClaims.toSet());
            if (intersect.length == c.length) {
              Map<String, Map<String, bool>> toDisclose = {};
              for (var id in c) {
                var cq =
                    query.claims!.firstWhere((element) => element.id == id);
                var ns = cq.path.pointer.first;
                var key = cq.path.pointer.last;
                var inner = toDisclose[ns] ?? <String, bool>{};
                inner[key] = cq.intentToRetain ?? false;
                toDisclose[ns] = inner;
              }
              var r = getDataToReveal(
                  ItemsRequest(docType: mso.docType, nameSpaces: toDisclose),
                  cred);
              candidates.add(
                  IssuerSignedObject(issuerAuth: cred.issuerAuth, items: r));
            }
          }
        }
      } else {
        if (isCandidate) {
          Map<String, Map<String, bool>> toDisclose = {};
          for (var c in query.claims!) {
            var ns = c.path.pointer.first;
            var key = c.path.pointer.last;
            var inner = toDisclose[ns] ?? <String, bool>{};
            inner[key] = c.intentToRetain ?? false;
            toDisclose[ns] = inner;
          }
          var r = getDataToReveal(
              ItemsRequest(docType: mso.docType, nameSpaces: toDisclose), cred);
          candidates
              .add(IssuerSignedObject(issuerAuth: cred.issuerAuth, items: r));
        }
      }
    }

    if (candidates.isEmpty) {
      return FilterResult(
          matchingDescriptorIds: [query.id],
          presentationDefinitionId: 'dcql',
          fulfilled: false);
    } else {
      return FilterResult(
          matchingDescriptorIds: [query.id],
          presentationDefinitionId: 'dcql',
          fulfilled: true,
          isoMdocCredentials: candidates);
    }
  } else if (query.format == OidCredentialFormat.ldpVc) {
    if (w3cCredentials == null || w3cCredentials.isEmpty) {
      return FilterResult(
          matchingDescriptorIds: [query.id],
          presentationDefinitionId: 'dcql',
          fulfilled: false);
    }

    List<VerifiableCredential> candidates = [];
    for (var cred in w3cCredentials) {
      if (query.claims == null && query.claimSets == null) {
        candidates.add(cred);
      }
      bool isCandidate = false;
      List<String> containingClaims = [];
      if (query.claims != null) {
        (isCandidate, containingClaims) =
            _hasClaims(query.claims!, cred.toJson(), query.claimSets == null);
      }
      if (query.claimSets != null) {
        if (containingClaims.isNotEmpty) {
          for (var c in query.claimSets!) {
            var intersect = c.toSet().intersection(containingClaims.toSet());
            if (intersect.length == c.length) {
              candidates.add(cred);
              break;
            }
          }
        }
      } else {
        if (isCandidate) {
          candidates.add(cred);
        }
      }
    }

    if (candidates.isEmpty) {
      return FilterResult(
          matchingDescriptorIds: [query.id],
          presentationDefinitionId: 'dcql',
          fulfilled: false);
    } else {
      return FilterResult(
          credentials: candidates,
          matchingDescriptorIds: [query.id],
          presentationDefinitionId: 'dcql',
          fulfilled: true);
    }
  } else {
    throw Exception('Unsupported Format: ${query.format}');
  }
}

(bool, List<String>) _hasClaims(
    List<ClaimsQuery> query, dynamic credential, bool hasSet) {
  List<String> matches = [];
  bool match = true;
  for (var q in query) {
    if (hasSet && q.id == null) {
      throw Exception(
          'Malformed query: If claim_sets is present, every claims query must have an id parameter');
    }
    dynamic value;
    try {
      value = q.path.getValueForPath(credential);
    } catch (_) {}
    if (value != null) {
      if (q.values != null) {
        if (q.values!.contains(value) && q.id != null) {
          matches.add(q.id!);
        } else {
          match = false;
        }
      } else {
        if (q.id != null) {
          matches.add(q.id!);
        }
      }
    } else {
      match = false;
    }
  }
  return (match, matches);
}
