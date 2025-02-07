import 'dart:convert';

import 'package:dart_ssi/src/util/utils.dart';
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

  dynamic getValueForPath(dynamic jsonData) {
    var start = pointer.first;
    var value = jsonData[start];
    if (pointer.length == 1) {
      return value;
    }
  }

  List<dynamic> toJson() {
    return pointer;
  }
}

class DcqlQuery {
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
    if (data.containsKey('credentials_sets')) {
      var tmp = data['credentials_sets'] as List;
      cs = tmp.map((e) => CredentialSetQuery.fromJson(e)).toList();
    }

    return DcqlQuery(credentials: c, credentialSets: cs);
  }

  Map<String, dynamic> toJson() {
    var data = <String, dynamic>{
      'credentials': credentials.map((e) => e.toJson()).toList()
    };

    if (credentialSets != null) {
      data['credential_sets'] = credentialSets!.map((e) => e.toJson()).toList();
    }

    return data;
  }

  @override
  String toString() {
    return jsonEncode(toJson());
  }
}

class CredentialQuery {
  String id, format;
  CredentialQueryMetadata? meta;
  ClaimsQuery? claims;
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

    ClaimsQuery? c;
    if (data.containsKey('claims')) {
      c = ClaimsQuery.fromJson(data['claims']);
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

  Map<String, dynamic> toJson() {
    var data = <String, dynamic>{'id': id, 'format': format};
    if (meta != null) {
      data['meta'] = meta!.toJson();
    }
    if (claims != null) {
      data['claims'] = claims!.toJson();
    }
    if (claimSets != null) {
      data['claim_sets'] = claimSets;
    }

    return data;
  }

  @override
  String toString() {
    return jsonEncode(toJson());
  }
}

class CredentialSetQuery {
  List<String> options;
  bool required;
  String? purpose;

  CredentialSetQuery(
      {required this.options, this.required = true, this.purpose});

  factory CredentialSetQuery.fromJson(dynamic json) {
    var data = credentialToMap(json);
    List<String> opt = [];
    if (data.containsKey('options')) {
      opt = (data['options'] as List).cast<String>();
    } else {
      throw Exception('options field is required');
    }

    return CredentialSetQuery(
        options: opt,
        required: data['required'] ?? true,
        purpose: data['purpose']);
  }

  Map<String, dynamic> toJson() {
    var data = {'options': options, 'required': required};
    if (purpose != null) {
      data['purpose'] = purpose!;
    }
    return data;
  }

  @override
  toString() {
    return jsonEncode(toJson());
  }
}

class CredentialQueryMetadata {
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

  Map<String, dynamic> toJson() {
    return {};
  }

  @override
  toString() {
    return jsonEncode(toJson());
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

class ClaimsQuery {
  String? id;
  ClaimPathPointer path;
  List<dynamic>? values;

  ClaimsQuery({this.id, required this.path, this.values});

  factory ClaimsQuery.fromJson(dynamic json) {
    var data = credentialToMap(json);
    ClaimPathPointer p;
    if (data.containsKey('path')) {
      p = ClaimPathPointer.fromJson(data['path']);
    } else {
      throw Exception('path field is required');
    }

    return ClaimsQuery(path: p, id: data['id'], values: data['values']);
  }

  Map<String, dynamic> toJson() {
    var data = <String, dynamic>{'path': path.toJson()};
    if (id != null) {
      data['id'] = id!;
    }
    if (values != null) {
      data['values'] = values;
    }

    return data;
  }

  @override
  toString() {
    return jsonEncode(toJson());
  }
}
