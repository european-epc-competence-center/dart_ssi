import 'dart:convert';

import 'package:dart_ssi/credentials.dart';
import 'package:dart_ssi/src/oid/issuance.dart';
import 'package:dart_ssi/src/util/private_util.dart';
import 'package:iso_mdoc/iso_mdoc.dart' as iso;
import 'package:iso_mdoc/iso_mdoc.dart';
import 'package:json_path/json_path.dart';
import 'package:json_schema/json_schema.dart';
import 'package:sd_jwt/sd_jwt.dart' as sd_jwt;
import 'package:sd_jwt/sd_jwt.dart';
import 'package:uuid/uuid.dart';

import '../util/types.dart';
import '../util/utils.dart';

class PresentationDefinition extends JsonObject {
  late String id;
  late List<InputDescriptor> inputDescriptors;
  String? name;
  String? purpose;
  FormatProperty? format;
  List<SubmissionRequirement>? submissionRequirement;

  PresentationDefinition(
      {String? id,
      required this.inputDescriptors,
      this.name,
      this.purpose,
      this.format,
      this.submissionRequirement})
      : id = id ?? Uuid().v4();

  PresentationDefinition.fromJson(dynamic presentationDefinitionJson) {
    var definition = credentialToMap(presentationDefinitionJson);
    if (definition.containsKey('presentation_definition')) {
      definition = definition['presentation_definition'];
    }
    if (definition.containsKey('id')) {
      id = definition['id'];
    } else {
      throw FormatException('id property required in presentation definition');
    }

    if (definition.containsKey('input_descriptors')) {
      List tmp = definition['input_descriptors'];
      inputDescriptors = [];
      if (tmp.isNotEmpty) {
        for (var i in tmp) {
          inputDescriptors.add(InputDescriptor.fromJson(i));
        }
      }
    } else {
      throw FormatException(
          'input_descriptors property is required in presentation definition');
    }

    if (definition.containsKey('name')) name = definition['name'];
    if (definition.containsKey('purpose')) purpose = definition['purpose'];
    if (definition.containsKey('format')) {
      format = FormatProperty.fromJson(definition['format']);
    }

    if (definition.containsKey('submission_requirements')) {
      List tmp = definition['submission_requirements'];
      if (tmp.isNotEmpty) {
        submissionRequirement = [];
        for (var s in tmp) {
          submissionRequirement!.add(SubmissionRequirement.fromJson(s));
        }
      }
    }
  }

  @override
  Map<String, dynamic> toJson() {
    Map<String, dynamic> jsonObject = {};
    jsonObject['id'] = id;
    List input = [];
    for (var des in inputDescriptors) {
      input.add(des.toJson());
    }
    jsonObject['input_descriptors'] = input;
    if (name != null) jsonObject['name'] = name;
    if (purpose != null) jsonObject['purpose'] = purpose;
    if (format != null) jsonObject['format'] = format!.toJson();
    if (submissionRequirement != null) {
      List sr = [];
      for (var s in submissionRequirement!) {
        sr.add(s.toJson());
      }
      jsonObject['submission_requirements'] = sr;
    }
    return jsonObject;
  }
}

class InputDescriptor extends JsonObject {
  late String id;
  String? name;
  String? purpose;
  FormatProperty? format;
  InputDescriptorConstraints? constraints;
  List<String>? group;

  InputDescriptor(
      {String? id,
      this.name,
      this.purpose,
      this.format,
      this.constraints,
      this.group})
      : id = id ?? Uuid().v4();

  InputDescriptor.fromJson(dynamic inputDescriptorJson) {
    var input = credentialToMap(inputDescriptorJson);
    if (input.containsKey('id')) {
      id = input['id'];
    } else {
      throw FormatException('Input descriptor needs id property');
    }

    if (input.containsKey('name')) name = input['name'];
    if (input.containsKey('purpose')) purpose = input['purpose'];
    if (input.containsKey('constraints')) {
      constraints = InputDescriptorConstraints.fromJson(input['constraints']);
    }
    if (input.containsKey('format')) {
      format = FormatProperty.fromJson(input['format']);
    }
    if (input.containsKey('group')) group = input['group'].cast<String>();
  }

  @override
  Map<String, dynamic> toJson() {
    Map<String, dynamic> jsonObject = {};
    jsonObject['id'] = id;
    if (name != null) jsonObject['name'] = name;
    if (purpose != null) jsonObject['purpose'] = purpose;
    if (format != null) jsonObject['format'] = format!.toJson();
    if (constraints != null) jsonObject['constraints'] = constraints!.toJson();
    if (group != null) jsonObject['group'] = group;
    return jsonObject;
  }
}

class InputDescriptorConstraints extends JsonObject {
  List<InputDescriptorField>? fields;
  Limiting? limitDisclosure;

  /// Either `required` or `preferred`.
  ///
  /// - `required`: This indicates that the processing entity MUST submit a response that has been self-attested.
  /// - `preferred`: This indicates that it is RECOMMENDED that the processing entity submit a response that has been self-attested.
  Limiting? subjectIsIssuer;

  /// The is_holder property would be used by a Verifier to require that certain inputs be provided by a certain Subject
  HolderSubjectConstraint? isHolder;

  /// The same_subject property would be used by a Verifier to require that certain provided inputs be about the same Subject
  HolderSubjectConstraint? sameSubject;
  StatusObject? statuses;

  InputDescriptorConstraints(
      {this.fields,
      this.limitDisclosure,
      this.subjectIsIssuer,
      this.isHolder,
      this.sameSubject,
      this.statuses});

  InputDescriptorConstraints.fromJson(dynamic constraintsJson) {
    var constraints = credentialToMap(constraintsJson);
    if (constraints.containsKey('limit_disclosure')) {
      var ld = constraints['limit_disclosure'];
      if (ld == 'required') {
        limitDisclosure = Limiting.required;
      } else if (ld == 'preferred') {
        limitDisclosure = Limiting.preferred;
      } else {
        throw Exception('Unknown value in limit_disclosure');
      }
    }

    if (constraints.containsKey('fields')) {
      fields = [];
      List tmp = constraints['fields'];
      if (tmp.isNotEmpty) {
        for (var f in tmp) {
          fields!.add(InputDescriptorField.fromJson(f));
        }
      }
    }

    if (constraints.containsKey('subject_is_issuer')) {
      String sii = constraints['subject_is_issuer'];
      if (sii == 'required') {
        subjectIsIssuer = Limiting.required;
      } else if (sii == 'preferred') {
        subjectIsIssuer = Limiting.preferred;
      } else {
        throw Exception('Unknown value in limit_disclosure');
      }
    }

    if (constraints.containsKey('is_holder')) {
      isHolder = HolderSubjectConstraint.fromJson(constraints['is_holder']);
    }

    if (constraints.containsKey('same_subject')) {
      sameSubject =
          HolderSubjectConstraint.fromJson(constraints['same_subject']);
    }

    if (constraints.containsKey('statuses')) {
      statuses = StatusObject.fromJson(constraints['status']);
    }
  }

  @override
  Map<String, dynamic> toJson() {
    Map<String, dynamic> jsonObject = {};
    if (fields != null) {
      List field = [];
      for (var f in fields!) {
        field.add(f.toJson());
      }
      jsonObject['fields'] = field;
    }

    if (limitDisclosure != null) {
      if (limitDisclosure == Limiting.preferred) {
        jsonObject['limit_disclosure'] = 'preferred';
      } else {
        jsonObject['limit_disclosure'] = 'required';
      }
    }

    if (subjectIsIssuer != null) {
      if (subjectIsIssuer == Limiting.preferred) {
        jsonObject['subject_is_issuer'] = 'preferred';
      } else {
        jsonObject['subject_is_issuer'] = 'required';
      }
    }

    if (isHolder != null) jsonObject['is_holder'] = isHolder!.toJson();

    if (sameSubject != null) jsonObject['same_subject'] = sameSubject!.toJson();

    if (statuses != null) jsonObject['statuses'] = statuses!.toJson();

    return jsonObject;
  }
}

class InputDescriptorField extends JsonObject {
  late List<JsonPath> path;
  String? id;
  String? purpose;
  String? name;
  JsonSchema? filter;
  bool? optional;

  /// Either `required` or `preferred`.
  ///
  /// - `required`: This indicates that the returned value MUST be the boolean result of applying the value of the filter property to the result of evaluating the path property.
  /// - `preferred`: This indicates that the returned value SHOULD be the boolean result of applying the value of the filter property to the result of evaluating the path property.
  Limiting? predicate;

  InputDescriptorField(
      {required this.path,
      this.id,
      this.purpose,
      this.name,
      this.filter,
      this.optional,
      this.predicate});

  InputDescriptorField.fromJson(dynamic fieldJson) {
    var field = credentialToMap(fieldJson);
    if (field.containsKey('path')) {
      List pathString = field['path'];
      path = [];
      for (var p in pathString) {
        path.add(JsonPath(p));
      }
    } else {
      throw FormatException('InputDescriptor need path property');
    }

    if (field.containsKey('id')) id = field['id'];
    if (field.containsKey('purpose')) purpose = field['purpose'];
    if (field.containsKey('name')) name = field['name'];
    if (field.containsKey('filter')) {
      filter = JsonSchema.create(field['filter']);
    }
    if (field.containsKey('optional')) optional = field['optional'];
    if (field.containsKey('predicate')) {
      String p = field['predicate'];
      if (p == 'preferred') {
        predicate = Limiting.preferred;
      } else if (p == 'required') {
        predicate = Limiting.required;
      } else {
        throw Exception('Unknown value for predicate');
      }
    }
  }

  @override
  Map<String, dynamic> toJson() {
    Map<String, dynamic> jsonObject = {};
    List<String> paths = [];
    for (var p in path) {
      paths.add(p.toString());
    }
    jsonObject['path'] = paths;

    if (id != null) jsonObject['id'] = id;
    if (purpose != null) jsonObject['purpose'] = purpose;
    if (name != null) jsonObject['name'] = name;
    if (optional != null) jsonObject['optional'] = optional;

    if (filter != null) jsonObject['filter'] = jsonDecode(filter!.toJson());
    if (predicate != null) {
      if (predicate == Limiting.required) {
        jsonObject['predicate'] = 'required';
      } else {
        jsonObject['predicate'] = 'preferred';
      }
    }
    return jsonObject;
  }
}

class HolderSubjectConstraint extends JsonObject {
  /// Identifies the attributes whose Subject is of concern to the Verifier
  late List<String> fieldId;

  /// Either `required` or `preferred`.
  ///
  /// - `required`: This indicates that the processing entity MUST include proof that the Subject of each attribute identified by a value in the field_id array is the same as the entity submitting the response.
  /// - `preferred`: This indicates that it is RECOMMENDED that the processing entity include proof that the Subject of each attribute identified by a value in the field_id array is the same as the entity submitting the response.
  late Limiting directive;

  HolderSubjectConstraint({required this.fieldId, required this.directive});

  HolderSubjectConstraint.fromJson(dynamic isHolderObject) {
    Map<String, dynamic> ih = credentialToMap(isHolderObject);
    if (ih.containsKey('field_id')) {
      fieldId = ih['field_id'].cast<String>();
    } else {
      throw FormatException(
          'field_id property is required for is_holder Object');
    }

    if (ih.containsKey('directive')) {
      String value = ih['directive'];
      if (value == 'preferred') {
        directive = Limiting.preferred;
      } else if (value == 'required') {
        directive = Limiting.required;
      } else {
        throw Exception('Unknown value for directive property');
      }
    } else {
      throw FormatException(
          'directive property is required for is_holder object');
    }
  }

  @override
  Map<String, dynamic> toJson() {
    Map<String, dynamic> jsonObject = {};
    jsonObject['field_id'] = fieldId;
    if (directive == Limiting.required) {
      jsonObject['directive'] = 'required';
    } else {
      jsonObject['directive'] = 'preferred';
    }
    return jsonObject;
  }
}

class StatusObject extends JsonObject {
  StatusDirective? active;
  StatusDirective? suspended;
  StatusDirective? revoked;

  StatusObject({this.active, this.suspended, this.revoked}) {
    if (revoked == null && suspended == null && active == null) {
      throw FormatException(
          'One property out of active, revoked and suspended must be given');
    }
  }

  StatusObject.fromJson(dynamic statusInput) {
    Map<String, dynamic> stat = credentialToMap(statusInput);
    if (stat.containsKey('active')) {
      active = _determineDirective(stat['active']['directive']);
    }
    if (stat.containsKey('suspended')) {
      suspended = _determineDirective(stat['suspended']['directive']);
    }
    if (stat.containsKey('revoked')) {
      revoked = _determineDirective(stat['revoked']['directive']);
    }

    if (revoked == null && suspended == null && active == null) {
      throw FormatException(
          'One property out of active, revoked and suspended must be given');
    }
  }

  @override
  Map<String, dynamic> toJson() {
    Map<String, dynamic> jsonObject = {};
    if (active != null) {
      jsonObject['active'] = {'directive': _determineDirectiveString(active!)};
    }
    if (suspended != null) {
      jsonObject['suspended'] = {
        'directive': _determineDirectiveString(suspended!)
      };
    }
    if (revoked != null) {
      jsonObject['revoked'] = {
        'directive': _determineDirectiveString(revoked!)
      };
    }
    return jsonObject;
  }

  StatusDirective _determineDirective(String directive) {
    if (directive == 'required') {
      return StatusDirective.required;
    } else if (directive == 'allowed') {
      return StatusDirective.allowed;
    } else if (directive == 'disallowed') {
      return StatusDirective.disallowed;
    } else {
      throw Exception('Unknown Status-Directive value');
    }
  }

  String _determineDirectiveString(StatusDirective directive) {
    if (directive == StatusDirective.disallowed) {
      return 'disallowed';
    } else if (directive == StatusDirective.allowed) {
      return 'allowed';
    } else {
      return 'required';
    }
  }
}

class SubmissionRequirement extends JsonObject {
  late SubmissionRequirementRule rule;
  String? from;
  List<SubmissionRequirement>? fromNested;
  String? name;
  String? purpose;
  int? min, max, count;

  SubmissionRequirement(
      {required this.rule,
      this.from,
      this.fromNested,
      this.name,
      this.purpose,
      this.max,
      this.count,
      this.min}) {
    if (from == null && fromNested == null) {
      throw FormatException('Need either from or fromNested');
    }
    if (from != null && fromNested != null) {
      throw FormatException('Do nut use  from and fromNested together');
    }
  }

  SubmissionRequirement.fromJson(dynamic requirementJson) {
    var requirement = credentialToMap(requirementJson);
    if (requirement.containsKey('rule')) {
      var tmpRule = requirement['rule'];
      if (tmpRule == 'all') {
        rule = SubmissionRequirementRule.all;
      } else if (tmpRule == 'pick') {
        rule = SubmissionRequirementRule.pick;
        if (requirement.containsKey('min')) {
          var minTmp = requirement['min'];
          min = minTmp is int ? minTmp : int.parse(minTmp);
          if (min! < 0) {
            throw Exception('min value must be greater than or equal to zero');
          }
        }
        if (requirement.containsKey('max')) {
          var maxTmp = requirement['max'];
          max = maxTmp is int ? maxTmp : int.parse(maxTmp);
          if (max! <= 0) throw Exception('max value must be greater than zero');
          if (min != null && max! <= min!) {
            throw Exception('max must be greater than min');
          }
        }
        if (requirement.containsKey('count')) {
          var countTemp = requirement['count'];
          count = countTemp is int ? countTemp : int.parse(countTemp);
          if (count! <= 0) throw Exception('count must greater than zero');
        }
      } else {
        throw Exception('Unknown value for rule');
      }
    } else {
      throw FormatException('Rule property is required');
    }

    if (requirement.containsKey('from')) from = requirement['from'];
    if (requirement.containsKey('from_nested')) {
      List tmp = requirement['from_nested'];
      if (tmp.isNotEmpty) {
        fromNested = [];
        for (var s in tmp) {
          fromNested!.add(SubmissionRequirement.fromJson(s));
        }
      }
    }

    if (from == null && fromNested == null) {
      throw FormatException('Need either from or fromNested');
    }
    if (from != null && fromNested != null) {
      throw FormatException('Do nut use  from and fromNested together');
    }

    if (requirement.containsKey('name')) name = requirement['name'];
    if (requirement.containsKey('purpose')) purpose = requirement['purpose'];
  }

  @override
  Map<String, dynamic> toJson() {
    Map<String, dynamic> jsonObject = {};
    if (rule == SubmissionRequirementRule.pick) {
      jsonObject['rule'] = 'pick';
    } else {
      jsonObject['rule'] = 'all';
    }
    if (from != null) jsonObject['from'] = from;
    if (fromNested != null) {
      List tmp = [];
      for (var n in fromNested!) {
        tmp.add(n.toJson());
      }
      jsonObject['from_nested'] = tmp;
    }

    if (name != null) jsonObject['name'] = name;
    if (purpose != null) jsonObject['purpose'] = purpose;
    if (min != null) jsonObject['min'] = min;
    if (count != null) jsonObject['count'] = count;
    if (max != null) jsonObject['max'] = max;
    return jsonObject;
  }
}

class FormatProperty extends JsonObject {
  JwtFormat? jwt;
  JwtFormat? jwtVc;
  JwtFormat? jwtVp;
  LinkedDataProofFormat? ldp;
  LinkedDataProofFormat? ldpVc;
  LinkedDataProofFormat? ldpVp;
  MdocFormat? mdocFormat;
  SdJwtVcFormat? sdJwtVcFormat;

  FormatProperty(
      {this.jwt,
      this.jwtVc,
      this.jwtVp,
      this.ldp,
      this.ldpVc,
      this.ldpVp,
      this.mdocFormat,
      this.sdJwtVcFormat});

  FormatProperty.fromJson(dynamic formatJson) {
    var format = credentialToMap(formatJson);
    if (format.containsKey('jwt')) jwt = JwtFormat.fromJson(format['jwt']);
    if (format.containsKey('jwt_vc')) {
      jwtVc = JwtFormat.fromJson(format['jwt_vc']);
    }
    if (format.containsKey('jwt_vp')) {
      jwtVp = JwtFormat.fromJson(format['jwt_vp']);
    }
    if (format.containsKey('ldp')) {
      ldp = LinkedDataProofFormat.fromJson(format['ldp']);
    }
    if (format.containsKey(OidCredentialFormat.ldpVc)) {
      ldpVc = LinkedDataProofFormat.fromJson(format[OidCredentialFormat.ldpVc]);
    }
    if (format.containsKey('ldp_vp')) {
      ldpVp = LinkedDataProofFormat.fromJson(format['ldp_vp']);
    }
    if (format.containsKey(OidCredentialFormat.msoMdoc)) {
      mdocFormat = MdocFormat.fromJson(format[OidCredentialFormat.msoMdoc]);
    }
    if (format.containsKey(OidCredentialFormat.sdJwt)) {
      sdJwtVcFormat = SdJwtVcFormat.fromJson(format[OidCredentialFormat.sdJwt]);
    }
    if (format.containsKey(OidCredentialFormat.sdJwtDc)) {
      sdJwtVcFormat =
          SdJwtVcFormat.fromJson(format[OidCredentialFormat.sdJwtDc]);
    }
  }

  @override
  Map<String, dynamic> toJson() {
    Map<String, dynamic> jsonObject = {};
    if (jwt != null) jsonObject['jwt'] = jwt!.toJson();
    if (jwtVp != null) jsonObject['jwt_vp'] = jwtVp!.toJson();
    if (jwtVc != null) jsonObject['jwt_vc'] = jwtVc!.toJson();
    if (ldp != null) jsonObject['ldp'] = ldp!.toJson();
    if (ldpVp != null) jsonObject['ldp_vp'] = ldpVp!.toJson();
    if (ldpVc != null) jsonObject['ldp_vc'] = ldpVc!.toJson();
    if (mdocFormat != null) jsonObject['mso_mdoc'] = mdocFormat!.toJson();
    if (sdJwtVcFormat != null) {
      jsonObject[OidCredentialFormat.sdJwtDc] = sdJwtVcFormat!.toJson();
    }
    return jsonObject;
  }
}

class JwtFormat extends JsonObject {
  late List<String> algorithms;

  JwtFormat({required this.algorithms});

  JwtFormat.fromJson(dynamic jwtFormatJson) {
    var jwtAlg = credentialToMap(jwtFormatJson);
    if (jwtAlg.containsKey('alg')) {
      algorithms = jwtAlg['alg'].cast<String>();
    } else {
      throw FormatException('JwtFormat needs alg property');
    }
  }

  @override
  Map<String, dynamic> toJson() {
    return {'alg': algorithms};
  }
}

class MdocFormat extends JsonObject {
  late List<String> algorithms;

  MdocFormat({required this.algorithms});

  MdocFormat.fromJson(dynamic jwtFormatJson) {
    var jwtAlg = credentialToMap(jwtFormatJson);
    if (jwtAlg.containsKey('alg')) {
      algorithms = jwtAlg['alg'].cast<String>();
    } else {
      throw FormatException('Mdoc Format needs alg property');
    }
  }

  @override
  Map<String, dynamic> toJson() {
    return {'alg': algorithms};
  }
}

class SdJwtVcFormat extends JsonObject {
  List<String>? sdJwtAlgValues, kbJwtAlgValues;

  SdJwtVcFormat({this.sdJwtAlgValues, this.kbJwtAlgValues});

  SdJwtVcFormat.fromJson(dynamic jwtFormatJson) {
    var jwtAlg = credentialToMap(jwtFormatJson);
    if (jwtAlg.containsKey('sd-jwt_alg_values')) {
      sdJwtAlgValues = jwtAlg['sd-jwt_alg_values'].cast<String>();
    }

    if (jwtAlg.containsKey('kb-jwt_alg_values')) {
      kbJwtAlgValues = jwtAlg['kb-jwt_alg_values'].cast<String>();
    }
  }

  @override
  Map<String, dynamic> toJson() {
    Map<String, dynamic> json = {};
    if (sdJwtAlgValues != null) {
      json['sd-jwt_alg_values'] = sdJwtAlgValues;
    }
    if (kbJwtAlgValues != null) {
      json['kb-jwt_alg_values'] = kbJwtAlgValues;
    }
    return json;
  }
}

class LinkedDataProofFormat extends JsonObject {
  late List<String> proofType;

  LinkedDataProofFormat({required this.proofType});
  LinkedDataProofFormat.fromJson(dynamic proofTypeJson) {
    var proofTypeTmp = credentialToMap(proofTypeJson);
    if (proofTypeTmp.containsKey('proof_type')) {
      proofType = proofTypeTmp['proof_type'].cast<String>();
    } else {
      throw FormatException('JwtFormat needs proof_type property');
    }
  }

  @override
  Map<String, dynamic> toJson() {
    return {'proof_type': proofType};
  }
}

enum Limiting { required, preferred }

enum SubmissionRequirementRule { all, pick }

enum StatusDirective { required, allowed, disallowed }

/// Object used when a credential-List is filtered with a presentationDefinition or DcqlQuery
class FilterResult extends JsonObject {
  String presentationDefinitionId;
  SubmissionRequirement? submissionRequirement;
  List<String> matchingDescriptorIds;
  List<InputDescriptorConstraints>? selfIssuable;
  bool fulfilled;

  /// Whether this result is required; for presentation Definitions, every result is required
  bool required;

  /// Matching credentials in mdoc format
  List<IssuerSignedObject>? isoMdocCredentials;

  /// Matching credentials in sd_jwt format
  List<SdJws>? sdJwtCredentials;

  /// Matching credentials in w3c VCDM format
  List<VerifiableCredential>? credentials;

  /// Matching results, if from_nested is used in submission requirement or options
  /// of CredentialSetQuery contains more than one entry
  List<FilterResult>? nestedResults;

  FilterResult(
      {this.credentials,
      required this.matchingDescriptorIds,
      this.submissionRequirement,
      required this.presentationDefinitionId,
      this.nestedResults,
      this.selfIssuable,
      this.fulfilled = true,
      this.required = true,
      this.isoMdocCredentials,
      this.sdJwtCredentials});

  @override
  Map<String, dynamic> toJson() {
    Map<String, dynamic> jsonObject = {};

    if (credentials != null) {
      List creds = [];
      for (var c in credentials!) {
        creds.add(c.toJson());
      }
      jsonObject['credentials'] = creds;
    }
    if (submissionRequirement != null) {
      jsonObject['submissionRequirement'] = submissionRequirement!.toJson();
    }

    jsonObject['matchingDescriptorIds'] = matchingDescriptorIds;

    if (selfIssuable != null && selfIssuable!.isNotEmpty) {
      List self = [];
      for (var i in selfIssuable!) {
        self.add(i.toJson());
      }
      jsonObject['selfIssuable'] = self;
    }

    jsonObject['fulfilled'] = fulfilled;

    return jsonObject;
  }
}

//************** Presentation Submission **************************************
class PresentationSubmission extends JsonObject {
  late String id;
  late String presentationDefinitionId;
  late List<InputDescriptorMappingObject> descriptorMap;

  PresentationSubmission(
      {String? id,
      required this.presentationDefinitionId,
      required this.descriptorMap})
      : id = id ?? Uuid().v4();

  PresentationSubmission.fromJson(dynamic jsonObject) {
    Map<String, dynamic> submission = credentialToMap(jsonObject);
    if (submission.containsKey('id')) {
      id = submission['id'];
    } else {
      throw FormatException('Id Property is needed in presentation submission');
    }

    if (submission.containsKey('definition_id')) {
      presentationDefinitionId = submission['definition_id'];
    } else {
      throw FormatException(
          'Definition id is needed in presentation submission');
    }

    if (submission.containsKey('descriptor_map')) {
      List tmp = submission['descriptor_map'];
      descriptorMap = [];
      if (tmp.isNotEmpty) {
        for (var d in tmp) {
          descriptorMap.add(InputDescriptorMappingObject.fromJson(d));
        }
      }
    } else {
      throw FormatException(
          'descriptor_map property is needed in presentation submission');
    }
  }

  @override
  Map<String, dynamic> toJson() {
    Map<String, dynamic> jsonObject = {};
    jsonObject['id'] = id;
    jsonObject['definition_id'] = presentationDefinitionId;
    List tmp = [];
    for (var d in descriptorMap) {
      tmp.add(d.toJson());
    }
    jsonObject['descriptor_map'] = tmp;
    return jsonObject;
  }
}

class InputDescriptorMappingObject extends JsonObject {
  late String id;
  late String format;
  late JsonPath path;

  InputDescriptorMappingObject(
      {required this.id, required this.format, required this.path});

  InputDescriptorMappingObject.fromJson(dynamic jsonObject) {
    Map<String, dynamic> descriptor = credentialToMap(jsonObject);
    if (descriptor.containsKey('id')) {
      id = descriptor['id'];
    } else {
      throw Exception('Id property is needed in descriptor-Map Object');
    }

    if (descriptor.containsKey('format')) {
      format = descriptor['format'];
    } else {
      throw Exception('Format property is needed in descriptor-map object');
    }

    if (descriptor.containsKey('path')) {
      path = JsonPath(descriptor['path']);
    } else {
      throw Exception(' path property is needed in descriptor-map object');
    }
  }

  @override
  Map<String, dynamic> toJson() {
    Map<String, dynamic> jsonObject = {};
    jsonObject['id'] = id;
    jsonObject['format'] = format;
    jsonObject['path'] = path.toString();
    return jsonObject;
  }
}

List<FilterResult> searchCredentialsForPresentationDefinition(
    PresentationDefinition presentationDefinition,
    {List<VerifiableCredential>? credentials,
    List<iso.IssuerSignedObject>? isoMdocCredentials,
    List<sd_jwt.SdJws>? sdJwtCredentials}) {
  var globalFormat = presentationDefinition.format;
  if (globalFormat != null) {
    if (globalFormat.ldpVp != null ||
        globalFormat.ldp != null ||
        globalFormat.ldpVc != null) {
      if (credentials == null || credentials.isEmpty) {
        throw Exception('No credentials for this format');
      }
    } else if (globalFormat.mdocFormat != null) {
      if (isoMdocCredentials == null) {
        throw Exception('No credentials for this format');
      }
    } else if (globalFormat.sdJwtVcFormat != null) {
      if (sdJwtCredentials == null) {
        throw Exception('No credentials for this format');
      }
    } else {
      throw Exception('unsupported Format global');
    }
  }

  if (presentationDefinition.submissionRequirement != null) {
    Map<String, FilterResult> filterResultPerDescriptor = {};
    Map<String, dynamic> descriptorGroups = {};

    //search things for all descriptors
    for (var descriptor in presentationDefinition.inputDescriptors) {
      if (descriptor.group == null) {
        throw Exception('Ungrouped input descriptor');
      }

      //input descriptors per group
      for (var g in descriptor.group!) {
        if (descriptorGroups.containsKey(g)) {
          List<dynamic> gl = descriptorGroups[g];
          gl.add(descriptor.id);
          descriptorGroups[g] = gl;
        } else {
          descriptorGroups[g] = [descriptor.id];
        }
      }

      //credentials per descriptor
      var filteredCreds = _processInputDescriptor(
          presentationDefinition.id,
          descriptor,
          globalFormat,
          credentials,
          isoMdocCredentials,
          sdJwtCredentials);
      filterResultPerDescriptor[descriptor.id] = filteredCreds;
    }

    //Evaluate submission requirements
    List<FilterResult> finalCredList = [];
    for (var requirement in presentationDefinition.submissionRequirement!) {
      finalCredList.add(_processSubmissionRequirement(filterResultPerDescriptor,
          descriptorGroups, requirement, presentationDefinition.id));
    }
    return finalCredList;
  } else {
    List<FilterResult> finalResult = [];
    for (var descriptor in presentationDefinition.inputDescriptors) {
      // Without any requirements, all input_descriptors must be fulfilled
      // but can be fulfilled with different credentials
      var result = _processInputDescriptor(
          presentationDefinition.id,
          descriptor,
          globalFormat,
          credentials,
          isoMdocCredentials,
          sdJwtCredentials);
      finalResult.add(result);
    }
    return finalResult;
  }
}

FilterResult _processSubmissionRequirement(
    Map<String, FilterResult> filterResultPerDescriptor,
    Map<String, dynamic> descriptorGroups,
    SubmissionRequirement requirement,
    String definitionId) {
  if (requirement.fromNested != null && requirement.fromNested!.isNotEmpty) {
    List<FilterResult> result = [];
    for (var nestedRequirement in requirement.fromNested!) {
      result.add(_processSubmissionRequirement(filterResultPerDescriptor,
          descriptorGroups, nestedRequirement, definitionId));
    }

    bool fulfilled = true;
    if (requirement.rule == SubmissionRequirementRule.all) {
      for (var r in result) {
        if (!r.fulfilled) {
          fulfilled = false;
        }
        break;
      }
    } else if (requirement.rule == SubmissionRequirementRule.pick) {
      int f = 0;
      for (var r in result) {
        if (r.fulfilled) f++;
      }

      if (requirement.min != null && f < requirement.min!) {
        fulfilled = false;
      }
      if (requirement.count != null && f < requirement.count!) {
        fulfilled = false;
      }
    }

    return FilterResult(
        matchingDescriptorIds: [],
        presentationDefinitionId: definitionId,
        fulfilled: fulfilled,
        nestedResults: result);
  }

  List<String> accordingDescriptors = descriptorGroups[requirement.from];
  List<VerifiableCredential> creds = [];
  List<iso.IssuerSignedObject> credsIso = [];
  List<sd_jwt.SdJws> credsSd = [];
  List<InputDescriptorConstraints> selfIssuable = [];
  bool fulfilled = true;

  for (String d in accordingDescriptors) {
    var descriptor = filterResultPerDescriptor[d]!;
    if (descriptor.selfIssuable != null) {
      selfIssuable.addAll(descriptor.selfIssuable!);
    }

    var credsForDescriptor = descriptor.credentials;
    var credsForDescriptorIso = descriptor.isoMdocCredentials;
    var credsForDescriptorSd = descriptor.sdJwtCredentials;

    if (requirement.rule == SubmissionRequirementRule.all) {
      bool isoFulfilled = true;
      bool w3cFulfilled = true;
      bool sdFulfilled = true;
      if ((credsForDescriptor == null || credsForDescriptor.isEmpty) &&
          descriptor.selfIssuable == null) {
        w3cFulfilled = false;
      }
      if ((credsForDescriptorIso == null || credsForDescriptorIso.isEmpty) &&
          descriptor.selfIssuable == null) {
        isoFulfilled = false;
      }
      if ((credsForDescriptorSd == null || credsForDescriptorSd.isEmpty) &&
          descriptor.selfIssuable == null) {
        sdFulfilled = false;
      }

      if (w3cFulfilled == false &&
          isoFulfilled == false &&
          sdFulfilled == false) {
        fulfilled = false;
      }
    }

    if (credsForDescriptor != null) {
      if (creds.isEmpty) {
        creds = credsForDescriptor;
      } else {
        List<VerifiableCredential> toAdd = [];
        for (var c1 in credsForDescriptor) {
          if (!_containsCredential(creds, c1)) toAdd.add(c1);
        }

        creds += toAdd;
      }
    }

    if (credsForDescriptorIso != null) {
      if (credsIso.isEmpty) {
        credsIso = credsForDescriptorIso;
      } else {
        List<iso.IssuerSignedObject> toAdd = [];
        for (var c1 in credsForDescriptorIso) {
          if (!_containsCredentialIso(credsIso, c1)) toAdd.add(c1);
        }
        credsIso += toAdd;
      }
    }

    if (credsForDescriptorSd != null) {
      if (creds.isEmpty) {
        credsSd = credsForDescriptorSd;
      } else {
        List<sd_jwt.SdJws> toAdd = [];
        for (var c1 in credsForDescriptorSd) {
          if (!_containsCredentialSd(credsSd, c1)) toAdd.add(c1);
        }
        credsSd += toAdd;
      }
    }
  }

  if (requirement.rule == SubmissionRequirementRule.pick) {
    int notLower = 0;
    if (requirement.count != null) notLower = requirement.count!;
    if (requirement.min != null) notLower = requirement.min!;
    if (creds.length + credsIso.length < notLower && selfIssuable.isEmpty) {
      fulfilled = false;
    }
  }

  return FilterResult(
      selfIssuable: selfIssuable.isNotEmpty ? selfIssuable : null,
      credentials: creds.isEmpty ? null : creds,
      isoMdocCredentials: credsIso.isEmpty ? null : credsIso,
      sdJwtCredentials: credsSd.isEmpty ? null : credsSd,
      matchingDescriptorIds: accordingDescriptors,
      submissionRequirement: requirement,
      presentationDefinitionId: definitionId,
      fulfilled: fulfilled);
}

bool _containsCredential(
    List<VerifiableCredential> toCheck, VerifiableCredential candidate) {
  for (var c in toCheck) {
    if (c.proof?.proofValue != null && candidate.proof?.proofValue != null) {
      if (c.proof!.proofValue! == candidate.proof!.proofValue) {
        return true;
      }
    } else if (c.proof?.jws != null && candidate.proof?.jws != null) {
      if (c.proof!.jws! == candidate.proof!.jws) {
        return true;
      }
    }
  }

  return false;
}

bool _containsCredentialIso(
    List<iso.IssuerSignedObject> toCheck, iso.IssuerSignedObject candidate) {
  for (var c in toCheck) {
    if (listEquals(
        c.issuerAuth.signature ?? [], c.issuerAuth.signature ?? [])) {
      return true;
    }
  }

  return false;
}

bool _containsCredentialSd(List<sd_jwt.SdJws> toCheck, sd_jwt.SdJws candidate) {
  var parsed = toCheck.map((e) => e.toCompactSerialization()).toList();
  return parsed.contains(candidate.toCompactSerialization());
}

List<VerifiableCredential> _filterW3cVc(InputDescriptor descriptor,
    List<VerifiableCredential> credentials, FormatProperty? format) {
  List<VerifiableCredential> candidateW3C = [];

  if (descriptor.constraints?.fields != null) {
    var fields = descriptor.constraints!.fields!;

    List<Map<String, dynamic>> parsed;
    if (descriptor.constraints!.subjectIsIssuer != null &&
        descriptor.constraints!.subjectIsIssuer! == Limiting.required) {
      parsed = [];
      for (var cred in credentials) {
        if (cred.isSelfIssued()) {
          parsed.add(cred.toJson());
        }
      }
    } else {
      parsed = credentials.map((e) => e.toJson()).toList();
    }
    List<Map<String, dynamic>> res;
    (res, _, _) = _evaluateInputDescriptorFields(fields, parsed);
    candidateW3C = res.map((e) => VerifiableCredential.fromJson(e)).toList();
  } else {
    candidateW3C = credentials;
  }

  //check against format
  if (format != null) {
    List<VerifiableCredential> candidateFormatFiltered = [];
    for (var cred in candidateW3C) {
      String credProofFormat = cred.proof!.type;
      if (format.ldpVc != null) {
        if (format.ldpVc!.proofType.contains(credProofFormat)) {
          candidateFormatFiltered.add(cred);
        }
      }
    }
    candidateW3C = candidateFormatFiltered;
  }

  return candidateW3C;
}

List<iso.IssuerSignedObject> _filterMdocCredentials(
    InputDescriptor descriptor, List<iso.IssuerSignedObject> credentials) {
  List<iso.IssuerSignedObject> candidateIso = [];

  print('start filter mdoc');
  List<Map<String, dynamic>> input = [];
  List<iso.IssuerSignedObject> undisclosedCreds = [];
  for (int i = 0; i < credentials.length; i++) {
    var c = credentials[i];
    var mso = iso.MobileSecurityObject.fromCbor(c.issuerAuth.payload);
    Map<String, dynamic> mapped = {};

    mapped['_id'] = i;
    if (mso.docType == descriptor.id) {
      undisclosedCreds.add(c);
      for (var nameSpace in c.items.keys) {
        var data = c.items[nameSpace]!;
        var mapPerNS = <String, dynamic>{};
        for (var i in data) {
          mapPerNS[i.dataElementIdentifier] = i.dataElementValue;
        }
        mapped[nameSpace] = mapPerNS;
      }

      input.add(mapped);
    }
  }
  if (input.isNotEmpty && descriptor.constraints?.fields != null) {
    var fields = descriptor.constraints!.fields!;
    List<Map<String, dynamic>> res;
    Map<String, Map<String, bool>> res2;
    print(input.length);
    print(input);
    (res, res2, _) = _evaluateInputDescriptorFields(fields, input);
    print(res);
    for (var candidate in res) {
      var id = candidate['_id'] is int
          ? candidate['_id']
          : int.parse(candidate['_id']);
      var cred = credentials[id];
      var mso = iso.MobileSecurityObject.fromCbor(cred.issuerAuth.payload);
      var r = iso.getDataToReveal(
          iso.ItemsRequest(docType: mso.docType, nameSpaces: res2), cred);
      candidateIso
          .add(iso.IssuerSignedObject(issuerAuth: cred.issuerAuth, items: r));
    }
  } else {
    candidateIso = undisclosedCreds;
  }

  return candidateIso;
}

List<sd_jwt.SdJws> _filterSdJwt(
    InputDescriptor descriptor, List<sd_jwt.SdJws> credentials) {
  List<sd_jwt.SdJws> candidateSdJwt = [];

  if (descriptor.constraints?.fields != null) {
    List<Map<String, dynamic>> input = [];
    for (int i = 0; i < credentials.length; i++) {
      var sdJws = credentials[i];
      var sd = sdJws.toSdJwt();
      var c = sd.additionalClaims ?? {};
      c['_id'] = i;
      input.add(c);
    }
    List<Map<String, dynamic>> res;
    List<JsonPath> res2;
    (res, _, res2) =
        _evaluateInputDescriptorFields(descriptor.constraints!.fields!, input);
    print(res);

    for (var candidate in res) {
      var id = candidate['_id'] is int
          ? candidate['_id']
          : int.parse(candidate['_id']);
      var cred = credentials[id];
      if (descriptor.constraints?.limitDisclosure != null) {
        var disclosed = cred.disclose(res2);
        candidateSdJwt.add(disclosed);
      } else {
        candidateSdJwt.add(cred);
      }
    }
  }

  return candidateSdJwt;
}

FilterResult _processInputDescriptor(
    String definitionId,
    InputDescriptor descriptor,
    FormatProperty? globalFormat,
    List<VerifiableCredential>? credentials,
    List<iso.IssuerSignedObject>? isoMdocCredentials,
    List<sd_jwt.SdJws>? sdJwtCredentials) {
  List<VerifiableCredential> candidateW3C = [];
  List<iso.IssuerSignedObject> candidateIso = [];
  List<sd_jwt.SdJws> candidateSdJwt = [];

  // evaluate Format
  var localFormat = descriptor.format ?? globalFormat;
  if (localFormat != null) {
    if (localFormat.ldpVp != null ||
        localFormat.ldp != null ||
        localFormat.ldpVc != null) {
      if (credentials != null && credentials.isNotEmpty) {
        candidateW3C = _filterW3cVc(descriptor, credentials, localFormat);
      }
    } else if (localFormat.mdocFormat != null &&
        isoMdocCredentials != null &&
        isoMdocCredentials.isNotEmpty) {
      candidateIso = _filterMdocCredentials(descriptor, isoMdocCredentials);
    } else if (localFormat.sdJwtVcFormat != null &&
        sdJwtCredentials != null &&
        sdJwtCredentials.isNotEmpty) {
      candidateSdJwt = _filterSdJwt(descriptor, sdJwtCredentials);
    } else {
      throw Exception('unsupported Format');
    }
  } else {
    candidateW3C = _filterW3cVc(descriptor, credentials ?? [], null);
    candidateIso = _filterMdocCredentials(descriptor, isoMdocCredentials ?? []);
    candidateSdJwt = _filterSdJwt(descriptor, sdJwtCredentials ?? []);
  }

  // if (descriptor.constraints!.isHolder != null) {
  //   throw UnimplementedError('is_holder property is not supported yet');
  // }
  // if (descriptor.constraints!.sameSubject != null) {
  //   throw UnimplementedError('same_subject feature is not supported yet');
  // }
  // if (descriptor.constraints!.statuses != null) {
  //   throw UnimplementedError('statuses feature is not supported yet');
  // }

  return FilterResult(
      selfIssuable: descriptor.constraints?.subjectIsIssuer != null
          ? [descriptor.constraints!]
          : null,
      credentials: candidateW3C.isEmpty ? null : candidateW3C,
      matchingDescriptorIds: [descriptor.id],
      presentationDefinitionId: definitionId,
      isoMdocCredentials: candidateIso.isEmpty ? null : candidateIso,
      sdJwtCredentials: candidateSdJwt.isEmpty ? null : candidateSdJwt);
}

(
  List<Map<String, dynamic>>,
  Map<String, Map<String, bool>> namespaces,
  List<JsonPath>
) _evaluateInputDescriptorFields(List<InputDescriptorField> inputFields,
    List<Map<String, dynamic>> credentials) {
  List<Map<String, dynamic>> candidate = [];
  Map<String, Map<String, bool>> namespaces = {};
  List<JsonPath> paths = [];

  for (var cred in credentials) {
    Set<bool> isCandidateSet = {};
    for (var field in inputFields) {
      if (field.predicate != null) {
        throw UnimplementedError(
            'Evaluating predicate feature is not supported yet');
      }
      bool pathMatch = false;

      for (var path in field.path) {
        paths.add(path);
        var pathString = path.toString();
        var split = pathString.split('[');
        if (split.length >= 3) {
          var ns = split[1].replaceAll(']', '').replaceAll('\'', '');
          var prop = split[2].replaceAll(']', '').replaceAll('\'', '');
          var nsMap = namespaces[ns] ?? <String, bool>{};
          nsMap[prop] = false;
          namespaces[ns] = nsMap;
        }

        var match = path.read(cred);
        var matchList = match.toList();
        if (matchList.isEmpty &&
            (field.optional == null || field.optional == false)) {
          continue;
        }
        if (field.filter != null) {
          if (field.filter!.validate(matchList[0].value).isValid &&
              (field.optional == null || field.optional == false)) {
            pathMatch = true;
          }
        } else {
          pathMatch = true;
        }
      }
      isCandidateSet.add(pathMatch);
    }
    if (isCandidateSet.length == 1 && isCandidateSet.first) {
      candidate.add(cred);
    }
  }

  return (candidate, namespaces, paths);
}
