import 'package:dart_ssi/credentials.dart';
import 'package:dart_ssi/oid.dart';
import 'package:test/expect.dart';
import 'package:test/scaffolding.dart';

import 'example_credentials.dart';

void main() {
  group('pointer.getValueForPath', () {
    final exampleJson = {
      'key': 'value',
      'object': {'o': 't', 'o2': 6},
      'array': ['a', 'b', 'c'],
      'objectArray': [
        {'k': 1, 'i': 1},
        {'k': 2, 'i': 2}
      ]
    };

    test('simple key value', () {
      var pointer = ClaimPathPointer(['key']);
      var value = pointer.getValueForPath(exampleJson);
      expect(value, 'value');
    });

    test('nested key value', () {
      var pointer = ClaimPathPointer(['object', 'o']);
      var value = pointer.getValueForPath(exampleJson);
      expect(value, 't');
    });

    test('get array', () {
      var pointer = ClaimPathPointer(['array']);
      var value = pointer.getValueForPath(exampleJson);
      expect(value, isList);
      expect(value.length, 3);
    });

    test('one array element', () {
      var pointer = ClaimPathPointer(['array', 1]);
      var value = pointer.getValueForPath(exampleJson);
      expect(value, 'b');
    });

    test('array out of bounds', () {
      var pointer = ClaimPathPointer(['array', 5]);
      var value = pointer.getValueForPath(exampleJson);
      expect(value, null);
    });

    test('data of all objects in an array', () {
      var pointer = ClaimPathPointer(['objectArray', null, 'i']);
      var value = pointer.getValueForPath(exampleJson);
      expect(value, isList);
      expect(value.length, 2);
      expect(value.contains(1), isTrue);
      expect(value.contains(2), isTrue);
    });
  });

  group('simple filtering via format and type', () {
    test('presentationDefinition, ldp_vc', () {
      var definition = {
        "id": "example_sd_jwt_vc_request",
        "input_descriptors": [
          {
            "id": "identity_credential",
            "format": {
              "ldp_vc": {
                'proof_type': ['EdDsaSignature2022']
              }
            },
            "constraints": {
              "limit_disclosure": "required",
              "fields": [
                {
                  "path": [r"$.type"],
                  "filter": {
                    "type": "array",
                    "contains": {'type': 'string', 'const': 'TestVc2'}
                  }
                }
              ]
            }
          }
        ]
      };

      var result = searchCredentialsForPresentationDefinition(
          PresentationDefinition.fromJson(definition),
          credentials: [w3cVc1, w3cVc2, w3cVc3],
          sdJwtCredentials: [sdJwt1, sdJwt2],
          isoMdocCredentials: [msoVc1, msoVc2]);

      expect(result.length, 1);

      var f1 = result.first;
      expect(f1.fulfilled, isTrue);
      expect(f1.sdJwtCredentials, null);
      expect(f1.credentials?.length, 1);
      expect(f1.isoMdocCredentials, null);
      expect(f1.nestedResults, null);
      expect(f1.matchingDescriptorIds.contains('identity_credential'), isTrue);
      expect(f1.matchingDescriptorIds.length, 1);
    });
    test('presentationDefinition, sd_jwt', () {
      var definition = {
        "id": "example_sd_jwt_vc_request",
        "input_descriptors": [
          {
            "id": "identity_credential",
            "format": {"dc+sd-jwt": {}},
            "constraints": {
              "limit_disclosure": "required",
              "fields": [
                {
                  "path": [r"$.vct"],
                  "filter": {"type": "string", "const": "TestVc2"}
                }
              ]
            }
          }
        ]
      };

      var result = searchCredentialsForPresentationDefinition(
          PresentationDefinition.fromJson(definition),
          credentials: [w3cVc1, w3cVc2, w3cVc3],
          sdJwtCredentials: [sdJwt1, sdJwt2],
          isoMdocCredentials: [msoVc1, msoVc2]);

      expect(result.length, 1);

      var f1 = result.first;
      expect(f1.fulfilled, isTrue);
      expect(f1.sdJwtCredentials?.length, 1);
      expect(f1.credentials, null);
      expect(f1.isoMdocCredentials, null);
      expect(f1.nestedResults, null);
      expect(f1.matchingDescriptorIds.contains('identity_credential'), isTrue);
      expect(f1.matchingDescriptorIds.length, 1);

      // check disclosure state: because limit_disclosure = required, nothing should be disclosed
      var c1 = f1.sdJwtCredentials!.first;
      expect(c1.disclosures, isEmpty);
      expect(c1.toSdJwt().additionalClaims?.keys.length, 2);
      expect(c1.toSdJwt().additionalClaims?.keys.contains('vct'), isTrue);
      expect(c1.toSdJwt().additionalClaims?.keys.contains('driving_privilege'),
          isTrue);
      expect(
          c1.toSdJwt().additionalClaims?['driving_privilege'].first, isEmpty);
      expect(c1.toSdJwt().additionalClaims?['driving_privilege'].last, isEmpty);
      expect(c1.toSdJwt().additionalClaims?['driving_privilege'].length, 2);
    });
    test('presentationDefinition, sd_jwt, no limit_disclosure', () {
      var definition = {
        "id": "example_sd_jwt_vc_request",
        "input_descriptors": [
          {
            "id": "identity_credential",
            "format": {"dc+sd-jwt": {}},
            "constraints": {
              "fields": [
                {
                  "path": [r"$.vct"],
                  "filter": {"type": "string", "const": "TestVc2"}
                }
              ]
            }
          }
        ]
      };

      var result = searchCredentialsForPresentationDefinition(
          PresentationDefinition.fromJson(definition),
          credentials: [w3cVc1, w3cVc2, w3cVc3],
          sdJwtCredentials: [sdJwt1, sdJwt2],
          isoMdocCredentials: [msoVc1, msoVc2]);

      expect(result.length, 1);

      var f1 = result.first;
      expect(f1.fulfilled, isTrue);
      expect(f1.sdJwtCredentials?.length, 1);
      expect(f1.credentials, null);
      expect(f1.isoMdocCredentials, null);
      expect(f1.nestedResults, null);
      expect(f1.matchingDescriptorIds.contains('identity_credential'), isTrue);
      expect(f1.matchingDescriptorIds.length, 1);

      // check disclosure state: because limit_disclosure is not present every claim is shown
      var c1 = f1.sdJwtCredentials!.first;
      expect(c1.disclosures?.length, sdJwt2.disclosures?.length);
      expect(c1.toSdJwt().additionalClaims?.keys.length,
          sdJwt2.toSdJwt().additionalClaims?.length);
    });
    test('presentationDefinition, mso_mdoc', () {
      var definition = {
        "id": "example_sd_jwt_vc_request",
        "input_descriptors": [
          {
            "id": "org.iso.18013.5.1.mDL",
            "format": {
              "mso_mdoc": {
                'alg': ['1']
              }
            },
          }
        ]
      };

      var result = searchCredentialsForPresentationDefinition(
          PresentationDefinition.fromJson(definition),
          credentials: [w3cVc1, w3cVc2, w3cVc3],
          sdJwtCredentials: [sdJwt1, sdJwt2],
          isoMdocCredentials: [msoVc1, msoVc2]);

      expect(result.length, 1);

      var f1 = result.first;
      expect(f1.fulfilled, isTrue);
      expect(f1.sdJwtCredentials, null);
      expect(f1.credentials, null);
      expect(f1.isoMdocCredentials?.length, 1);
      expect(f1.nestedResults, null);
      expect(
          f1.matchingDescriptorIds.contains('org.iso.18013.5.1.mDL'), isTrue);
      expect(f1.matchingDescriptorIds.length, 1);
      // check disclose state: because constraints is not present, every property is presented
      var c1 = f1.isoMdocCredentials!.first;
      expect(c1.items.length, 1);
      var n1 = c1.items['org.iso.18013.5.1'];
      expect(n1?.length, 3);
    });
    test('dcql, ldp_vc', () {
      // not possible now
      // value filtering only allowed for strings, integer boolean and
      // metadata definition not present for this credential type
    });
    test('dcql, sd_jwt', () {
      var query = {
        "credentials": [
          {
            "id": "my_credential",
            "format": "dc+sd-jwt",
            "meta": {
              "vct_values": ["TestVc2"]
            },
          }
        ]
      };
      var result = searchCredentialsForDcqlQuery(DcqlQuery.fromJson(query),
          w3cCredentials: [w3cVc1, w3cVc2, w3cVc3],
          sdJwtCredentials: [sdJwt1, sdJwt2],
          mdocCredentials: [msoVc1, msoVc2]);

      expect(result.length, 1);

      var f1 = result.first;
      expect(f1.fulfilled, isTrue);
      expect(f1.sdJwtCredentials?.length, 1);
      expect(f1.credentials, null);
      expect(f1.isoMdocCredentials, null);
      expect(f1.nestedResults, null);
      expect(f1.matchingDescriptorIds.contains('my_credential'), isTrue);
      expect(f1.matchingDescriptorIds.length, 1);

      // check disclose state: because claims is not present, every shall be disclosed
      var c1 = f1.sdJwtCredentials!.first;
      expect(c1.disclosures?.length, sdJwt2.disclosures?.length);
      expect(
          c1.toSdJwt().disclosures.length, sdJwt2.toSdJwt().disclosures.length);
      var cl1 = c1.toSdJwt().additionalClaims?.keys;
      var clo = sdJwt2.toSdJwt().additionalClaims?.keys;
      expect(clo?.length, cl1?.length);
      expect(clo!.toSet().intersection(cl1!.toSet()).length, clo.length);
    });
    test('dcql, mso_mdoc', () {
      var query = {
        "credentials": [
          {
            "id": "my_credential",
            "format": "mso_mdoc",
            "meta": {"doctype_value": "org.iso.18013.5.1.mDL"},
          }
        ]
      };
      var result = searchCredentialsForDcqlQuery(DcqlQuery.fromJson(query),
          w3cCredentials: [w3cVc1, w3cVc2, w3cVc3],
          sdJwtCredentials: [sdJwt1, sdJwt2],
          mdocCredentials: [msoVc1, msoVc2]);

      expect(result.length, 1);

      var f1 = result.first;
      expect(f1.fulfilled, isTrue);
      expect(f1.sdJwtCredentials, null);
      expect(f1.credentials, null);
      expect(f1.isoMdocCredentials?.length, 1);
      expect(f1.nestedResults, null);
      expect(f1.matchingDescriptorIds.contains('my_credential'), isTrue);
      expect(f1.matchingDescriptorIds.length, 1);

      // check disclose state: because claims is not present, every shall be disclosed
      var c1 = f1.isoMdocCredentials!.first;
      expect(c1.items.length, 1);
      var n1 = c1.items['org.iso.18013.5.1'];
      expect(n1?.length, 3);
    });
  });

  group(
      'filter for credentials which has requested attribute regardless of format',
      () {
    test('presentation definition, no mdoc', () {
      // This will never return mdoc credentials (descriptor id wont match a doctype)
      var definition = {
        "id": "example_sd_jwt_vc_request",
        "input_descriptors": [
          {
            "id": "family_name",
            "constraints": {
              'limit_disclosure': 'required',
              "fields": [
                {
                  "path": [r"$..family_name"],
                }
              ]
            }
          }
        ]
      };

      var result = searchCredentialsForPresentationDefinition(
          PresentationDefinition.fromJson(definition),
          credentials: [w3cVc1, w3cVc2, w3cVc3],
          sdJwtCredentials: [sdJwt1, sdJwt2],
          isoMdocCredentials: [msoVc1, msoVc2]);

      expect(result.length, 1);

      var f1 = result.first;
      expect(f1.fulfilled, isTrue);
      expect(f1.sdJwtCredentials?.length, 1);
      expect(f1.credentials?.length, 1);
      expect(f1.isoMdocCredentials, null);
      expect(f1.nestedResults, null);
      expect(f1.matchingDescriptorIds.contains('family_name'), isTrue);
      expect(f1.matchingDescriptorIds.length, 1);
      // check disclosure: only family_name
      var c1sd = f1.sdJwtCredentials!.first;
      expect(c1sd.disclosures?.length, 1);
      expect(c1sd.toSdJwt().additionalClaims?.length, 3);
      expect(c1sd.toSdJwt().additionalClaims?.keys.contains('family_name'),
          isTrue);
      expect(c1sd.toSdJwt().additionalClaims?.keys.contains('vct'), isTrue);
      // this empty map is always disclosed because of structure of the credential
      expect(
          c1sd.toSdJwt().additionalClaims?.keys.contains('age_equal_or_over'),
          isTrue);
    });
    test('dcql', () {
      var query = {
        "credentials": [
          {
            "id": "mso_mdoc",
            "format": "mso_mdoc",
            'claims': [
              {
                "path": ["org.iso.18013.5.1", "family_name"]
              }
            ]
          },
          {
            "id": "ldp",
            "format": "ldp_vc",
            'claims': [
              {
                "path": ["credentialSubject", "family_name"]
              }
            ]
          },
          {
            "id": "sd_jwt",
            "format": "dc+sd-jwt",
            'claims': [
              {
                "path": ["family_name"]
              }
            ]
          },
        ],
        'credential_sets': [
          {
            "purpose": "familyName",
            "options": [
              ["mso_mdoc"],
              ["sd_jwt"],
              ["ldp"]
            ]
          },
        ]
      };
      var result = searchCredentialsForDcqlQuery(DcqlQuery.fromJson(query),
          w3cCredentials: [w3cVc1, w3cVc2, w3cVc3],
          sdJwtCredentials: [sdJwt1, sdJwt2],
          mdocCredentials: [msoVc1, msoVc2]);

      expect(result.length, 1);

      var f1 = result.first;
      expect(f1.fulfilled, isTrue);
      expect(f1.sdJwtCredentials, null);
      expect(f1.credentials, null);
      expect(f1.isoMdocCredentials, null);
      expect(f1.nestedResults?.length, 3);
      expect(f1.matchingDescriptorIds.length, 0);

      // order of the nested results must be the same as the order in options
      var n1 = f1.nestedResults!.first;
      expect(n1.matchingDescriptorIds.contains('mso_mdoc'), isTrue);
      expect(n1.fulfilled, isTrue);
      expect(n1.sdJwtCredentials, null);
      expect(n1.credentials, null);
      expect(n1.isoMdocCredentials?.length, 2);
      expect(n1.nestedResults, null);
      expect(n1.matchingDescriptorIds.length, 1);
      // check disclosure: only family_name
      var c1 = n1.isoMdocCredentials!.first;
      expect(c1.items.length, 1);
      var name1 = c1.items['org.iso.18013.5.1'];
      expect(name1?.length, 1);
      expect(name1?.first.dataElementIdentifier, 'family_name');
      var c2 = n1.isoMdocCredentials!.last;
      expect(c2.items.length, 1);
      var name2 = c2.items['org.iso.18013.5.1'];
      expect(name2?.length, 1);
      expect(name2?.first.dataElementIdentifier, 'family_name');

      var n2 = f1.nestedResults![1];
      expect(n2.fulfilled, isTrue);
      expect(n2.sdJwtCredentials?.length, 1);
      expect(n2.credentials, null);
      expect(n2.isoMdocCredentials, null);
      expect(n2.nestedResults, null);
      expect(n2.matchingDescriptorIds.contains('sd_jwt'), isTrue);
      expect(n2.matchingDescriptorIds.length, 1);
      // check disclosure: only family_name
      var c1sd = n2.sdJwtCredentials!.first;
      expect(c1sd.disclosures?.length, 1);
      expect(c1sd.toSdJwt().additionalClaims?.length, 3);
      expect(c1sd.toSdJwt().additionalClaims?.keys.contains('family_name'),
          isTrue);
      expect(c1sd.toSdJwt().additionalClaims?.keys.contains('vct'), isTrue);
      // this empty is always disclosed because of structure of the credential
      expect(
          c1sd.toSdJwt().additionalClaims?.keys.contains('age_equal_or_over'),
          isTrue);

      var n3 = f1.nestedResults![2];
      expect(n3.fulfilled, isTrue);
      expect(n3.sdJwtCredentials, null);
      expect(n3.credentials?.length, 1);
      expect(n3.isoMdocCredentials, null);
      expect(n3.nestedResults, null);
      expect(n3.matchingDescriptorIds.contains('ldp'), isTrue);
      expect(n3.matchingDescriptorIds.length, 1);
    });
  });

  group('Or combinations', () {
    test('presentation definition', () {
      // give me a credential which contains your family name or your insurance_number
      var definition = {
        "id": "example_sd_jwt_vc_request",
        "input_descriptors": [
          {
            "id": "family_name",
            'group': ['A'],
            "constraints": {
              'limit_disclosure': 'required',
              "fields": [
                {
                  "path": [r"$..family_name"],
                }
              ]
            }
          },
          {
            "id": "insurance_number",
            'group': ['A'],
            "constraints": {
              "fields": [
                {
                  "path": [r"$..insurance_number"],
                }
              ]
            }
          }
        ],
        "submission_requirements": [
          {"from": 'A', 'rule': 'pick', 'min': 1}
        ]
      };

      var result = searchCredentialsForPresentationDefinition(
          PresentationDefinition.fromJson(definition),
          credentials: [w3cVc1, w3cVc2, w3cVc3],
          sdJwtCredentials: [sdJwt1, sdJwt2],
          isoMdocCredentials: [msoVc1, msoVc2]);

      expect(result.length, 1);

      var f1 = result.first;
      expect(f1.fulfilled, isTrue);
      expect(f1.sdJwtCredentials?.length, 1);
      expect(f1.credentials?.length, 2);
      expect(f1.isoMdocCredentials, null);
      expect(f1.nestedResults, null);
      expect(f1.matchingDescriptorIds.contains('family_name'), isTrue);
      expect(f1.matchingDescriptorIds.contains('insurance_number'), isTrue);
      expect(f1.matchingDescriptorIds.length, 2);

      // check disclosure: only family_name
      var c1sd = f1.sdJwtCredentials!.first;
      expect(c1sd.disclosures?.length, 1);
      expect(c1sd.toSdJwt().additionalClaims?.length, 3);
      expect(c1sd.toSdJwt().additionalClaims?.keys.contains('family_name'),
          isTrue);
      expect(c1sd.toSdJwt().additionalClaims?.keys.contains('vct'), isTrue);
      // this empty is always disclosed because of structure of the credential
      expect(
          c1sd.toSdJwt().additionalClaims?.keys.contains('age_equal_or_over'),
          isTrue);
    });

    test('dcql using only credential sets', () {
      var query = {
        "credentials": [
          {
            "id": "sd_jwt_family",
            "format": "dc+sd-jwt",
            'claims': [
              {
                "path": ["family_name"]
              }
            ]
          },
          {
            "id": "mso_mdoc_family",
            "format": "mso_mdoc",
            'claims': [
              {
                "path": ["org.iso.18013.5.1", "family_name"]
              }
            ]
          },
          {
            "id": "ldp_family",
            "format": "ldp_vc",
            'claims': [
              {
                "path": ["credentialSubject", "family_name"]
              }
            ]
          },
          {
            "id": "mso_mdoc_insurance",
            "format": "mso_mdoc",
            'claims': [
              {
                "path": ["de.insurance.test", "insurance_number"]
              }
            ]
          },
          {
            "id": "sd_jwt_insurance",
            "format": "dc+sd-jwt",
            'claims': [
              {
                "path": ["insurance_number"]
              }
            ]
          },
          {
            "id": "ldp_insurance",
            "format": "ldp_vc",
            'claims': [
              {
                "path": ["credentialSubject", "insurance_number"]
              }
            ]
          },
        ],
        'credential_sets': [
          {
            "purpose": "familyName or insurance",
            "options": [
              ["mso_mdoc_family"],
              ["sd_jwt_family"],
              ["ldp_family"],
              ["mso_mdoc_insurance"],
              ["sd_jwt_insurance"],
              ["ldp_insurance"]
            ]
          },
        ]
      };
      var result = searchCredentialsForDcqlQuery(DcqlQuery.fromJson(query),
          w3cCredentials: [w3cVc1, w3cVc2, w3cVc3],
          sdJwtCredentials: [sdJwt1, sdJwt2],
          mdocCredentials: [msoVc1, msoVc2]);

      expect(result.length, 1);

      var r1 = result.first;
      expect(r1.fulfilled, isTrue);
      expect(r1.sdJwtCredentials, null);
      expect(r1.credentials, null);
      expect(r1.isoMdocCredentials, null);
      expect(r1.nestedResults?.length, 6);
      expect(r1.matchingDescriptorIds.length, 0);

      var f1 = r1.nestedResults!.first;
      expect(f1.matchingDescriptorIds.contains('mso_mdoc_family'), isTrue);
      expect(f1.fulfilled, isTrue);
      expect(f1.sdJwtCredentials, null);
      expect(f1.credentials, null);
      expect(f1.isoMdocCredentials?.length, 2);
      expect(f1.nestedResults, null);
      expect(f1.matchingDescriptorIds.length, 1);

      var f2 = r1.nestedResults![1];
      expect(f2.fulfilled, isTrue);
      expect(f2.sdJwtCredentials?.length, 1);
      expect(f2.credentials, null);
      expect(f2.isoMdocCredentials, null);
      expect(f2.nestedResults, null);
      expect(f2.matchingDescriptorIds.contains('sd_jwt_family'), isTrue);
      expect(f2.matchingDescriptorIds.length, 1);

      var f3 = r1.nestedResults![2];
      expect(f3.fulfilled, isTrue);
      expect(f3.sdJwtCredentials, null);
      expect(f3.credentials?.length, 1);
      expect(f3.isoMdocCredentials, null);
      expect(f3.nestedResults, null);
      expect(f3.matchingDescriptorIds.contains('ldp_family'), isTrue);
      expect(f3.matchingDescriptorIds.length, 1);

      var f4 = r1.nestedResults![3];
      expect(f4.matchingDescriptorIds.contains('mso_mdoc_insurance'), isTrue);
      expect(f4.fulfilled, isTrue);
      expect(f4.sdJwtCredentials, null);
      expect(f4.credentials, null);
      expect(f4.isoMdocCredentials?.length, 1);
      expect(f4.nestedResults, null);
      expect(f4.matchingDescriptorIds.length, 1);

      var f5 = r1.nestedResults![4];
      expect(f5.fulfilled, isFalse);
      expect(f5.sdJwtCredentials, null);
      expect(f5.credentials, null);
      expect(f5.isoMdocCredentials, null);
      expect(f5.nestedResults, null);
      expect(f5.matchingDescriptorIds.contains('sd_jwt_insurance'), isTrue);
      expect(f5.matchingDescriptorIds.length, 1);

      var f6 = r1.nestedResults!.last;
      expect(f6.fulfilled, isTrue);
      expect(f3.sdJwtCredentials, null);
      expect(f6.credentials?.length, 1);
      expect(f6.isoMdocCredentials, null);
      expect(f6.nestedResults, null);
      expect(f6.matchingDescriptorIds.contains('ldp_insurance'), isTrue);
      expect(f6.matchingDescriptorIds.length, 1);
    });

    test('dcql using only claim sets and credential sets', () {
      var query = {
        "credentials": [
          {
            "id": "sd_jwt",
            "format": "dc+sd-jwt",
            'claims': [
              {
                "id": 'family',
                "path": ["family_name"]
              },
              {
                "id": 'insurance',
                "path": ["insurance_number"]
              }
            ],
            'claim_sets': [
              ['insurance'],
              ['family']
            ]
          },
          {
            "id": "mso_mdoc",
            "format": "mso_mdoc",
            'claims': [
              {
                'id': 'family',
                "path": ["org.iso.18013.5.1", "family_name"]
              },
              {
                "id": 'insurance',
                "path": ["de.insurance.test", "insurance_number"]
              }
            ],
            'claim_sets': [
              ['insurance'],
              ['family']
            ]
          },
          {
            "id": "ldp",
            "format": "ldp_vc",
            'claims': [
              {
                'id': 'family',
                "path": ["credentialSubject", "family_name"]
              },
              {
                "id": 'insurance',
                "path": ["credentialSubject", "insurance_number"]
              }
            ],
            'claim_sets': [
              ['insurance'],
              ['family']
            ]
          }
        ],
        'credential_sets': [
          {
            "purpose": "familyName or insurance",
            "options": [
              ["mso_mdoc"],
              ["sd_jwt"],
              ["ldp"],
            ]
          },
        ]
      };
      var result = searchCredentialsForDcqlQuery(DcqlQuery.fromJson(query),
          w3cCredentials: [w3cVc1, w3cVc2, w3cVc3],
          sdJwtCredentials: [sdJwt1, sdJwt2],
          mdocCredentials: [msoVc1, msoVc2]);

      expect(result.length, 1);

      var r1 = result.first;
      expect(r1.fulfilled, isTrue);
      expect(r1.sdJwtCredentials, null);
      expect(r1.credentials, null);
      expect(r1.isoMdocCredentials, null);
      expect(r1.nestedResults?.length, 3);
      expect(r1.matchingDescriptorIds.length, 0);

      var f1 = r1.nestedResults!.first;
      expect(f1.matchingDescriptorIds.contains('mso_mdoc'), isTrue);
      expect(f1.fulfilled, isTrue);
      expect(f1.sdJwtCredentials, null);
      expect(f1.credentials, null);
      // because one credential contain both properties we expect it two times with different properties disclosed
      expect(f1.isoMdocCredentials?.length, 3);
      expect(f1.nestedResults, null);
      expect(f1.matchingDescriptorIds.length, 1);

      var f2 = r1.nestedResults![1];
      expect(f2.fulfilled, isTrue);
      expect(f2.sdJwtCredentials?.length, 1);
      expect(f2.credentials, null);
      expect(f2.isoMdocCredentials, null);
      expect(f2.nestedResults, null);
      expect(f2.matchingDescriptorIds.contains('sd_jwt'), isTrue);
      expect(f2.matchingDescriptorIds.length, 1);

      var f3 = r1.nestedResults![2];
      expect(f3.fulfilled, isTrue);
      expect(f3.sdJwtCredentials, null);
      expect(f3.credentials?.length, 2);
      expect(f3.isoMdocCredentials, null);
      expect(f3.nestedResults, null);
      expect(f3.matchingDescriptorIds.contains('ldp'), isTrue);
      expect(f3.matchingDescriptorIds.length, 1);
    });
  });

  group('path nested of presentationDefinition', () {
    test('path nested', () {
      // show me, that you are a real person based on your family name
      // or your insurance number.
      var definition = {
        "id": "example_sd_jwt_vc_request",
        "input_descriptors": [
          {
            "id": "family_name",
            'group': ['A'],
            "constraints": {
              "fields": [
                {
                  "path": [r"$..family_name"],
                }
              ]
            }
          },
          {
            "id": "insurance_number",
            'group': ['B'],
            "constraints": {
              "fields": [
                {
                  "path": [r"$..insurance_number"],
                }
              ]
            }
          },
        ],
        "submission_requirements": [
          {
            'rule': 'pick',
            'min': 1,
            'from_nested': [
              {'rule': 'all', 'from': 'A'},
              {'rule': 'all', 'from': 'B'}
            ]
          }
        ]
      };

      var result = searchCredentialsForPresentationDefinition(
          PresentationDefinition.fromJson(definition),
          credentials: [w3cVc1, w3cVc2, w3cVc3],
          sdJwtCredentials: [sdJwt1, sdJwt2],
          isoMdocCredentials: [msoVc1, msoVc2]);

      expect(result.length, 1);
      var r1 = result.first;
      expect(r1.fulfilled, isTrue);
      expect(r1.sdJwtCredentials, null);
      expect(r1.credentials, null);
      expect(r1.isoMdocCredentials, null);
      expect(r1.nestedResults?.length, 2);
      expect(r1.matchingDescriptorIds.length, 0);

      var f1 = r1.nestedResults!.first;
      expect(f1.matchingDescriptorIds.contains('family_name'), isTrue);
      expect(f1.fulfilled, isTrue);
      expect(f1.sdJwtCredentials?.length, 1);
      expect(f1.credentials?.length, 1);
      expect(f1.isoMdocCredentials, null);
      expect(f1.nestedResults, null);
      expect(f1.matchingDescriptorIds.length, 1);

      var f2 = r1.nestedResults![1];
      expect(f2.fulfilled, isTrue);
      expect(f2.sdJwtCredentials, null);
      expect(f2.credentials?.length, 1);
      expect(f2.isoMdocCredentials, null);
      expect(f2.nestedResults, null);
      expect(f2.matchingDescriptorIds.contains('insurance_number'), isTrue);
      expect(f2.matchingDescriptorIds.length, 1);
    });

    test('missing claim id', () {
      var query = {
        "credentials": [
          {
            "id": "sd_jwt",
            "format": "dc+sd-jwt",
            'claims': [
              {
                "path": ["family_name"]
              },
              {
                "id": 'insurance',
                "path": ["insurance_number"]
              }
            ],
            'claim_sets': [
              ['insurance'],
              ['family']
            ]
          }
        ]
      };
      expect(
          () => searchCredentialsForDcqlQuery(DcqlQuery.fromJson(query),
              w3cCredentials: [w3cVc1, w3cVc2, w3cVc3],
              sdJwtCredentials: [sdJwt1, sdJwt2],
              mdocCredentials: [msoVc1, msoVc2]),
          throwsException);
    });
  });
}
