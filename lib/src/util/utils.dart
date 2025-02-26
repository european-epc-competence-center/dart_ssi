import 'dart:convert';
import 'dart:typed_data';

import 'package:asn1lib/asn1lib.dart';
import 'package:base_codecs/base_codecs.dart';
import 'package:crypto/crypto.dart';
import 'package:dart_multihash/dart_multihash.dart';
import 'package:dart_ssi/did.dart';
import 'package:dart_ssi/src/util/crypto_provider.dart';
import 'package:ed25519_edwards/ed25519_edwards.dart' as ed;
import 'package:elliptic/elliptic.dart' as elliptic;
import 'package:elliptic/elliptic.dart';
import 'package:web3dart/crypto.dart';

import '../wallet/wallet_store.dart';

Uint8List _multibaseToUint8List(String multibase) {
  if (multibase.startsWith('z')) {
    return base58BitcoinDecode(multibase.substring(1));
  } else {
    throw UnimplementedError('Unsupported multibase indicator ${multibase[0]}');
  }
}

bool isUri(String uri) {
  try {
    Uri.parse(uri);
    return true;
  } catch (_) {
    return false;
  }
}

String multibaseToBase64Url(String multibase) {
  return base64UrlEncode(_multibaseToUint8List(multibase));
}

Map<String, dynamic> multibaseKeyToJwk(String multibaseKey) {
  var key = _multibaseToUint8List(multibaseKey);
  var indicator = key.sublist(0, 2);
  var indicatorHex = bytesToHex(indicator);
  key = key.sublist(2);
  Map<String, dynamic> jwk = {};
  if (indicatorHex == 'ed01') {
    jwk['kty'] = 'OKP';
    jwk['crv'] = 'Ed25519';
    jwk['x'] = removePaddingFromBase64(base64UrlEncode(key));
  } else if (indicatorHex == 'ec01') {
    jwk['kty'] = 'OKP';
    jwk['crv'] = 'X25519';
    jwk['x'] = removePaddingFromBase64(base64UrlEncode(key));
  } else if (indicatorHex == '8024') {
    jwk['kty'] = 'EC';
    jwk['crv'] = 'P-256';
    var c = getP256();
    var pub = c.compressedHexToPublicKey(hex.encode(key));
    jwk['x'] = removePaddingFromBase64(base64UrlEncode(
        pub.X < BigInt.zero ? intToBytes(pub.X) : unsignedIntToBytes(pub.X)));
    jwk['y'] = removePaddingFromBase64(base64UrlEncode(
        pub.Y < BigInt.zero ? intToBytes(pub.Y) : unsignedIntToBytes(pub.Y)));
  } else if (indicatorHex == 'e701') {
    jwk['kty'] = 'EC';
    jwk['crv'] = 'secp256k1';
    var c = getSecp256k1();
    var pub = c.compressedHexToPublicKey(hex.encode(key));
    jwk['x'] = removePaddingFromBase64(base64UrlEncode(
        pub.X < BigInt.zero ? intToBytes(pub.X) : unsignedIntToBytes(pub.X)));
    jwk['y'] = removePaddingFromBase64(base64UrlEncode(
        pub.Y < BigInt.zero ? intToBytes(pub.Y) : unsignedIntToBytes(pub.Y)));
  } else if (indicatorHex == '8124') {
    jwk['kty'] = 'EC';
    jwk['crv'] = 'P-384';
    var c = getP384();
    var pub = c.compressedHexToPublicKey(hex.encode(key));
    jwk['x'] = removePaddingFromBase64(base64UrlEncode(
        pub.X < BigInt.zero ? intToBytes(pub.X) : unsignedIntToBytes(pub.X)));
    jwk['y'] = removePaddingFromBase64(base64UrlEncode(
        pub.Y < BigInt.zero ? intToBytes(pub.Y) : unsignedIntToBytes(pub.Y)));
  } else if (indicatorHex == '8224') {
    jwk['kty'] = 'EC';
    jwk['crv'] = 'P-521';
    var c = getP521();
    var pub = c.compressedHexToPublicKey(hex.encode(key));
    jwk['x'] = removePaddingFromBase64(base64UrlEncode(
        pub.X < BigInt.zero ? intToBytes(pub.X) : unsignedIntToBytes(pub.X)));
    jwk['y'] = removePaddingFromBase64(base64UrlEncode(
        pub.Y < BigInt.zero ? intToBytes(pub.Y) : unsignedIntToBytes(pub.Y)));
  } else {
    throw UnimplementedError(
        'Unsupported multicodec indicator 0x$indicatorHex');
  }
  return jwk;
}

String jwkToMultiBase(Map<String, dynamic> jwk) {
  var crv = jwk['crv'];
  if (crv == 'Ed25519') {
    return 'z${base58BitcoinEncode(Uint8List.fromList([
          237,
          1
        ] + base64Decode(addPaddingToBase64(jwk['x']))))}';
  } else if (crv == 'P-256') {
    var c = elliptic.getP256();
    var compressedHex = c.publicKeyToCompressedHex(elliptic.PublicKey(
        c,
        bytesToUnsignedInt(base64Decode(addPaddingToBase64(jwk['x']))),
        bytesToUnsignedInt(base64Decode(addPaddingToBase64(jwk['y'])))));
    var compressedBytes = hexDecode(compressedHex);
    return 'z${base58BitcoinEncode(Uint8List.fromList([
          128,
          36
        ] + compressedBytes))}';
  } else if (crv == 'P-384') {
    var c = elliptic.getP384();
    var compressedHex = c.publicKeyToCompressedHex(elliptic.PublicKey(
        c,
        bytesToUnsignedInt(base64Decode(addPaddingToBase64(jwk['x']))),
        bytesToUnsignedInt(base64Decode(addPaddingToBase64(jwk['y'])))));
    var compressedBytes = hexDecode(compressedHex);
    return 'z${base58BitcoinEncode(Uint8List.fromList([
          129,
          36
        ] + compressedBytes))}';
  } else if (crv == 'P-521') {
    var c = elliptic.getP521();
    var compressedHex = c.publicKeyToCompressedHex(elliptic.PublicKey(
        c,
        bytesToUnsignedInt(base64Decode(addPaddingToBase64(jwk['x']))),
        bytesToUnsignedInt(base64Decode(addPaddingToBase64(jwk['y'])))));
    var compressedBytes = hexDecode(compressedHex);
    return 'z${base58BitcoinEncode(Uint8List.fromList([
          130,
          36
        ] + compressedBytes))}';
  } else {
    throw Exception('unsupported curve $crv');
  }
}

// if (keyType == KeyType.p521) {
// c = getP521();
// prefix = [130, 36];
// } else if (keyType == KeyType.p384) {
// c = getP384();
// prefix = [129, 36];
// } else {
// c = getP256();
// prefix = [128, 36];
// }

/// Converts json-String [credential] to dart Map.
Map<String, dynamic> credentialToMap(dynamic credential) {
  if (credential is String) {
    return jsonDecode(credential);
  } else if (credential is Map<String, dynamic>) {
    return credential;
  } else if (credential is Map<dynamic, dynamic>) {
    return credential.map((key, value) => MapEntry(key as String, value));
  } else {
    throw Exception(
        'Unknown datatype ${credential.runtimeType} for $credential. Only String or Map<String, dynamic> accepted');
  }
}

String addPaddingToBase64(String base64Input) {
  while (base64Input.length % 4 != 0) {
    base64Input += '=';
  }
  return base64Input;
}

String removePaddingFromBase64(String base64Input) {
  while (base64Input.endsWith('=')) {
    base64Input = base64Input.substring(0, base64Input.length - 1);
  }
  return base64Input;
}

// Future<List<String>> getDidFromDidConfiguration(String url) async {
//   List<String> didsInConfig = [];
//   var uri = Uri.parse(url);
//   print('https://${uri.host}/.well-known/did-configuration');
//   try {
//     var res = await http
//         .get(Uri.parse('https://${uri.host}/.well-known/did-configuration'))
//         .timeout(Duration(seconds: 30));
//     if (res.statusCode == 200) {
//       var entries = jsonDecode(res.body);
//       List<dynamic> dids = entries['entries'];
//       await Future.forEach(dids, (dynamic element) async {
//         var jwt = element['jwt'];
//         var did = element['did'];
//         print(did);
//         var verified = await verifyStringSignature(jwt, expectedDid: did);
//         print(verified);
//         if (verified) didsInConfig.add(did);
//       });
//     }
//   } catch (e) {
//     throw Exception('Error occurred during fetch of did-configuration: $e');
//   }
//   return didsInConfig;
// }

ASN1Set _buildSubjectInfoPart(String part, String data) {
  var set = ASN1Set();
  var seq = ASN1Sequence();
  List<int> oid = [2, 5, 4];
  switch (part) {
    case 'commonName':
      oid.add(3);
      break;
    case 'stateOrProvinceName':
      oid.add(8);
      break;
    case 'localityName':
      oid.add(7);
      break;
    case 'organizationName':
      oid.add(10);
      break;
    case 'organizationalUnitName':
      oid.add(11);
      break;
  }
  seq.add(ASN1ObjectIdentifier(oid, identifier: part));
  seq.add(ASN1UTF8String(data));
  set.add(seq);
  return set;
}

/// Generate a x509 Certificate Signing Request for a key belonging to [did].
Future<String> buildCsrForDid(WalletStore wallet, String did,
    {String? countryCode,
    String? state,
    String? city,
    String? organization,
    String? organizationalUnit,
    String? emailAddress}) async {
  // if (!did.startsWith('did:key:z6Mk')) {
  //   throw Exception('Only did:key with Ed25519 keys are supported now');
  // }

  var ddo = await resolveDidDocument(did);
  var parsedDdo = ddo.resolveKeyIds().convertAllKeysToJwk();
  var jwk = parsedDdo.verificationMethod?.firstOrNull?.publicKeyJwk;

  if (jwk == null) {
    throw Exception('No public key found');
  }

  var csr = ASN1Sequence();
  var cri = ASN1Sequence();

  //Version
  cri.add(ASN1Integer(BigInt.zero));

  //subject
  var subject = ASN1Sequence();

  //countryCode in subject
  if (countryCode != null) {
    if (countryCode.length != 2) {
      throw Exception('Only two letter countryCodes are accepted');
    }
    var country = ASN1Sequence();
    country.add(ASN1ObjectIdentifier([2, 5, 4, 6], identifier: 'countryName'));
    country.add(ASN1PrintableString(countryCode));
    var countrySet = ASN1Set();
    countrySet.add(country);
    subject.add(countrySet);
  }

  if (state != null) {
    subject.add(_buildSubjectInfoPart('stateOrProvinceName', state));
  }
  if (city != null) {
    subject.add(_buildSubjectInfoPart('localityName', city));
  }
  if (organization != null) {
    subject.add(_buildSubjectInfoPart('organizationName', organization));
  }
  if (organizationalUnit != null) {
    subject.add(
        _buildSubjectInfoPart('organizationalUnitName', organizationalUnit));
  }

  subject.add(_buildSubjectInfoPart('commonName', did));

  //email
  if (emailAddress != null) {
    var country = ASN1Sequence();
    country.add(ASN1ObjectIdentifier([1, 2, 840, 113549, 1, 9, 1],
        identifier: 'countryName'));
    country.add(ASN1IA5String(emailAddress));
    var countrySet = ASN1Set();
    countrySet.add(country);
    subject.add(countrySet);
  }

  cri.add(subject);

  //subject public Key
  if (jwk['kty'] == 'OKP') {
    if (jwk['crv'] != 'Ed25519') {
      throw Exception('Unsupported Curve: ${jwk['crv']}');
    }

    var pub = ed.PublicKey(base64Decode(addPaddingToBase64(jwk['x'])));

    var publicKey = ASN1Sequence();
    var pubKeyId = ASN1Sequence();
    pubKeyId.add(ASN1ObjectIdentifier([1, 3, 101, 112]));
    publicKey.add(pubKeyId);
    publicKey.add(ASN1BitString(pub.bytes));
    var sigId = ASN1Sequence()..add(ASN1ObjectIdentifier([1, 3, 101, 112]));

    cri.add(publicKey);

    //sign
    var sig = await wallet.sign(did, Uint8List.fromList(cri.encodedBytes));
    csr.add(cri);
    csr.add(sigId);
    csr.add(ASN1BitString(sig));
  } else if (jwk['kty'] == 'EC') {
    var publicKey = ASN1Sequence();
    var pubKeyId = ASN1Sequence();

    pubKeyId.add(ASN1ObjectIdentifier([1, 2, 840, 10045, 2, 1])); // ecPublicKey
    var sigId = ASN1Sequence();
    if (jwk['crv'] == 'P-256') {
      pubKeyId.add(ASN1ObjectIdentifier([1, 2, 840, 10045, 3, 1, 7]));
      sigId.add(ASN1ObjectIdentifier([1, 2, 840, 10045, 4, 3, 2]));
    } else if (jwk['crv'] == 'P-384') {
      pubKeyId.add(ASN1ObjectIdentifier([1, 3, 132, 0, 34]));
      sigId.add(ASN1ObjectIdentifier([1, 2, 840, 10045, 4, 3, 3]));
    } else if (jwk['crv'] == 'P-521') {
      pubKeyId.add(ASN1ObjectIdentifier([1, 3, 132, 0, 35]));
      sigId.add(ASN1ObjectIdentifier([1, 2, 840, 10045, 4, 3, 4]));
    } else if (jwk['crv'] == 'P-256k' || jwk['crv'] == 'secp256k1') {
      pubKeyId.add(ASN1ObjectIdentifier([1, 3, 132, 0, 10]));
      sigId.add(ASN1ObjectIdentifier([1, 2, 840, 10045, 4, 3, 2]));
    } else {
      throw Exception('Unsupported Curve: ${jwk['crv']}');
    }

    var x = base64Decode(addPaddingToBase64(jwk['x']));
    var y = base64Decode(addPaddingToBase64(jwk['y']));
    print(x.length);
    print(y.length);
    if (jwk['crv'] == 'P-521') {
      if (x.length == 65) {
        x = Uint8List.fromList([0, ...x]);
      }
      if (y.length == 65) {
        y = Uint8List.fromList([0, ...y]);
      }
    }
    print(x.length);
    print(y.length);

    var pubKey = ASN1BitString([4, ...x, ...y]);

    publicKey.add(pubKeyId);
    publicKey.add(pubKey);

    cri.add(publicKey);

    //sign
    var sig = await wallet.sign(did, Uint8List.fromList(cri.encodedBytes));
    csr.add(cri);
    csr.add(sigId);
    var r = sig.sublist(0, sig.length ~/ 2);
    var s = sig.sublist(sig.length ~/ 2);
    var encodedSignature = ASN1Sequence();
    encodedSignature.add(ASN1Integer(bytesToUnsignedInt(r)));
    encodedSignature.add(ASN1Integer(bytesToUnsignedInt(s)));
    csr.add(ASN1BitString(encodedSignature.encodedBytes));
  } else {
    throw Exception('Unsupported KeyType: ${jwk['kty']}');
  }

  //buildPem
  var buffer = StringBuffer();
  var bytes = csr.encodedBytes;
  buffer.writeln('-----BEGIN CERTIFICATE REQUEST-----');
  for (var i = 0; i < bytes.length; i += 48) {
    buffer.writeln(base64.encode(bytes.skip(i).take(48).toList()));
  }
  buffer.writeln('-----END CERTIFICATE REQUEST-----');
  return buffer.toString();
}

/// Checks multihash format
/// only supporting sha2-256 atm.
bool checkMultiHash(Uint8List hash, Uint8List data) {
  var multihash = Multihash.decode(hash);
  if (multihash.code != 0x12) {
    throw Exception("Hash function must be "
        "sha2-256 for now (Code: 34893)");
  }

  var hashedData = sha256.convert(data).bytes;
  for (var i = 0; i < hashedData.length; i++) {
    var a = multihash.digest[i];
    var b = hashedData[i];
    if (a != b) {
      return false;
    }
  }
  return hashedData.length == multihash.digest.length;
}

String getDateTimeNowString() {
  var date = DateTime.now();
  var asString = date.toUtc().toIso8601String();
  var xmlDate = asString.split('.').first;
  xmlDate += 'Z';
  return xmlDate;
}

Future<List<int>> _calculateZ(KeyAgreementGenerator keyAgreement,
    Map<String, dynamic> otherPublicKey) async {
  return keyAgreement.generateAgreement(otherPublicKey);
}

Future<List<int>> ecdhES(KeyAgreementGenerator keyAgreement,
    Map<String, dynamic> publicKey, String alg, String enc,
    {String? apu, String? apv}) async {
  List<int> z = await _calculateZ(keyAgreement, publicKey);

  print(z);

  var keyDataLen = 128;
  Uint8List encAscii;
  if (alg == 'ECDH-ES') {
    encAscii = ascii.encode(enc);
    if (enc.contains('128')) {
      keyDataLen = 128;
    }
    if (enc.contains('192')) {
      keyDataLen = 192;
    }
    if (enc.contains('256')) {
      keyDataLen = 256;
    }
  } else {
    // with KeyWrap
    encAscii = ascii.encode(alg);
    if (alg.contains('128')) {
      keyDataLen = 128;
    }
    if (alg.contains('192')) {
      keyDataLen = 192;
    }
    if (alg.contains('256')) {
      keyDataLen = 256;
    }
  }
  print('enc: $enc, alg: $alg, len: $keyDataLen');
  var suppPubInfo = _int32BigEndianBytes(keyDataLen);

  var encLength = _int32BigEndianBytes(encAscii.length);

  List<int> partyU, partyULength;
  if (apu != null) {
    partyU = base64Decode(addPaddingToBase64(apu));
    partyULength = _int32BigEndianBytes(partyU.length);
  } else {
    partyU = [];
    partyULength = _int32BigEndianBytes(0);
  }

  List<int> partyV, partyVLength;
  if (apv != null) {
    partyV = base64Decode(addPaddingToBase64(apv));
    partyVLength = _int32BigEndianBytes(partyV.length);
  } else {
    partyV = [];
    partyVLength = _int32BigEndianBytes(0);
  }

  var otherInfo = encLength +
      encAscii +
      partyULength +
      partyU +
      partyVLength +
      partyV +
      suppPubInfo;

  var kdfIn = [0, 0, 0, 1] + z + otherInfo;
  var digest = sha256.convert(kdfIn);
  return digest.bytes.sublist(0, keyDataLen ~/ 8);
}

Future<List<int>> ecdh1PU(
    KeyAgreementGenerator keyAgreement1,
    KeyAgreementGenerator keyAgreement2,
    Map<String, dynamic> public1,
    Map<String, dynamic> public2,
    List<int> tag,
    String keyWrapAlgorithm,
    String apu,
    String apv) async {
  var ze = await _calculateZ(keyAgreement1, public1);
  var zs = await _calculateZ(keyAgreement2, public2);

  var z = ze + zs;

  //Didcomm only uses A256KW
  var keyDataLen = 256;
  var cctagLen = _int32BigEndianBytes(tag.length);
  var suppPubInfo = _int32BigEndianBytes(keyDataLen) + cctagLen + tag;

  var encAscii = ascii.encode(keyWrapAlgorithm);
  var encLength = _int32BigEndianBytes(encAscii.length);

  var partyU = base64Decode(addPaddingToBase64(apu));
  var partyULength = _int32BigEndianBytes(partyU.length);

  var partyV = base64Decode(addPaddingToBase64(apv));
  var partyVLength = _int32BigEndianBytes(partyV.length);

  var otherInfo = encLength +
      encAscii +
      partyULength +
      partyU +
      partyVLength +
      partyV +
      suppPubInfo;

  var kdfIn = [0, 0, 0, 1] + z + otherInfo;
  var digest = sha256.convert(kdfIn);

  return digest.bytes;
}

Uint8List _int32BigEndianBytes(int value) =>
    Uint8List(4)..buffer.asByteData().setInt32(0, value, Endian.big);
