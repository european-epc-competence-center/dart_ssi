import 'dart:math';
import 'dart:typed_data';

import 'package:base_codecs/base_codecs.dart';
import 'package:pointycastle/export.dart' as pc;
import 'package:x25519/src/curve25519.dart' as x25519;

//ported from https://github.com/oasisprotocol/ed25519/blob/master/extra/x25519/x25519.go
String ed25519PublicToX25519Public(List<int> ed25519Public) {
  var Y = x25519.FieldElement();
  x25519.feFromBytes(Y, ed25519Public);
  var oneMinusY = x25519.FieldElement();
  x25519.FeOne(oneMinusY);
  x25519.FeSub(oneMinusY, oneMinusY, Y);
  x25519.feInvert(oneMinusY, oneMinusY);

  var outX = x25519.FieldElement();
  x25519.FeOne(outX);
  x25519.FeAdd(outX, outX, Y);

  x25519.feMul(outX, outX, oneMinusY);

  var dst = List.filled(32, 0);
  x25519.FeToBytes(dst, outX);

  const xMultiCodec = [236, 1];

  return base58Bitcoin.encode(Uint8List.fromList(xMultiCodec + dst));
}

bool listEquals(List l1, List l2) {
  if (l2.length != l1.length) {
    return false;
  }

  for (int i = 0; i < l2.length; i++) {
    if (l1[i] != l2[i]) {
      return false;
    }
  }

  return true;
}

String bytesToHex(Uint8List bytes) {
  var hex = bytes.map((i) => i.toRadixString(16).padLeft(2, '0')).join();
  return hex;
}

Uint8List hexToBytes(String hexInput) {
  if (hexInput.startsWith('0x')) {
    hexInput = hexInput.substring(2);
  }
  var result = Uint8List(hexInput.length ~/ 2);
  var input = hexInput.split('');
  for (int i = 0; i < input.length; i += 2) {
    result[i ~/ 2] = (int.parse('${input[i]}${input[i + 1]}', radix: 16));
  }
  return result;
}

BigInt hexToInt(String hexInput) {
  var bytes = hexToBytes(hexInput);
  return bytesToUnsignedInt(bytes);
}

// Source: pointyCastle src/utils
var _byteMask = BigInt.from(0xff);

Uint8List unsignedIntToBytes(BigInt number) {
  if (number.isNegative) {
    throw Exception('Negative number');
  }
  if (number == BigInt.zero) {
    return Uint8List.fromList([0]);
  }
  var size = number.bitLength + (number.isNegative ? 8 : 7) >> 3;
  var result = Uint8List(size);
  for (var i = 0; i < size; i++) {
    result[size - i - 1] = (number & _byteMask).toInt();
    number = number >> 8;
  }
  return result;
}

BigInt bytesToUnsignedInt(List<int> magnitude) {
  BigInt result;

  if (magnitude.length == 1) {
    result = BigInt.from(magnitude[0]);
  } else {
    result = BigInt.from(0);
    for (var i = 0; i < magnitude.length; i++) {
      var item = magnitude[magnitude.length - i - 1];
      result |= BigInt.from(item) << (8 * i);
    }
  }

  if (result != BigInt.zero) {
    result = result.toUnsigned(result.bitLength);
  }
  return result;
}

pc.SecureRandom getSecureRandom() {
  final secureRandom = pc.FortunaRandom();

  var random = Random.secure();
  var seed = List.generate(32, (index) => random.nextInt(256));

  secureRandom.seed(pc.KeyParameter(Uint8List.fromList(seed)));

  return secureRandom;
}

// source: https://github.com/appsup-dart/crypto_keys/blob/master/lib/src/pointycastle_ext.dart
class AESKeyWrap implements pc.BlockCipher {
  final pc.BlockCipher _underlyingCipher = pc.AESEngine();

  @override
  String get algorithmName => 'AESWrap';

  @override
  int get blockSize => 8;

  static final Uint8List _iv = Uint8List.fromList([
    0xa6,
    0xa6,
    0xa6,
    0xa6,
    0xa6,
    0xa6,
    0xa6,
    0xa6,
  ]);
  late bool _encrypting;

  @override
  void init(bool forEncryption, covariant pc.KeyParameter? params) {
    _encrypting = forEncryption;
    _underlyingCipher.init(forEncryption, params);
  }

  Uint8List wrap(Uint8List data) {
    var n = data.length ~/ 8;

    var r = Uint8List.fromList(data);

    var a = Uint8List(16);

    var b = Uint8List(16);
    var b64 = ByteData.view(b.buffer);

    a.setAll(0, _iv);

    for (var j = 0; j <= 5; j++) {
      for (var i = 0; i < n; i++) {
        var t = n * j + i + 1;

        a.setAll(8, r.skip(i * 8).take(8));

        _underlyingCipher.processBlock(a, 0, b, 0);

        b64.setUint32(0, b64.getUint32(0) ^ (t << 32));
        b64.setUint32(4, b64.getUint32(4) ^ (t & 0xffffffff));

        a.setAll(0, b.take(8));
        r.setAll(i * 8, b.skip(8));
      }
    }

    var c = Uint8List(n * 8 + 8);
    c.setAll(0, a.take(8));
    c.setAll(8, r);

    return c;
  }

  Uint8List unwrap(Uint8List data) {
    var n = data.length ~/ 8 - 1;

    var a = Uint8List(16);
    a.setAll(0, data.take(8));
    var a64 = ByteData.view(a.buffer);

    var b = Uint8List(16);

    var r = Uint8List(n * 8);
    r.setAll(0, data.skip(8));

    for (var j = 5; j >= 0; j--) {
      for (var i = n - 1; i >= 0; i--) {
        var t = n * j + i + 1;

        a64.setInt32(0, a64.getInt32(0) ^ (t << 32));
        a64.setInt32(4, a64.getInt32(4) ^ (t & 0xffffffff));
        a.setAll(8, r.skip(i * 8).take(8));

        _underlyingCipher.processBlock(a, 0, b, 0);
        a.setAll(0, b.take(8));
        r.setAll(i * 8, b.skip(8));
      }
    }

    for (var i = 0; i < 8; i++) {
      if (_iv[i] != a[i]) {
        throw 'Invalid '; // TODO
      }
    }
    return r;
  }

  @override
  Uint8List process(Uint8List data) {
    if (data.length % 8 != 0) {
      throw ArgumentError('Input data should be a multiple of 64 bits.');
    }

    if (_encrypting) {
      return wrap(data);
    } else {
      return unwrap(data);
    }
  }

  @override
  int processBlock(Uint8List inp, int inpOff, Uint8List out, int outOff) {
    throw UnsupportedError('Should not be called.');
  }

  @override
  void reset() {
    throw UnsupportedError('Should not be called.');
  }
}
