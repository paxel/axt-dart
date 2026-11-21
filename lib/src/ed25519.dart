/// Ed25519 with the strict verification of AXT (`spec/keys.md`, section 2.3).
///
/// Signing and the equation of step 5 come from the package `cryptography`;
/// steps 1 to 3, which libraries choose differently, are checked here with an
/// edwards25519 point implementation of its own.
library;

import 'dart:typed_data';

import 'package:cryptography/cryptography.dart' as c;

final BigInt _p = (BigInt.one << 255) - BigInt.from(19);

/// The order L of the base point.
final BigInt groupOrder =
    (BigInt.one << 252) +
    BigInt.parse('27742317777372353535851937790883648493');

final BigInt _d =
    (-BigInt.from(121665) * BigInt.from(121666).modInverse(_p)) % _p;

final BigInt _sqrtMinusOne = BigInt.two.modPow((_p - BigInt.one) >> 2, _p);

/// A point in extended coordinates (X : Y : Z : T), x = X/Z, y = Y/Z.
typedef _Point = (BigInt, BigInt, BigInt, BigInt);

final _Point _neutral = (BigInt.zero, BigInt.one, BigInt.one, BigInt.zero);

BigInt _mod(BigInt a) => a % _p;

_Point _add(_Point a, _Point b) {
  final (x1, y1, z1, t1) = a;
  final (x2, y2, z2, t2) = b;
  final aa = _mod((y1 - x1) * (y2 - x2));
  final bb = _mod((y1 + x1) * (y2 + x2));
  final cc = _mod(BigInt.two * t1 * t2 * _d);
  final dd = _mod(BigInt.two * z1 * z2);
  final e = bb - aa;
  final f = dd - cc;
  final g = dd + cc;
  final h = bb + aa;
  return (_mod(e * f), _mod(g * h), _mod(f * g), _mod(e * h));
}

_Point _multiply(_Point point, BigInt scalar) {
  var result = _neutral;
  var addend = point;
  var k = scalar;
  while (k > BigInt.zero) {
    if (k.isOdd) result = _add(result, addend);
    addend = _add(addend, addend);
    k >>= 1;
  }
  return result;
}

bool _isNeutral(_Point point) {
  final (x, y, z, _) = point;
  return _mod(x) == BigInt.zero && _mod(y - z) == BigInt.zero;
}

BigInt _littleEndian(List<int> bytes) {
  var value = BigInt.zero;
  for (var i = bytes.length - 1; i >= 0; i--) {
    value = (value << 8) | BigInt.from(bytes[i]);
  }
  return value;
}

/// Decodes a point as RFC 8032, section 5.1.3, says; null if that fails.
_Point? _decode(List<int> encoded) {
  if (encoded.length != 32) return null;
  final bytes = Uint8List.fromList(encoded);
  final sign = bytes[31] >> 7;
  bytes[31] &= 0x7f;
  final y = _littleEndian(bytes);
  if (y >= _p) return null;
  final yy = _mod(y * y);
  final u = _mod(yy - BigInt.one);
  final v = _mod(_d * yy + BigInt.one);
  final v3 = _mod(v * v * v);
  var x = _mod(
    u * v3 * (u * v3 * v3 * v).modPow((_p - BigInt.from(5)) >> 3, _p),
  );
  final vxx = _mod(v * x * x);
  if (vxx == u) {
    // x is a root.
  } else if (vxx == _mod(-u)) {
    x = _mod(x * _sqrtMinusOne);
  } else {
    return null;
  }
  if (x == BigInt.zero && sign == 1) return null;
  if ((x.isOdd ? 1 : 0) != sign) x = _p - x;
  return (x, y, BigInt.one, _mod(x * y));
}

/// Whether [encoded] passes steps 2 and 3 of the strict verification: it
/// decodes as a point, and that point has the order L.
bool isPointOfOrderL(List<int> encoded) {
  final point = _decode(encoded);
  if (point == null || _isNeutral(point)) return false;
  return _isNeutral(_multiply(point, groupOrder));
}

final c.Ed25519 _ed25519 = c.Ed25519();

/// The public key of the Ed25519 private key [seed] (RFC 8032, 5.1.5).
Future<Uint8List> publicKeyOf(List<int> seed) async {
  final keyPair = await _ed25519.newKeyPairFromSeed(seed);
  final publicKey = await keyPair.extractPublicKey();
  return Uint8List.fromList(publicKey.bytes);
}

/// The pure Ed25519 signature of [data] with the private key [seed].
Future<Uint8List> sign(List<int> seed, List<int> data) async {
  final keyPair = await _ed25519.newKeyPairFromSeed(seed);
  final signature = await _ed25519.sign(data, keyPair: keyPair);
  return Uint8List.fromList(signature.bytes);
}

/// Whether [signature] over [data] verifies with [publicKey] by the strict
/// rule of `spec/keys.md`, section 2.3.
Future<bool> verifyStrict(
  List<int> publicKey,
  List<int> data,
  List<int> signature,
) async {
  if (publicKey.length != 32 || signature.length != 64) return false;
  if (_littleEndian(signature.sublist(32)) >= groupOrder) return false;
  if (!isPointOfOrderL(publicKey) ||
      !isPointOfOrderL(signature.sublist(0, 32))) {
    return false;
  }
  return _ed25519.verify(
    data,
    signature: c.Signature(
      signature,
      publicKey: c.SimplePublicKey(publicKey, type: c.KeyPairType.ed25519),
    ),
  );
}
