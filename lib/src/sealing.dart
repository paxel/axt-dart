/// Encryption for the relay: padding, and sealing and opening with HPKE (AXT
/// `spec/keys.md`, sections 4.1 to 4.5; RFC 9180).
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as crypto;
import 'package:cryptography/cryptography.dart' as c;

import 'errors.dart';

/// The `info` of every sealed message.
final Uint8List _info = ascii.encode('AXT-v1 relay message');

/// The suite of the KEM, DHKEM(X25519, HKDF-SHA256).
final Uint8List _kemSuite = Uint8List.fromList([
  ...ascii.encode('KEM'),
  0,
  0x20,
]);

/// The suite of HPKE: the KEM 0x0020, HKDF-SHA256 0x0001, ChaCha20-Poly1305
/// 0x0003.
final Uint8List _hpkeSuite = Uint8List.fromList([
  ...ascii.encode('HPKE'),
  0, 0x20, 0, 0x01, 0, 0x03, //
]);

final List<int> _version = ascii.encode('HPKE-v1');

final c.X25519 _x25519 = c.X25519();

final c.Chacha20 _aead = c.Chacha20.poly1305Aead();

/// The padded length P(n) of a message of [length] bytes (section 4.4).
int paddedLength(int length) {
  final x = length + 1;
  if (x <= 1024) return 1024;
  final e = x.bitLength - 1;
  final s = e.bitLength;
  final lastBits = e - s;
  final mask = (1 << lastBits) - 1;
  return (x + mask) & ~mask;
}

Uint8List _hmac(List<int> key, List<int> data) =>
    Uint8List.fromList(crypto.Hmac(crypto.sha256, key).convert(data).bytes);

Uint8List _labeledExtract(
  List<int> suite,
  List<int> salt,
  String label,
  List<int> ikm,
) => _hmac(salt.isEmpty ? Uint8List(32) : salt, [
  ..._version,
  ...suite,
  ...ascii.encode(label),
  ...ikm,
]);

Uint8List _labeledExpand(
  List<int> suite,
  List<int> prk,
  String label,
  List<int> info,
  int length,
) {
  final labeled = [
    length >> 8,
    length & 0xff,
    ..._version,
    ...suite,
    ...ascii.encode(label),
    ...info,
  ];
  final out = <int>[];
  var block = <int>[];
  for (var i = 1; out.length < length; i++) {
    block = _hmac(prk, [...block, ...labeled, i]);
    out.addAll(block);
  }
  return Uint8List.fromList(out.sublist(0, length));
}

Future<Uint8List> _dh(List<int> privateKey, List<int> publicKey) async {
  final keyPair = await _x25519.newKeyPairFromSeed(privateKey);
  final secret = await _x25519.sharedSecretKey(
    keyPair: keyPair,
    remotePublicKey: c.SimplePublicKey(publicKey, type: c.KeyPairType.x25519),
  );
  return Uint8List.fromList(await secret.extractBytes());
}

bool _allZero(List<int> bytes) => bytes.every((b) => b == 0);

/// The shared secret of the KEM for the DH output [dh] and [kemContext].
Uint8List _sharedSecret(List<int> dh, List<int> kemContext) {
  final prk = _labeledExtract(_kemSuite, const [], 'eae_prk', dh);
  return _labeledExpand(_kemSuite, prk, 'shared_secret', kemContext, 32);
}

/// The key and the base nonce of the base mode for [sharedSecret].
(Uint8List, Uint8List) _keySchedule(List<int> sharedSecret) {
  final pskIdHash = _labeledExtract(
    _hpkeSuite,
    const [],
    'psk_id_hash',
    const [],
  );
  final infoHash = _labeledExtract(_hpkeSuite, const [], 'info_hash', _info);
  final context = [0, ...pskIdHash, ...infoHash];
  final secret = _labeledExtract(_hpkeSuite, sharedSecret, 'secret', const []);
  return (
    _labeledExpand(_hpkeSuite, secret, 'key', context, 32),
    _labeledExpand(_hpkeSuite, secret, 'base_nonce', context, 12),
  );
}

/// Whether [encryptionKey] is an X25519 key of small order, for which every
/// private key gives the all-zero value (section 4.2).
Future<bool> isSmallOrderEncryptionKey(List<int> encryptionKey) async {
  if (encryptionKey.length != 32) return true;
  return _allZero(await _dh(List.filled(32, 0x42), encryptionKey));
}

/// Seals [message] for [encryptionKey] (section 4.3): `01`, the encapsulated
/// key, then the padded message encrypted with HPKE.
///
/// Throws [AxtException] `ENCRYPTION_KEY_INVALID` for a key of small order.
Future<Uint8List> seal(List<int> message, List<int> encryptionKey) {
  final padded = Uint8List(paddedLength(message.length))
    ..setAll(0, message)
    ..[message.length] = 0x80;
  return sealPlaintext(padded, encryptionKey);
}

/// Encrypts [plaintext], already padded, for [encryptionKey] with HPKE and a
/// fresh ephemeral key, and puts `01` and the encapsulated key in front.
Future<Uint8List> sealPlaintext(
  List<int> plaintext,
  List<int> encryptionKey,
) async {
  final ephemeral = await _x25519.newKeyPair();
  final enc = (await ephemeral.extractPublicKey()).bytes;
  final dh = await _dh(await ephemeral.extractPrivateKeyBytes(), encryptionKey);
  if (_allZero(dh)) {
    throw const AxtException(
      ErrorCode.encryptionKeyInvalid,
      'the X25519 output is all zero',
    );
  }
  final (key, nonce) = _keySchedule(
    _sharedSecret(dh, [...enc, ...encryptionKey]),
  );
  final box = await _aead.encrypt(
    plaintext,
    secretKey: c.SecretKey(key),
    nonce: nonce,
  );
  return Uint8List.fromList([1, ...enc, ...box.cipherText, ...box.mac.bytes]);
}

/// Opens [sealed] with the first of [privateKeys] that opens it, and removes
/// the padding (section 4.5).
///
/// Throws [AxtException] `NOT_OPENED` when it does not begin with `01` or no
/// key opens it, and `PADDING_INVALID` for a plaintext that does not end with
/// `80` followed only by zero bytes.
Future<Uint8List> open(List<int> sealed, List<List<int>> privateKeys) async {
  if (sealed.length < 1 + 32 + 16 || sealed[0] != 1) {
    throw const AxtException(ErrorCode.notOpened, 'not a sealed message');
  }
  final enc = sealed.sublist(1, 33);
  final cipherText = sealed.sublist(33, sealed.length - 16);
  final mac = c.Mac(sealed.sublist(sealed.length - 16));
  for (final privateKey in privateKeys) {
    final dh = await _dh(privateKey, enc);
    if (_allZero(dh)) continue;
    final keyPair = await _x25519.newKeyPairFromSeed(privateKey);
    final ownKey = (await keyPair.extractPublicKey()).bytes;
    final (key, nonce) = _keySchedule(_sharedSecret(dh, [...enc, ...ownKey]));
    final List<int> padded;
    try {
      padded = await _aead.decrypt(
        c.SecretBox(cipherText, nonce: nonce, mac: mac),
        secretKey: c.SecretKey(key),
      );
    } on c.SecretBoxAuthenticationError {
      continue;
    }
    var end = padded.length - 1;
    while (end >= 0 && padded[end] == 0) {
      end--;
    }
    if (end < 0 || padded[end] != 0x80) {
      throw const AxtException(
        ErrorCode.paddingInvalid,
        'the plaintext does not end with 80 and zero bytes',
      );
    }
    return Uint8List.fromList(padded.sublist(0, end));
  }
  throw const AxtException(ErrorCode.notOpened, 'no key opens it');
}
