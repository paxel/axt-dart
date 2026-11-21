/// The signatures of messages and of added devices, and the short fingerprint
/// (AXT `spec/keys.md`, sections 2.2, 3.1 and 5.2).
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as crypto;

import 'ed25519.dart';

final List<int> _messagePrefix = [...ascii.encode('AXT-v1 message'), 0];

final List<int> _deviceAddPrefix = [...ascii.encode('AXT-v1 device add'), 0];

final List<int> _fingerprintPrefix = [...ascii.encode('AXT-v1 fingerprint'), 0];

/// The bytes the signature of the live message [message] covers: the prefix
/// and the envelope without its last 64 bytes, as received.
Uint8List signedBytesOfLiveMessage(Uint8List message) => Uint8List.fromList([
  ..._messagePrefix,
  ...Uint8List.sublistView(message, 10, message.length - 64),
]);

/// Whether the live message [message], of [sender], carries a signature that
/// verifies by the strict rule over the bytes as received.
Future<bool> verifyLiveMessage(Uint8List message, Uint8List sender) =>
    verifyStrict(
      sender,
      signedBytesOfLiveMessage(message),
      Uint8List.sublistView(message, message.length - 64),
    );

/// The bytes the proof of an added device covers.
Uint8List deviceAddProofBytes(List<int> member, List<int> device) =>
    Uint8List.fromList([..._deviceAddPrefix, ...member, ...device]);

/// The short fingerprint of an Ed25519 public key (section 3.1).
String shortFingerprint(List<int> publicKey) {
  final hash = crypto.sha256.convert([
    ..._fingerprintPrefix,
    ...publicKey,
  ]).bytes;
  return [
    for (var group = 0; group < 5; group++)
      (BigInt.parse(
                [
                  for (final b in hash.sublist(5 * group, 5 * group + 5))
                    b.toRadixString(16).padLeft(2, '0'),
                ].join(),
                radix: 16,
              ) %
              BigInt.from(100000))
          .toString()
          .padLeft(5, '0'),
  ].join(' ');
}
