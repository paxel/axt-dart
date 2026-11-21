import 'dart:convert';
import 'dart:typed_data';

import 'package:avro/avro.dart';
import 'package:axt_protocol/src/ed25519.dart';
import 'package:axt_protocol/src/envelope.dart';
import 'package:axt_protocol/src/signing.dart';
import 'package:crypto/crypto.dart' as crypto;

/// A test key: its seed and its public key.
final class TestKey {
  TestKey._(this.seed, this.public);

  static Future<TestKey> named(String label) async {
    final seed = Uint8List.fromList(
      crypto.sha256.convert(utf8.encode('axt_protocol test key $label')).bytes,
    );
    return TestKey._(seed, await publicKeyOf(seed));
  }

  final Uint8List seed;
  final Uint8List public;

  String get hex => toHex(public);
}

String toHex(List<int> bytes) =>
    [for (final b in bytes) b.toRadixString(16).padLeft(2, '0')].join();

/// A live message of [kind] by [signer] with [body], signed.
Future<Uint8List> signedMessage(
  TestKey signer,
  Kind kind,
  Uint8List body,
) async {
  final unsigned = encodeMessage(
    Envelope(
      kind: kind,
      sender: signer.public,
      record: null,
      body: body,
      signature: Uint8List(64),
    ),
  );
  final signature = await sign(signer.seed, signedBytesOfLiveMessage(unsigned));
  return unsigned..setAll(unsigned.length - 64, signature);
}

Uint8List _body(String schema, Map<String, Object?> value) =>
    AvroCodec(writer: axtSchema(schema)).encodeSingleObject(value);

Future<Uint8List> proofOf(TestKey device, TestKey member) =>
    sign(device.seed, deviceAddProofBytes(member.public, device.public));

/// A `DEVICE_ADD` of [device] by [member], with the device's proof, or with
/// [proof] in its place.
Future<Uint8List> deviceAdd(
  TestKey member,
  TestKey device, {
  Uint8List? proof,
  Uint8List? deviceKey,
}) async => signedMessage(
  member,
  Kind.deviceAdd,
  _body('axt.DeviceAdd', {
    'device': deviceKey ?? device.public,
    'proof': proof ?? await proofOf(device, member),
  }),
);

/// A `DEVICE_REMOVE` of [device] by [signer].
Future<Uint8List> deviceRemove(TestKey signer, TestKey device) => signedMessage(
  signer,
  Kind.deviceRemove,
  _body('axt.DeviceRemove', {'device': device.public}),
);

/// A `DEVICE_JOIN` of [device] to [to], with its proof or [proof].
Future<Uint8List> deviceJoin(
  TestKey device,
  TestKey to, {
  Uint8List? proof,
}) async => signedMessage(
  device,
  Kind.deviceJoin,
  _body('axt.DeviceJoin', {
    'to': to.public,
    'proof': proof ?? await proofOf(device, to),
  }),
);

/// [message] with one byte of its signature changed.
Uint8List tampered(Uint8List message) =>
    Uint8List.fromList(message)..[message.length - 1] ^= 1;
