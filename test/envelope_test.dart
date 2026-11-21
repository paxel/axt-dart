import 'dart:typed_data';

import 'package:avro/avro.dart';
import 'package:axt_protocol/src/envelope.dart';
import 'package:axt_protocol/src/errors.dart';
import 'package:test/test.dart';

Uint8List unhex(String text) => Uint8List.fromList([
  for (var i = 0; i < text.length; i += 2)
    int.parse(text.substring(i, i + 2), radix: 16),
]);

// The DELETE of the AXT 0.1.0 vector
// encoding/decode_message/a-delete-with-an-empty-body.
const deleteHex =
    'c30116306f71b9ce9ea8020a1b84a600f3503e22bbcc99e63202a7194bf6bd69aff1471c'
    'ce6410d53c26ec4a024864346333623261312d306639652d346438632d623761362d3566'
    '346533643263316230610800ea32efa326af397ee5c8f40a8c3e7ad77009210de20c6005'
    '6ee1dd1e6eb27f8dad916c2bf409d553a5b49f71004497a56771ce21ea19f5a5986aaf49'
    'ec1f5e09';

Matcher rejectedWith(ErrorCode code) =>
    throwsA(isA<AxtException>().having((e) => e.code, 'code', code));

void main() {
  group('decodeMessage', () {
    test('reads the envelope of a DELETE', () {
      final envelope = decodeMessage(unhex(deleteHex));
      expect(envelope.format, 1);
      expect(envelope.kind, Kind.delete);
      expect(envelope.sender.length, 32);
      expect(envelope.record?.id, 'd4c3b2a1-0f9e-4d8c-b7a6-5f4e3d2c1b0a');
      expect(envelope.record?.version, 4);
      expect(envelope.body, isEmpty);
      expect(envelope.signature.length, 64);
    });

    test('encodes it back to the same bytes', () {
      final bytes = unhex(deleteHex);
      expect(encodeMessage(decodeMessage(bytes)), bytes);
    });

    test('keeps a record id that is no UUID as received', () {
      final envelope = decodeMessage(unhex(deleteHex));
      final again = decodeMessage(
        encodeMessage(
          Envelope(
            kind: envelope.kind,
            sender: envelope.sender,
            record: const RecordRef('NOT-A-UUID', 4),
            body: envelope.body,
            signature: envelope.signature,
          ),
        ),
      );
      expect(again.record?.id, 'NOT-A-UUID');
    });

    test('encodes and reads a message without a record', () {
      final envelope = Envelope(
        kind: Kind.manifest,
        sender: Uint8List(32),
        record: null,
        body: Uint8List(0),
        signature: Uint8List(64),
      );
      expect(decodeMessage(encodeMessage(envelope)).record, isNull);
    });

    test('rejects a message above 16 MiB as TOO_LARGE', () {
      expect(
        () => decodeMessage(Uint8List(maxMessageBytes + 1)),
        rejectedWith(ErrorCode.tooLarge),
      );
    });

    test('rejects another envelope fingerprint as FORMAT_UNSUPPORTED', () {
      final bytes = unhex(deleteHex)..[2] ^= 1;
      expect(
        () => decodeMessage(bytes),
        rejectedWith(ErrorCode.formatUnsupported),
      );
    });

    test('rejects a missing marker, a short message and a byte left over', () {
      expect(
        () => decodeMessage(unhex(deleteHex)..[1] = 2),
        rejectedWith(ErrorCode.invalidMessage),
      );
      expect(
        () => decodeMessage(unhex('c30116306f71b9ce9e')),
        rejectedWith(ErrorCode.invalidMessage),
      );
      expect(
        () => decodeMessage(unhex('${deleteHex}00')),
        rejectedWith(ErrorCode.invalidMessage),
      );
    });

    test('rejects format 2 under the fingerprint of format 1', () {
      final bytes = unhex(deleteHex)..[10] = 4;
      expect(
        () => decodeMessage(bytes),
        rejectedWith(ErrorCode.invalidMessage),
      );
    });
  });

  group('decodeBody', () {
    test('reads a WITHDRAW body', () {
      final body = unhex(
        'c301d57da92315f555e3da9e54c9aa2db43244df99889d9138c1ca7175d4ca0908168f'
        '63530e4a7dedb7',
      );
      final value = decodeBody(Kind.withdraw, body)! as Map<String, Object?>;
      expect((value['to']! as Uint8List).length, 32);
    });

    test('rejects an empty body and the body of another kind', () {
      expect(
        () => decodeBody(Kind.withdraw, Uint8List(0)),
        rejectedWith(ErrorCode.invalidMessage),
      );
      final resync = AvroCodec(writer: axtSchema('axt.Resync'))
          .encodeSingleObject({'to': Uint8List(32)});
      expect(
        () => decodeBody(Kind.withdraw, resync),
        rejectedWith(ErrorCode.invalidMessage),
      );
    });

    test('has no schema for DATA and DELETE', () {
      expect(() => decodeBody(Kind.data, Uint8List(0)), throwsArgumentError);
      expect(Kind.delete.bodySchema, isNull);
    });
  });

  test('every kind has the symbol of axt.Kind at its index', () {
    final symbols =
        ((axtSchema('axt.Envelope') as RecordSchema).fields[1].schema
                as EnumSchema)
            .symbols;
    expect([for (final kind in Kind.values) kind.symbol], symbols);
    expect(Kind.ofSymbol('PROPOSAL_REPLY'), Kind.proposalReply);
    expect(() => Kind.ofSymbol('NOPE'), rejectedWith(ErrorCode.invalidMessage));
  });

  test('the envelope fingerprint is that of format 1', () {
    expect(crc64ToBytes(envelopeFingerprint), unhex('16306f71b9ce9ea8'));
  });

  test('withoutLogicalTypes drops only logicalType', () {
    expect(
      withoutLogicalTypes({
        'type': 'string',
        'logicalType': 'uuid',
        'x': [
          {'logicalType': 'date', 'type': 'int'},
        ],
      }),
      {
        'type': 'string',
        'x': [
          {'type': 'int'},
        ],
      },
    );
  });

  test('axtSchema names an unknown schema', () {
    expect(() => axtSchema('axt.Nope'), throwsArgumentError);
  });

  test('AxtException names its code', () {
    expect(
      const AxtException(ErrorCode.tooLarge, 'big').toString(),
      'AxtException(TOO_LARGE): big',
    );
  });
}
