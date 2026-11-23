import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:avro/avro.dart';
import 'package:axt_protocol/src/conformance_adapter.dart';
import 'package:axt_protocol/src/container.dart';
import 'package:axt_protocol/src/ed25519.dart';
import 'package:axt_protocol/src/envelope.dart';
import 'package:axt_protocol/src/errors.dart';
import 'package:axt_protocol/src/file_reader.dart';
import 'package:axt_protocol/src/records.dart';
import 'package:axt_protocol/src/signing.dart';
import 'package:axt_protocol/src/type_description.dart';
import 'package:test/test.dart';

import 'key_fixtures.dart';

/// org.example.Memo, of one required text.
final TypeDescription memoType = TypeDescription.fromJson({
  'name': 'memo',
  'doc': 'A memo.',
  'texts': <String, Object?>{},
  'kind': {
    'axt.ObjectField': {
      'name': 'org.example.Memo',
      'version': 1,
      'fields': [
        {
          'name': 'text',
          'doc': 'The text.',
          'texts': <String, Object?>{},
          'required': true,
          'kind': {'axt.StringField': <String, Object?>{}},
        },
      ],
    },
  },
});

/// The entry of Memo in `axt.schemas`, as JSON text.
final String memo = jsonEncode(memoType.fileEntry);

final Schema memoSchema = memoType.schema;

Matcher rejected = throwsA(
  isA<AxtException>().having((e) => e.code, 'code', ErrorCode.fileRejected),
);

Uint8List datum(Uint8List live) => Uint8List.sublistView(live, 10);

Uint8List memoBody(String text) =>
    AvroCodec(writer: memoSchema).encodeSingleObject({'text': text});

Future<Uint8List> record(
  TestKey signer,
  Kind kind,
  String id,
  int version,
  Uint8List body,
) async {
  final unsigned = encodeMessage(
    Envelope(
      kind: kind,
      sender: signer.public,
      record: RecordRef(id, version),
      body: body,
      signature: Uint8List(64),
    ),
  );
  final signature = await sign(signer.seed, signedBytesOfLiveMessage(unsigned));
  return unsigned..setAll(unsigned.length - 64, signature);
}

Future<Uint8List> fileOf(
  TestKey sender,
  List<Uint8List> messages, {
  String? schemas = 'memo',
  Map<String, Uint8List?> override = const {},
  bool deflate = false,
}) async {
  final schemasBytes = schemas == null
      ? null
      : utf8.encode(schemas == 'memo' ? '[$memo]' : schemas);
  final signature = await sign(
    sender.seed,
    fileHeaderSignedBytes(sender.public, schemasBytes),
  );
  final metadata = <String, Uint8List>{
    'avro.schema': utf8.encode(axtSchemaText('axt.Envelope')),
    'axt.schemas': ?schemasBytes,
    'axt.sender': ascii.encode(sender.hex),
    'axt.signature': ascii.encode(toHex(signature)),
  };
  for (final MapEntry(:key, :value) in override.entries) {
    if (value == null) {
      metadata.remove(key);
    } else {
      metadata[key] = value;
    }
  }
  return writeContainer(
    metadata,
    [for (final m in messages) datum(m)],
    syncMarker: Uint8List(16),
    deflate: deflate,
  );
}

const id = '3f2c8a5e-9b1d-4c7e-8a6f-2d4b5c6e7f80';

void main() {
  late TestKey a, b;
  setUpAll(() async {
    a = await TestKey.named('file a');
    b = await TestKey.named('file b');
  });

  test('a good file, with and without deflate', () async {
    for (final deflate in [false, true]) {
      final file = await fileOf(a, [
        await record(a, Kind.data, id, 1, memoBody('x')),
      ], deflate: deflate);
      final checked = await checkFile(file);
      expect(checked.records, hasLength(1));
      expect(checked.sender, a.public);
    }
  });

  test('the container rejects what is no container file', () async {
    final good = await fileOf(a, [
      await record(a, Kind.data, id, 1, memoBody('x')),
    ]);
    expect(() => checkFile(Uint8List.fromList([1, 2, 3, 4])), rejected);
    expect(
      () => checkFile(Uint8List.fromList(good.sublist(0, good.length - 3))),
      rejected,
    );
    final badSync = Uint8List.fromList(good)..[good.length - 1] ^= 1;
    expect(() => checkFile(badSync), rejected);
    final snappy = BytesBuilder()
      ..add([0x4f, 0x62, 0x6a, 1, 2, 20])
      ..add(ascii.encode('avro.codec'))
      ..add([12])
      ..add(ascii.encode('snappy'))
      ..add([0])
      ..add(Uint8List(16));
    expect(() => checkFile(snappy.takeBytes()), rejected);
    expect(() => checkFile(Uint8List(maxFileBytes + 1)), rejected);
    final notInflating = writeContainer(
      {'avro.codec': ascii.encode('deflate')},
      [],
      syncMarker: Uint8List(16),
    );
    final broken = BytesBuilder()
      ..add(notInflating)
      ..add([2, 6, 0xff, 0xff, 0xff])
      ..add(Uint8List(16));
    expect(() => checkFile(broken.takeBytes()), rejected);
    final leftOver = BytesBuilder()
      ..add(writeContainer({}, [], syncMarker: Uint8List(16), deflate: false))
      ..add([0, 2, 0])
      ..add(Uint8List(16));
    expect(() => checkFile(leftOver.takeBytes()), rejected);
    final negative = BytesBuilder()
      ..add(writeContainer({}, [], syncMarker: Uint8List(16), deflate: false))
      ..add([1, 0])
      ..add(Uint8List(16));
    expect(() => checkFile(negative.takeBytes()), rejected);
  });

  test('the metadata may come in a block with a byte size', () {
    final out = BytesBuilder()
      ..add([0x4f, 0x62, 0x6a, 1])
      ..add([1, 2]) // -1 entries, 1 byte size
      ..add([2, 0x61, 2, 0x62])
      ..add([0])
      ..add(Uint8List(16));
    expect(Container.read(out.takeBytes(), envelopeLength).metadata['a'], [
      0x62,
    ]);
    final badKey = BytesBuilder()
      ..add([0x4f, 0x62, 0x6a, 1])
      ..add([2, 2, 0xff, 0, 0])
      ..add(Uint8List(16));
    expect(() => Container.read(badKey.takeBytes(), envelopeLength), rejected);
    final longVarint = Uint8List.fromList([
      0x4f,
      0x62,
      0x6a,
      1,
      ...List.filled(11, 0xff),
    ]);
    expect(() => Container.read(longVarint, envelopeLength), rejected);
  });

  test('the header rules reject the whole file', () async {
    final message = await record(a, Kind.data, id, 1, memoBody('x'));
    for (final override in [
      {'avro.schema': null},
      {'avro.schema': ascii.encode('"int"')},
      {
        'avro.schema': Uint8List.fromList([0xff]),
      },
      {'avro.schema': ascii.encode('{')},
      {'axt.sender': null},
      {'axt.sender': ascii.encode(a.hex.toUpperCase())},
      {'axt.signature': ascii.encode('00' * 64)},
    ]) {
      expect(
        () async => checkFile(await fileOf(a, [message], override: override)),
        rejected,
        reason: '$override',
      );
    }
    final entry = memoType.fileEntry;
    for (final schemas in [
      '[',
      '{}',
      '[1]',
      '[$memo,$memo]',
      jsonEncode([
        {'description': entry['description']},
      ]),
      jsonEncode([
        {'description': <String, Object?>{}, 'schema': entry['schema']},
      ]),
      jsonEncode([
        {'description': entry['description'], 'schema': '"int"'},
      ]),
      jsonEncode([
        {'description': entry['description'], 'schema': 'string'},
      ]),
    ]) {
      expect(
        () async => checkFile(await fileOf(a, [message], schemas: schemas)),
        rejected,
        reason: schemas,
      );
    }
    expect(
      () async => checkFile(await fileOf(a, [message], schemas: null)),
      rejected,
    );
    final badUtf8 = utf8.encode('[$memo]')..[0] = 0xff;
    final signature = await sign(
      a.seed,
      fileHeaderSignedBytes(a.public, badUtf8),
    );
    expect(
      () async => checkFile(
        await fileOf(
          a,
          [message],
          override: {
            'axt.schemas': badUtf8,
            'axt.signature': ascii.encode(toHex(signature)),
          },
        ),
      ),
      rejected,
    );
  });

  test('the message rules reject the whole file', () async {
    final data = await record(a, Kind.data, id, 1, memoBody('x'));
    final manifestBody = AvroCodec(writer: axtSchema('axt.Manifest'))
        .encodeSingleObject({
          'revision': 1,
          'app_name': 'a',
          'app_url': null,
          'formats': [1],
          'takes': <Object?>[],
          'any_type': null,
          'sends': null,
          'encryption_key': null,
          'relay': null,
        });
    final manifest = await signedMessage(a, Kind.manifest, manifestBody);
    final cases = <String, List<Uint8List>>{
      'a kind a file does not hold': [
        await signedMessage(
          a,
          Kind.resync,
          AvroCodec(writer: axtSchema('axt.Resync'))
              .encodeSingleObject({'to': b.public}),
        ),
      ],
      'a device change after a record': [data, await deviceAdd(a, b)],
      'a second manifest': [manifest, manifest],
      'a manifest after a record': [data, manifest],
      'a DATA without a record': [
        await signedMessage(a, Kind.data, memoBody('x')),
      ],
      'a DELETE with a body': [
        await record(a, Kind.delete, id, 2, memoBody('x')),
      ],
      'a DATA of no single-object body': [
        await record(a, Kind.data, id, 1, Uint8List(3)),
      ],
      'a DATA of an unknown fingerprint': [
        await record(
          a,
          Kind.data,
          id,
          1,
          AvroCodec(writer: Schema.parse('"string"')).encodeSingleObject('x'),
        ),
      ],
      'a manifest of another body': [
        await signedMessage(a, Kind.manifest, Uint8List(12)),
      ],
      'a bad signature': [tampered(data)],
      'a device change with a bad proof': [
        await deviceAdd(a, b, proof: Uint8List(64)),
      ],
      'another sender': [await record(b, Kind.data, id, 1, memoBody('x'))],
      'no envelope': [
        Uint8List.fromList([...data.sublist(0, 10), 4, ...data.sublist(11)]),
      ],
    };
    for (final MapEntry(:key, :value) in cases.entries) {
      expect(
        () async => checkFile(await fileOf(a, value)),
        rejected,
        reason: key,
      );
    }
    final badUnion = BytesBuilder()
      ..add(writeContainer({}, [], syncMarker: Uint8List(16), deflate: false))
      ..add([2, 72])
      ..add([2, 8, ...a.public, 4])
      ..add(Uint8List(16));
    expect(() => checkFile(badUnion.takeBytes()), rejected);
  });

  test('records of a file: ids, versions, fit, withdrawals', () async {
    final readerManifest = {
      'revision': 1,
      'app_name': 'r',
      'app_url': null,
      'formats': [1],
      'takes': [
        {
          'type': 'org.example.Memo',
          'min_version': 1,
          'max_version': null,
          'purpose': 'x',
          'purpose_translations': <String, String>{},
        },
      ],
      'any_type': null,
      'sends': null,
      'encryption_key': null,
      'relay': null,
    };
    final withdraw = AvroCodec(writer: axtSchema('axt.Withdraw'))
        .encodeSingleObject({'to': b.public});
    final file = await checkFile(
      await fileOf(a, [
        await record(a, Kind.data, 'bad', 1, memoBody('x')),
        await record(a, Kind.data, id, 0, memoBody('x')),
        await record(a, Kind.data, id, 1, memoBody('x')),
        await record(a, Kind.withdraw, id, 2, withdraw),
        await record(a, Kind.delete, id, 3, Uint8List(0)),
      ]),
    );
    final held = <String, HeldRecord>{};
    final results = await readFileRecords(
      file,
      FileReader(
        manifest: readerManifest,
        readers: {
          'org.example.Memo': '{"type":"record","name":"Memo","namespace":"org.example","fields":[{"name":"n","type":"int"}]}',
        },
      ),
      held: held,
      current: {},
    );
    expect(
      [for (final r in results) r.result],
      [
        'RECORD_ID_INVALID',
        'VERSION_INVALID',
        'DOES_NOT_RESOLVE',
        'IGNORED',
        'APPLIED',
      ],
    );
    final again = await readFileRecords(
      file,
      FileReader(manifest: readerManifest, readers: const {}, current: {b.hex}),
      held: {
        id: const HeldRecord(
          version: 0,
          state: HeldState.there,
          type: 'org.example.Other',
          taken: {},
        ),
      },
      current: {},
    );
    expect(
      [for (final r in again) r.result],
      [
        'RECORD_ID_INVALID',
        'VERSION_INVALID',
        'TYPE_CHANGED',
        'WITHDRAWN',
        'APPLIED',
      ],
    );
  });

  test('the adapter reads files', () async {
    final manifestBody = AvroCodec(writer: axtSchema('axt.Manifest'))
        .encodeSingleObject({
          'revision': 1,
          'app_name': 'a',
          'app_url': null,
          'formats': [2],
          'takes': <Object?>[],
          'any_type': {
            'purpose': 'Anything.',
            'purpose_translations': <String, String>{},
          },
          'sends': null,
          'encryption_key': null,
          'relay': null,
        });
    final file = await fileOf(a, [
      await deviceAdd(a, b),
      await signedMessage(a, Kind.manifest, manifestBody),
      await record(a, Kind.data, id, 1, memoBody('x')),
    ]);
    Future<Map<String, Object?>> read(Uint8List bytes, {Object? keys}) =>
        answer({
          'id': 'f',
          'op': 'read_file',
          'input': {
            'file': toHex(bytes),
            'reader': {
              'manifest': toHex(manifestBody),
              'readers': <String, Object?>{},
              'keys': keys,
            },
          },
        });
    final reply = (await read(file))['output']! as Map;
    expect(reply['accept']['manifest'], 'invalid');
    expect(reply['accept']['chain'].single['result'], 'APPLIED');
    expect(reply['accept']['records'].single['result'], 'APPLIED');
    expect((await read(Uint8List(4)))['output'], {
      'reject': {'error': 'FILE_REJECTED'},
    });
    final removed = await fileOf(b, [
      await deviceAdd(b, a),
      await deviceRemove(a, b),
      await record(b, Kind.data, id, 1, memoBody('x')),
    ]);
    final removedReply =
        (await read(
              removed,
              keys: {'current': <String>[], 'removed': <String>[]},
            ))['output']!
            as Map;
    expect(
      removedReply['accept']['records'].single['result'],
      'SENDER_REMOVED',
    );
    expect(removedReply['accept']['manifest'], 'none');
    expect(
      await answer({
        'id': 'f',
        'op': 'read_file',
        'input': {
          'file': '',
          'reader': {'manifest': toHex(manifestBody), 'readers': 1},
        },
      }),
      containsPair('failure', isA<String>()),
    );
  });

  test('a manifest that is valid is used', () async {
    final body = AvroCodec(writer: axtSchema('axt.Manifest'))
        .encodeSingleObject({
          'revision': 1,
          'app_name': 'a',
          'app_url': null,
          'formats': [1],
          'takes': <Object?>[],
          'any_type': null,
          'sends': null,
          'encryption_key': null,
          'relay': null,
        });
    final file = await fileOf(a, [
      await signedMessage(a, Kind.manifest, body),
    ], schemas: null);
    final reply = await answer({
      'id': 'f',
      'op': 'read_file',
      'input': {
        'file': toHex(file),
        'reader': {'manifest': toHex(body), 'readers': <String, Object?>{}},
      },
    });
    expect((reply['output']! as Map)['accept']['manifest'], 'used');
    expect(File('lib/src/container.dart').existsSync(), isTrue);
  });

  test('limits of the metadata and of a block', () {
    final big = writeContainer(
      {'x': Uint8List(maxMetadataBytes + 1)},
      [],
      syncMarker: Uint8List(16),
      deflate: false,
    );
    expect(() => checkFile(big), rejected);
    final block = BytesBuilder()
      ..add(writeContainer({}, [], syncMarker: Uint8List(16), deflate: false))
      ..add([2, 0x82, 0x80, 0x80, 0x40])
      ..add(Uint8List(maxBlockBytes + 1))
      ..add(Uint8List(16));
    expect(() => checkFile(block.takeBytes()), rejected);
  });

  test('a schema that is not published has no text', () {
    expect(() => axtSchemaText('axt.Nope'), throwsArgumentError);
  });
}
