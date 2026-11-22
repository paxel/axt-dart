import 'dart:convert';
import 'dart:typed_data';

import 'package:axt_protocol/axt_protocol.dart';
import 'package:axt_protocol/src/node.dart' show nextStamp;
import 'package:test/test.dart';

import 'file_test.dart' show fileOf, memoBody, record;
import 'key_fixtures.dart';

import 'package:axt_protocol/src/envelope.dart' show Kind;

/// A store in memory whose transactions roll back on an error.
final class MemoryStore implements AxtStore {
  Map<String, Uint8List> data = {};

  @override
  Future<Uint8List?> read(String key) async => data[key];

  @override
  Future<void> write(String key, Uint8List value) async => data[key] = value;

  @override
  Future<void> delete(String key) async => data.remove(key);

  @override
  Future<List<String>> list(String prefix) async => [
    for (final key in data.keys)
      if (key.startsWith(prefix)) key,
  ];

  @override
  Future<T> transaction<T>(Future<T> Function() body) async {
    final before = Map.of(data);
    try {
      return await body();
    } catch (_) {
      data = before;
      rethrow;
    }
  }
}

Map<String, Object?> textField(String name) => {
  'name': name,
  'doc': 'The $name.',
  'texts': <String, Object?>{},
  'required': true,
  'kind': {'axt.StringField': <String, Object?>{}},
};

/// org.example.Memo, of two required texts.
final TypeDescription memo = TypeDescription.fromJson({
  'name': 'memo',
  'doc': 'A memo.',
  'texts': <String, Object?>{},
  'kind': {
    'axt.ObjectField': {
      'name': 'org.example.Memo',
      'version': 1,
      'fields': [textField('text'), textField('note')],
    },
  },
});

Map<String, Object?> manifest(String name, {bool takesMemo = true}) => {
  'app_name': name,
  'app_url': null,
  'formats': [1],
  'takes': [
    if (takesMemo)
      {
        'type': 'org.example.Memo',
        'min_version': 1,
        'max_version': null,
        'purpose': 'A Memo becomes a note.',
        'purpose_translations': <String, String>{},
      },
  ],
  'any_type': null,
  'sends': null,
  'encryption_key': null,
  'relay': null,
};

void main() {
  group('more', moreTests);
  late TestKey a, b;
  setUpAll(() async {
    a = await TestKey.named('node a');
    b = await TestKey.named('node b');
  });

  test('two apps exchange records through files', () async {
    final sender = await AxtNode.open(
      store: MemoryStore(),
      signingSeed: a.seed,
      manifest: manifest('Sender'),
    );
    final readerStore = MemoryStore();
    final reader = await AxtNode.open(
      store: readerStore,
      signingSeed: b.seed,
      manifest: manifest('Reader'),
      readers: [memo],
    );
    expect(sender.shortFingerprintOfOwnKey, hasLength(29));
    final id = newRecordId();
    final held = <String, Map<String, Object?>?>{};
    final changes = <RecordChange>[];
    Future<FileResult> read(Uint8List file, {bool accept = true}) async =>
        reader.apply(
          await reader.inspect(file),
          acceptSender: accept,
          onRecord: (change) async {
            changes.add(change);
            held[change.id] = change.value;
          },
          currentValue: (sender, id) async => held[id],
        );

    var file = await sender.writeFile([
      OutgoingRecord(id, memo, {'text': 'vet', 'note': ''}),
    ], receiver: b.public);
    final preview = await reader.inspect(file);
    expect(preview.firstContact, isTrue);
    expect(preview.senderRemoved, isFalse);
    expect(preview.appName, 'Sender');
    expect(preview.sender, a.hex);
    expect(preview.fitting, {'org.example.Memo': 1});
    expect((await read(file, accept: false)).accepted, isFalse);
    expect(changes, isEmpty);
    final first = await read(file);
    expect(first.records.single.result, 'APPLIED');
    expect(changes.single.value, {'text': 'vet', 'note': ''});
    expect((await reader.inspect(file)).firstContact, isFalse);
    expect((await read(file)).records.single.result, 'DUPLICATE');

    held[id] = {'text': 'vet', 'note': 'mine'};
    file = await sender.writeFile([
      OutgoingRecord(id, memo, {'text': 'vet at 10', 'note': ''}),
    ], receiver: b.public);
    expect((await read(file)).records.single.result, 'MERGED');
    expect(held[id], {'text': 'vet at 10', 'note': 'mine'});

    // The user discards the change; the withdrawal then removes the copy.
    held[id] = {'text': 'vet at 10', 'note': ''};
    file = await sender.writeFile([], receiver: b.public);
    expect((await read(file)).records.single.result, 'WITHDRAWN');
    expect(held[id], isNull);
    file = await sender.writeFile([], receiver: b.public);
    expect((await read(file)).records.single.result, 'DUPLICATE');

    file = await sender.writeFile([
      OutgoingRecord(id, memo, {'text': 'back', 'note': ''}),
    ], receiver: b.public);
    expect((await read(file)).records.single.result, 'APPLIED');
    file = await sender.writeFile([
      OutgoingRecord.deleted(id),
    ], receiver: b.public);
    expect((await read(file)).records.single.result, 'APPLIED');
    expect(held[id], isNull);
    file = await sender.writeFile([], receiver: b.public);
    expect((await read(file)).records, isEmpty);
  });

  test('an export has no withdrawals and a record that does not fit', () async {
    final sender = await AxtNode.open(
      store: MemoryStore(),
      signingSeed: a.seed,
      manifest: manifest('Sender'),
    );
    final reader = await AxtNode.open(
      store: MemoryStore(),
      signingSeed: b.seed,
      manifest: manifest('Reader', takesMemo: false),
    );
    final file = await sender.writeFile([
      OutgoingRecord(newRecordId(), memo, {'text': 'x', 'note': ''}),
    ]);
    final preview = await reader.inspect(file);
    expect(preview.fitting, isEmpty);
    final result = await reader.apply(
      preview,
      acceptSender: true,
      onRecord: (_) async {},
      currentValue: (_, _) async => null,
    );
    expect(result.records.single.result, 'DOES_NOT_FIT');
  });

  test('the manifest revision rises with its content', () async {
    final store = MemoryStore();
    Future<int> revision(String name) async {
      final node = await AxtNode.open(
        store: store,
        signingSeed: a.seed,
        manifest: manifest(name),
      );
      await node.writeFile([]);
      return (jsonDecode(utf8.decode(store.data['manifest']!))
              as Map)['revision']
          as int;
    }

    expect(await revision('One'), 1);
    expect(await revision('One'), 1);
    expect(await revision('Two'), 2);
  });

  test('a removed sender applies nothing', () async {
    final readerStore = MemoryStore();
    final reader = await AxtNode.open(
      store: readerStore,
      signingSeed: b.seed,
      manifest: manifest('Reader'),
    );
    final sender = await AxtNode.open(
      store: MemoryStore(),
      signingSeed: a.seed,
      manifest: manifest('Sender'),
    );
    readerStore.data['sender/s'] = utf8.encode(
      jsonEncode({
        'name': 's',
        'current': [b.hex],
        'removed': [a.hex],
      }),
    );
    final file = await sender.writeFile([
      OutgoingRecord(newRecordId(), memo, {'text': 'x', 'note': ''}),
    ]);
    final preview = await reader.inspect(file);
    expect(preview.senderRemoved, isTrue);
    final result = await reader.apply(
      preview,
      acceptSender: true,
      onRecord: (_) async {},
      currentValue: (_, _) async => null,
    );
    expect(result.records.single.result, 'SENDER_REMOVED');
  });

  test('a failure in onRecord rolls the store back', () async {
    final sender = await AxtNode.open(
      store: MemoryStore(),
      signingSeed: a.seed,
      manifest: manifest('Sender'),
    );
    final store = MemoryStore();
    final reader = await AxtNode.open(
      store: store,
      signingSeed: b.seed,
      manifest: manifest('Reader'),
    );
    final file = await sender.writeFile([
      OutgoingRecord(newRecordId(), memo, {'text': 'x', 'note': ''}),
    ]);
    final preview = await reader.inspect(file);
    await expectLater(
      reader.apply(
        preview,
        acceptSender: true,
        onRecord: (_) async => throw StateError('app failed'),
        currentValue: (_, _) async => null,
      ),
      throwsStateError,
    );
    expect(store.data, isEmpty);
  });

  test('record ids and stamps', () {
    final id = newRecordId(now: DateTime.utc(2026, 11, 21));
    expect(
      id,
      matches(
        RegExp(
          r'^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$',
        ),
      ),
    );
    expect(nextStamp(0, nowMs: 1, random: 5), 65536 + 5);
    expect(nextStamp(1 << 40, nowMs: 1, random: 0), (1 << 40) + 1);
    expect(nextStamp(5, nowMs: -1, random: 0), 6);
    expect(
      () => nextStamp(9223372036854775807 - 10, nowMs: 0, random: 0),
      throwsStateError,
    );
  });
}

/// org.example.Blob, of required bytes.
final TypeDescription blob = TypeDescription.fromJson({
  'name': 'blob',
  'doc': 'A blob.',
  'texts': <String, Object?>{},
  'kind': {
    'axt.ObjectField': {
      'name': 'org.example.Blob',
      'version': 1,
      'fields': [
        {
          'name': 'data',
          'doc': 'The data.',
          'texts': <String, Object?>{},
          'required': true,
          'kind': {'axt.BytesField': <String, Object?>{}},
        },
      ],
    },
  },
});

void moreTests() {
  late TestKey a, b;
  setUpAll(() async {
    a = await TestKey.named('more a');
    b = await TestKey.named('more b');
  });

  test(
    'bytes survive the store; an unchanged record keeps its version',
    () async {
      final sender = await AxtNode.open(
        store: MemoryStore(),
        signingSeed: a.seed,
        manifest: manifest('S'),
      );
      final reader = await AxtNode.open(
        store: MemoryStore(),
        signingSeed: b.seed,
        manifest: {
          ...manifest('R'),
          'any_type': {
            'purpose': 'Anything.',
            'purpose_translations': <String, String>{},
          },
        },
      );
      final id = newRecordId();
      final held = <String, Map<String, Object?>?>{};
      Future<List<String>> read(Uint8List file) async => [
        for (final r in (await reader.apply(
          await reader.inspect(file),
          acceptSender: true,
          onRecord: (c) async => held[c.id] = c.value,
          currentValue: (_, id) async => held[id],
        )).records)
          r.result,
      ];
      final record = OutgoingRecord(id, blob, {
        'data': Uint8List.fromList([1, 2]),
      });
      expect(await read(await sender.writeFile([record], receiver: b.public)), [
        'APPLIED',
      ]);
      expect(await read(await sender.writeFile([record], receiver: b.public)), [
        'DUPLICATE',
      ]);
      expect(await read(await sender.writeFile([], receiver: b.public)), [
        'WITHDRAWN',
      ]);
      expect(await read(await sender.writeFile([record], receiver: b.public)), [
        'APPLIED',
      ]);
    },
  );

  test('a file with an invalid manifest and an id that is no UUID', () async {
    final sender = await AxtNode.open(
      store: MemoryStore(),
      signingSeed: a.seed,
      manifest: {
        ...manifest('S'),
        'formats': [2],
      },
    );
    final reader = await AxtNode.open(
      store: MemoryStore(),
      signingSeed: b.seed,
      manifest: manifest('R'),
    );
    final file = await sender.writeFile([]);
    final preview = await reader.inspect(file);
    expect(preview.appName, isNull);
    expect(
      () => sender.writeFile([
        OutgoingRecord('nope', memo, {'text': '', 'note': ''}),
      ]),
      throwsA(isA<AxtException>()),
    );
  });

  test('apply skips a record message whose id is no UUID', () async {
    final reader = await AxtNode.open(
      store: MemoryStore(),
      signingSeed: b.seed,
      manifest: manifest('R'),
    );
    final file = await fileOf(a, [
      await record(a, Kind.data, 'nope', 1, memoBody('x')),
    ]);
    final result = await reader.apply(
      await reader.inspect(file),
      acceptSender: true,
      onRecord: (_) async {},
      currentValue: (_, _) async => null,
    );
    expect(result.records.single.result, 'RECORD_ID_INVALID');
  });
}
