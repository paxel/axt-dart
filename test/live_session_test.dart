import 'dart:convert';
import 'dart:typed_data';

import 'package:avro/avro.dart';
import 'package:axt_protocol/src/conformance_adapter.dart';
import 'package:axt_protocol/src/ed25519.dart';
import 'package:axt_protocol/src/envelope.dart';
import 'package:axt_protocol/src/live_session.dart';
import 'package:axt_protocol/src/records.dart';
import 'package:axt_protocol/src/signing.dart';
import 'package:test/test.dart';

import 'key_fixtures.dart';

const memo =
    '{"type":"record","name":"Memo","namespace":"org.example",'
    '"fields":[{"name":"text","type":"string"}]}';

final Schema memoSchema = Schema.parse(memo);

Uint8List manifestBody(
  String name, {
  List<int> formats = const [1],
  bool takes = true,
}) => AvroCodec(writer: axtSchema('axt.Manifest')).encodeSingleObject({
  'revision': 1,
  'app_name': name,
  'app_url': null,
  'formats': formats,
  'takes': [
    if (takes)
      {
        'type': 'org.example.Memo',
        'min_version': 1,
        'max_version': null,
        'purpose': 'A Memo.',
        'purpose_translations': <String, String>{},
      },
  ],
  'any_type': null,
  'sends': null,
  'encryption_key': null,
  'relay': null,
});

Future<Uint8List> signed(
  TestKey signer,
  Kind kind,
  Uint8List body, {
  RecordRef? record,
}) async {
  final unsigned = encodeMessage(
    Envelope(
      kind: kind,
      sender: signer.public,
      record: record,
      body: body,
      signature: Uint8List(64),
    ),
  );
  final signature = await sign(signer.seed, signedBytesOfLiveMessage(unsigned));
  return unsigned..setAll(unsigned.length - 64, signature);
}

Uint8List body(String schema, Map<String, Object?> value) =>
    AvroCodec(writer: axtRawSchema(schema)).encodeSingleObject(value);

Map<String, Object?> decoded(Uint8List message) {
  final envelope = decodeMessage(message);
  return {
    'kind': envelope.kind.symbol,
    ...decodeBody(envelope.kind, envelope.body)! as Map<String, Object?>,
  };
}

const id = '3f2c8a5e-9b1d-4c7e-8a6f-2d4b5c6e7f80';
const offerId = '6f1c2b9e-3d4a-4e5f-8a7b-1c2d3e4f5a6b';

void main() {
  late TestKey a, b, c;
  setUpAll(() async {
    a = await TestKey.named('live a');
    b = await TestKey.named('live b');
    c = await TestKey.named('live c');
  });

  Future<LiveApp> appOf(
    TestKey self,
    TestKey peer, {
    Set<String> takes = const {'org.example.Memo'},
    Map<String, String> readers = const {},
  }) => LiveApp.open(
    seed: self.seed,
    manifestBody: manifestBody('app'),
    formats: const [1],
    readers: readers,
    userTakes: takes,
    peer: peer.public,
  );

  test('a receiver: manifest, offer, records, acks', () async {
    final app = await appOf(b, a);
    final offer = await signed(
      a,
      Kind.offer,
      body('axt.Offer', {
        'to': b.public,
        'offer_id': offerId,
        'types': [
          {'schema': memo, 'count': 1},
        ],
      }),
    );
    expect(
      (await app.receive(offer)).replies,
      isEmpty,
      reason: 'before the manifest',
    );
    expect(
      (await app.receive(await signed(a, Kind.manifest, manifestBody('a'))))
          .replies,
      isEmpty,
    );
    final answer = await app.receive(offer);
    expect(decoded(answer.replies.single)['kind'], 'ACCEPT');
    expect(
      decoded((await app.receive(offer)).replies.single)['kind'],
      'ACCEPT',
    );
    final data = await signed(
      a,
      Kind.data,
      AvroCodec(writer: memoSchema).encodeSingleObject({'text': 'x'}),
      record: const RecordRef(id, 1),
    );
    expect((await app.receive(data)).outcome, Outcome.applied);
    expect((await app.receive(data)).outcome, Outcome.duplicate);
    expect(app.record(id)?.version, 1);
    expect(app.record('nope'), isNull);
    final (entries, replies) = await app.flushAcks();
    expect(entries, hasLength(2));
    expect(decoded(replies.single)['kind'], 'ACK');
    final (none, noReplies) = await app.flushAcks();
    expect(none, isEmpty);
    expect(noReplies, isEmpty);
    final delete = await signed(
      a,
      Kind.delete,
      Uint8List(0),
      record: const RecordRef(id, 2),
    );
    expect((await app.receive(delete)).outcome, Outcome.applied);
    final withdraw = await signed(
      a,
      Kind.withdraw,
      body('axt.Withdraw', {'to': b.public}),
      record: const RecordRef(id, 3),
    );
    expect((await app.receive(withdraw)).outcome, Outcome.withdrawn);
    final otherTo = await signed(
      a,
      Kind.withdraw,
      body('axt.Withdraw', {'to': c.public}),
      record: const RecordRef(id, 4),
    );
    expect((await app.receive(otherTo)).replies, isEmpty);
    app.closeConnection();
    expect(
      (await app.receive(data)).replies,
      isEmpty,
      reason: 'no manifest in the new connection',
    );
  });

  test('a receiver reports what it cannot process', () async {
    final app = await appOf(
      b,
      a,
      takes: {},
      readers: {
        'org.example.Memo': '{"type":"record","name":"Memo","namespace":"org.example","fields":[{"name":"n","type":"int"}]}',
      },
    );
    Future<String?> code(Uint8List message) async {
      final replies = (await app.receive(message)).replies;
      return replies.isEmpty
          ? null
          : decoded(replies.single)['code'] as String?;
    }

    expect(await code(Uint8List(3)), isNull, reason: 'before any manifest');
    expect(
      await code(
        await signed(a, Kind.manifest, manifestBody('bad', formats: [2])),
      ),
      'MANIFEST_INVALID',
    );
    expect(
      await code(await signed(a, Kind.manifest, manifestBody('a'))),
      isNull,
    );
    expect(await code(Uint8List(3)), 'INVALID_MESSAGE');
    final data = await signed(
      a,
      Kind.data,
      AvroCodec(writer: memoSchema).encodeSingleObject({'text': 'x'}),
      record: const RecordRef(id, 1),
    );
    expect(await code(tampered(data)), 'SIGNATURE_INVALID');
    final other = Uint8List.fromList(data)..setAll(2, Uint8List(8));
    expect(await code(other), 'FORMAT_UNSUPPORTED');
    expect(await code(data), 'SCHEMA_UNKNOWN');
    expect(
      await code(
        await signed(
          a,
          Kind.manifest,
          manifestBody('a'),
          record: const RecordRef(id, 1),
        ),
      ),
      'INVALID_MESSAGE',
    );
    expect(
      await code(
        await signed(
          a,
          Kind.resync,
          body('axt.Resync', {'to': b.public}),
          record: const RecordRef(id, 1),
        ),
      ),
      'INVALID_MESSAGE',
    );
    expect(
      await code(
        await signed(
          c,
          Kind.data,
          Uint8List(0),
          record: const RecordRef(id, 1),
        ),
      ),
      isNull,
      reason: 'another sender',
    );
    Future<String?> offer(
      List<Map<String, Object?>> types, {
      String offer = offerId,
    }) async => code(
      await signed(
        a,
        Kind.offer,
        body('axt.Offer', {'to': b.public, 'offer_id': offer, 'types': types}),
      ),
    );
    expect(await offer([], offer: 'x'), 'OFFER_INVALID');
    expect(await offer([]), 'OFFER_INVALID');
    expect(
      await offer([
        {'schema': memo, 'count': -1},
      ]),
      'OFFER_INVALID',
    );
    expect(
      await offer([
        {'schema': '{', 'count': 0},
      ]),
      'OFFER_INVALID',
    );
    expect(
      await offer([
        {'schema': '"int"', 'count': 0},
      ]),
      'OFFER_INVALID',
    );
    expect(
      await offer([
        {'schema': memo, 'count': 0},
        {'schema': memo, 'count': 0},
      ]),
      'OFFER_INVALID',
    );
    expect(
      await offer([
        {'schema': ' ' * (maxSchemaBytes + 1), 'count': 0},
      ]),
      'TOO_LARGE',
    );
    final declined = await app.receive(
      await signed(
        a,
        Kind.offer,
        body('axt.Offer', {
          'to': b.public,
          'offer_id': offerId,
          'types': [
            {'schema': memo, 'count': 0},
            {
              'schema': '{"type":"record","name":"Other","namespace":"org.example","fields":[]}',
              'count': 0,
            },
          ],
        }),
      ),
    );
    expect(decoded(declined.replies.single)['kind'], 'DECLINE');
    expect(await code(data), 'NOT_ACCEPTED');
    expect(
      await code(
        await signed(
          a,
          Kind.delete,
          Uint8List(0),
          record: const RecordRef(id, 1),
        ),
      ),
      'NOT_ACCEPTED',
    );
    expect(
      await code(
        await signed(
          a,
          Kind.delete,
          Uint8List(1),
          record: const RecordRef(id, 1),
        ),
      ),
      'INVALID_MESSAGE',
    );
    expect(
      await code(
        await signed(
          a,
          Kind.delete,
          Uint8List(0),
          record: const RecordRef('x', 1),
        ),
      ),
      'RECORD_ID_INVALID',
    );
    expect(
      await code(
        await signed(
          a,
          Kind.delete,
          Uint8List(0),
          record: const RecordRef(id, 0),
        ),
      ),
      'VERSION_INVALID',
    );
    expect(
      await code(
        await signed(
          a,
          Kind.withdraw,
          Uint8List(0),
          record: const RecordRef(id, 1),
        ),
      ),
      'INVALID_MESSAGE',
    );
    expect(
      await code(
        await signed(
          a,
          Kind.withdraw,
          body('axt.Withdraw', {'to': b.public}),
          record: const RecordRef(id, 1),
        ),
      ),
      'NOT_ACCEPTED',
    );
    expect(
      await code(
        await signed(
          a,
          Kind.deviceJoin,
          body('axt.DeviceJoin', {'to': b.public, 'proof': Uint8List(64)}),
        ),
      ),
      isNull,
    );
    expect(
      await code(
        await signed(
          a,
          Kind.proposalReply,
          Uint8List(0),
          record: const RecordRef(id, 1),
        ),
      ),
      isNull,
    );
  });

  test('a sender: offers, answers, acks and errors', () async {
    final app = await appOf(a, b);
    expect(
      (await app.receive(await signed(b, Kind.manifest, manifestBody('b'))))
          .replies,
      isEmpty,
    );
    final offer = await app.offer(offerId, [(schema: memo, count: 1)]);
    expect(decoded(offer)['kind'], 'OFFER');
    expect(app.accepted('org.example.Memo'), isFalse);
    Future<Received> receive(
      Kind kind,
      String schema,
      Map<String, Object?> value,
    ) async => app.receive(await signed(b, kind, body(schema, value)));
    expect(
      (await receive(Kind.accept, 'axt.Accept', {
        'to': a.public,
        'offer_id': '7e8f9a0b-1c2d-4e3f-8a4b-5c6d7e8f9a0b',
        'types': ['org.example.Memo'],
      })).replies,
      isEmpty,
    );
    expect(
      decoded(
        (await receive(Kind.accept, 'axt.Accept', {
          'to': a.public,
          'offer_id': offerId,
          'types': ['org.example.Other'],
        })).replies.single,
      )['code'],
      'INVALID_MESSAGE',
    );
    expect(
      (await receive(Kind.accept, 'axt.Accept', {
        'to': c.public,
        'offer_id': offerId,
        'types': ['org.example.Memo'],
      })).replies,
      isEmpty,
    );
    await receive(Kind.accept, 'axt.Accept', {
      'to': a.public,
      'offer_id': offerId,
      'types': ['org.example.Memo'],
    });
    await receive(Kind.decline, 'axt.Decline', {
      'to': a.public,
      'offer_id': offerId,
      'types': [
        {'type': 'org.example.Memo', 'reason': 'NOT_WANTED'},
      ],
    });
    expect(app.accepted('org.example.Memo'), isTrue);
    Map<String, Object?> entry(
      String outcome, {
      int version = 1,
      int? receiver,
      List<String> kept = const [],
    }) => {
      'id': id,
      'version': version,
      'outcome': outcome,
      'receiver_version': receiver ?? version,
      'kept_fields': kept,
    };
    Future<String?> ack(List<Map<String, Object?>> records) async {
      final replies = (await receive(Kind.ack, 'axt.Ack', {
        'to': a.public,
        'records': records,
      })).replies;
      return replies.isEmpty
          ? null
          : decoded(replies.single)['code'] as String?;
    }

    for (final bad in [
      <Map<String, Object?>>[],
      [entry('STALE')],
      [entry('MERGED')],
      [
        entry('APPLIED', kept: ['x']),
      ],
      [entry('APPLIED'), entry('APPLIED')],
      [
        {...entry('APPLIED'), 'id': 'x'},
      ],
      [entry('APPLIED', version: 0)],
      [
        entry('MERGED', kept: ['x', 'x']),
      ],
    ]) {
      expect(await ack(bad), 'INVALID_MESSAGE', reason: '$bad');
    }
    expect(await ack([entry('KEPT')]), isNull);
    expect(await ack([entry('APPLIED')]), isNull);
    expect(app.outcomeOf(id, 1), Outcome.applied);
    expect(await ack([entry('DUPLICATE', version: 2)]), isNull);
    expect(
      await ack([
        entry('MERGED', version: 2, kept: ['text']),
      ]),
      isNull,
    );
    expect(app.outcomeOf(id, 2), Outcome.merged);
    expect(await ack([entry('KEPT', version: 3)]), isNull);
    expect(await ack([entry('WITHDRAWN', version: 3)]), isNull);
    expect(app.outcomeOf(id, 3), Outcome.withdrawn);
    expect(app.outcomeOf('x', 1), isNull);
    Future<void> error(Map<String, Object?> record, {Uint8List? to}) async =>
        receive(Kind.error, 'axt.Error', {
          'to': to ?? a.public,
          'code': 'UNDECODABLE',
          'message_hash': Uint8List(32),
          'record': record,
          'fingerprint': null,
          'field': null,
          'detail': '',
        });
    await error({'id': id, 'version': 1});
    await error({'id': id, 'version': 9});
    await error({'id': 'x', 'version': 9});
    await error({'id': id, 'version': 9}, to: c.public);
    expect(app.errors, ['UNDECODABLE', 'UNDECODABLE']);
    await app.receive(await signed(b, Kind.error, Uint8List(3)));
    expect(app.errors, hasLength(2));
  });

  test('a chain before and in the connection', () async {
    final app = await appOf(b, a);
    final rejected = await app.receive(
      await deviceAdd(a, c, proof: Uint8List(64)),
    );
    expect(rejected.replies, isEmpty);
    final manifest = await app.receive(
      await signed(a, Kind.manifest, manifestBody('a')),
    );
    expect(decoded(manifest.replies.single)['code'], 'DEVICE_REJECTED');
    expect(
      decoded(
        (await app.receive(await deviceAdd(a, c, proof: Uint8List(64))))
            .replies
            .single,
      )['code'],
      'DEVICE_REJECTED',
    );
    expect((await app.receive(await deviceAdd(a, c))).replies, isEmpty);
    final removal = await app.receive(await deviceRemove(c, a));
    expect(removal.close, isTrue);
    expect(
      (await app.receive(await signed(a, Kind.manifest, manifestBody('a'))))
          .replies,
      isEmpty,
    );
  });

  test('the adapter: formats, contact keys, resends and a session', () async {
    Future<Object?> out(String op, Object? input) async =>
        (await answer({'id': 'p', 'op': op, 'input': input}))['output'];
    expect(
      await out('choose_format', {
        'own': [1, 2],
        'theirs': [2, 3],
      }),
      {
        'accept': {'format': 2},
      },
    );
    expect(
      await out('choose_format', {
        'own': [1],
        'theirs': [2],
      }),
      {
        'accept': {'format': null},
      },
    );
    expect(
      await out('contact_key', {
        'current': ['k1', 'k2'],
        'manifests': ['k1', 'k2'],
        'got': [
          {'key': 'k2', 'kind': 'ACK'},
          {'key': 'k1', 'kind': 'MANIFEST'},
        ],
      }),
      {
        'accept': {
          'keys': ['k2'],
        },
      },
    );
    expect(
      await out('contact_key', {
        'current': ['k2', 'k1'],
        'manifests': ['k1', 'k2'],
        'got': <Object?>[],
      }),
      {
        'accept': {
          'keys': ['k1', 'k2'],
        },
      },
    );
    expect(
      await out('resend_after_removal', {
        'records': [
          {
            'id': 'r1',
            'outcomes': {'k1': 'APPLIED'},
          },
          {
            'id': 'r2',
            'outcomes': {'k2': 'APPLIED'},
          },
          {'id': 'r3', 'outcomes': <String, Object?>{}},
        ],
        'removed': ['k1'],
      }),
      {
        'accept': {
          'ids': ['r1', 'r3'],
        },
      },
    );
    final session =
        (await out('session', {
              'app': {
                'seed': toHex(b.seed),
                'manifest': toHex(manifestBody('b')),
                'formats': [1],
                'readers': <String, Object?>{},
                'user_takes': ['org.example.Memo'],
                'peer': a.hex,
              },
              'steps': [
                {
                  'receive': toHex(
                    await signed(a, Kind.manifest, manifestBody('a')),
                  ),
                },
                {
                  'offer': {
                    'offer_id': offerId,
                    'types': [
                      {'schema': memo, 'count': 0},
                    ],
                  },
                },
                {'flush_acks': true},
                {
                  'query': {'accepted': 'org.example.Memo'},
                },
                {
                  'query': {
                    'outcome': {'id': id, 'version': 1},
                  },
                },
                {
                  'query': {'record': id},
                },
                {
                  'query': {'errors': true},
                },
                {'close': true},
              ],
            }))!
            as Map;
    expect((session['steps'] as List).length, 8);
    for (final bad in [
      {'own': 'x', 'theirs': <int>[]},
    ]) {
      expect(
        await answer({'id': 'p', 'op': 'choose_format', 'input': bad}),
        containsPair('failure', isA<String>()),
      );
    }
    for (final bad in [
      {'current': <String>[], 'manifests': <String>[], 'got': 1},
    ]) {
      expect(
        await answer({'id': 'p', 'op': 'contact_key', 'input': bad}),
        containsPair('failure', isA<String>()),
      );
    }
    expect(
      await answer({
        'id': 'p',
        'op': 'resend_after_removal',
        'input': {'records': 1, 'removed': <String>[]},
      }),
      containsPair('failure', isA<String>()),
    );
    final app = {
      'seed': toHex(b.seed),
      'manifest': toHex(manifestBody('b')),
      'formats': [1],
      'readers': <String, Object?>{},
      'user_takes': ['org.example.Memo'],
      'peer': a.hex,
    };
    for (final bad in [
      {
        'app': {...app, 'user_takes': 1},
        'steps': <Object?>[],
      },
      {'app': app, 'steps': 1},
      {
        'app': app,
        'steps': [<String, Object?>{}],
      },
      {
        'app': app,
        'steps': [
          {
            'offer': {'offer_id': offerId, 'types': 1},
          },
        ],
      },
    ]) {
      expect(
        await answer({'id': 'p', 'op': 'session', 'input': bad}),
        containsPair('failure', isA<String>()),
        reason: '$bad',
      );
    }
    expect(utf8.encode('x'), [120]);
  });

  test('records under accepted offers that fail later steps', () async {
    const other =
        '{"type":"record","name":"Other","namespace":"org.example","fields":[]}';
    final app = await LiveApp.open(
      seed: b.seed,
      manifestBody: AvroCodec(writer: axtSchema('axt.Manifest'))
          .encodeSingleObject({
            'revision': 1,
            'app_name': 'b',
            'app_url': null,
            'formats': [1],
            'takes': <Object?>[],
            'any_type': {
              'purpose': 'Anything.',
              'purpose_translations': <String, String>{},
            },
            'sends': null,
            'encryption_key': null,
            'relay': null,
          }),
      formats: const [1],
      readers: const {'org.example.Memo': memo},
      userTakes: const {'org.example.Memo', 'org.example.Other'},
      peer: a.public,
    );
    await app.receive(await signed(a, Kind.manifest, manifestBody('a')));
    final offered = await app.receive(
      await signed(
        a,
        Kind.offer,
        body('axt.Offer', {
          'to': b.public,
          'offer_id': offerId,
          'types': [
            {'schema': memo, 'count': 0},
            {'schema': other, 'count': 0},
          ],
        }),
      ),
    );
    expect(decoded(offered.replies.single)['types'], [
      'org.example.Memo',
      'org.example.Other',
    ]);
    Future<String?> code(
      Uint8List bytes, {
      RecordRef ref = const RecordRef(id, 1),
    }) async {
      final replies = (await app.receive(
        await signed(a, Kind.data, bytes, record: ref),
      )).replies;
      return replies.isEmpty
          ? null
          : decoded(replies.single)['code'] as String?;
    }

    expect(await code(Uint8List(3)), 'INVALID_MESSAGE');
    final good = AvroCodec(writer: memoSchema)
        .encodeSingleObject({'text': 'x'});
    expect(
      await code(Uint8List.sublistView(good, 0, good.length - 1)),
      'UNDECODABLE',
    );
    expect(await code(good), isNull);
    final otherBody = AvroCodec(writer: Schema.parse(other))
        .encodeSingleObject(<String, Object?>{});
    expect(await code(otherBody, ref: const RecordRef(id, 2)), 'TYPE_CHANGED');
  });

  test(
    'a decline taken before an accept, and a session with a record',
    () async {
      final app = await appOf(a, b);
      await app.receive(await signed(b, Kind.manifest, manifestBody('b')));
      await app.offer(offerId, [(schema: memo, count: 0)]);
      await app.receive(
        await signed(
          b,
          Kind.decline,
          body('axt.Decline', {
            'to': a.public,
            'offer_id': offerId,
            'types': [
              {'type': 'org.example.Memo', 'reason': 'NOT_WANTED'},
            ],
          }),
        ),
      );
      expect(app.accepted('org.example.Memo'), isFalse);
      final offer = await signed(
        a,
        Kind.offer,
        body('axt.Offer', {
          'to': b.public,
          'offer_id': offerId,
          'types': [
            {'schema': memo, 'count': 0},
          ],
        }),
      );
      final data = await signed(
        a,
        Kind.data,
        AvroCodec(writer: memoSchema).encodeSingleObject({'text': 'x'}),
        record: const RecordRef(id, 1),
      );
      final session =
          (await answer({
                'id': 's',
                'op': 'session',
                'input': {
                  'app': {
                    'seed': toHex(b.seed),
                    'manifest': toHex(manifestBody('b')),
                    'formats': [1],
                    'readers': <String, Object?>{},
                    'user_takes': ['org.example.Memo'],
                    'peer': a.hex,
                  },
                  'steps': [
                    {
                      'receive': toHex(
                        await signed(a, Kind.manifest, manifestBody('a')),
                      ),
                    },
                    {'receive': toHex(offer)},
                    {'receive': toHex(data)},
                    {
                      'query': {
                        'outcome': {'id': id, 'version': 1},
                      },
                    },
                    {
                      'query': {'record': id},
                    },
                  ],
                },
              }))['output']!
              as Map;
      expect((session['steps'] as List).last, {
        'record': {'version': 1, 'state': 'there'},
      });
    },
  );
}
