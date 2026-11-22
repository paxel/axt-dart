import 'dart:convert';
import 'dart:typed_data';

import 'package:avro/avro.dart';
import 'package:axt_protocol/src/element_parts.dart';
import 'package:axt_protocol/src/envelope.dart';
import 'package:axt_protocol/src/errors.dart';
import 'package:axt_protocol/src/proposals.dart';
import 'package:axt_protocol/src/records.dart' show ElementKey;
import 'package:test/test.dart';

import 'key_fixtures.dart';
import 'live_session_test.dart' show signed, body;

const id = '3f2c8a5e-9b1d-4c7e-8a6f-2d4b5c6e7f80';
const proposalId = '7b3e9d21-4c8a-4f6e-9a1b-5d2c8e4f6a70';
const r1 = 'f1b3d5a7-2c4e-4f60-8a1b-3c5d7e9f0a2b';

final String note = jsonEncode({
  'type': 'record',
  'name': 'Note',
  'namespace': 'org.example',
  'fields': [
    {
      'name': 'relations',
      'type': {
        'type': 'array',
        'items': jsonDecode(axtSchema('axt.Relation').jsonText),
      },
    },
    {
      'name': 'extensions',
      'type': {
        'type': 'array',
        'items': jsonDecode(axtSchema('axt.Extension').jsonText),
      },
    },
  ],
});

final String cat = jsonEncode({
  'type': 'record',
  'name': 'Cat',
  'namespace': 'org.example',
  'fields': [
    {'name': 'fur', 'type': 'string'},
    {'name': 'when', 'type': jsonDecode(axtSchema('axt.Date').jsonText)},
  ],
});

final RecordSchema noteSchema = Schema.parse(note) as RecordSchema;
final RecordSchema catSchema = Schema.parse(cat) as RecordSchema;
final Schema relationSchema =
    (noteSchema.fields.first.schema as ArraySchema).items;

Map<String, Object?> relation(String id) => {
  'id': id,
  'kind': 'axt.related',
  'target': {'uri': 'https://example.org', 'text': ''},
  'note': '',
  'start': null,
  'end': null,
  'attributes': <String, String>{},
};

Uint8List catData(String fur) =>
    AvroCodec(writer: catSchema).encodeSingleObject({
      'fur': fur,
      'when': {'year': 2026, 'month': null, 'day': null},
    });

String hex(List<int> bytes) =>
    [for (final b in bytes) b.toRadixString(16).padLeft(2, '0')].join();

void main() {
  late TestKey owner, proposer;
  setUpAll(() async {
    owner = await TestKey.named('parts owner');
    proposer = await TestKey.named('parts proposer');
  });

  Future<ProposalOwner> ownerOf() => ProposalOwner.start(
    seed: owner.seed,
    siblings: const {},
    proposals: const {'org.example.Note'},
    schemas: [note, cat],
    receivers: [
      ProposalReceiver('p', current: {proposer.hex}, removed: {}, links: true),
    ],
    records: [
      OwnRecord(
        id: id,
        type: 'org.example.Note',
        version: 1,
        deleted: false,
        value: {
          'relations': [relation(r1)],
          'extensions': [
            {'name': 'org.example.Other', 'data': 'c301${'00' * 8}00'},
            {'name': 'org.example.Cat', 'data': hex(catData('tabby'))},
          ],
        },
        shared: {'p'},
      ),
    ],
    readers: null,
    open: [],
    answers: [],
    stops: [],
  );

  Future<Uint8List> proposal(Map<String, Uint8List> values, {Schema? schema}) =>
      signed(
        proposer,
        Kind.proposal,
        body('axt.Proposal', {
          'to': owner.public,
          'proposal_id': proposalId,
          'fields': [
            for (final e in values.entries)
              {
                'name': e.key,
                'schema': crc64ToBytes((schema ?? noteSchema).crc64),
                'value': e.value,
              },
          ],
        }),
        record: const RecordRef(id, 1),
      );

  Future<(String, String?, String?)> received(
    Map<String, Uint8List> values, {
    Schema? schema,
  }) async {
    final o = await ownerOf();
    final r = await o.receive(await proposal(values, schema: schema));
    if (r.replies.isEmpty) return (r.result, null, null);
    final envelope = decodeMessage(r.replies.single);
    final error = decodeBody(envelope.kind, envelope.body)! as Map;
    return (r.result, error['code'] as String, error['field'] as String?);
  }

  test('parts that are not valid are rejected', () async {
    final element = Uint8List.fromList([
      2,
      ...AvroCodec(writer: relationSchema).encode(relation(r1)),
    ]);
    expect(await received({'a/b/c/d': element}), (
      'rejected',
      'INVALID_MESSAGE',
      null,
    ));
    expect(await received({'relations/not-a-uuid': element}), (
      'rejected',
      'INVALID_MESSAGE',
      null,
    ));
    expect(
      await received({
        'relations/$r1': Uint8List.fromList([5]),
      }),
      ('rejected', 'UNDECODABLE', null),
    );
    expect(
      await received({
        'relations/$r1': Uint8List.fromList([2, 0x7f]),
      }),
      ('rejected', 'UNDECODABLE', null),
    );
    final badKind = Uint8List.fromList([
      2,
      ...AvroCodec(writer: relationSchema)
          .encode({...relation(r1), 'kind': 'nokind'}),
    ]);
    expect(await received({'relations/$r1': badKind}), (
      'rejected',
      'VALUE_INVALID',
      'relations/$r1.kind',
    ));
    expect(
      await received({
        'extensions/org.example.Cat/fur': Uint8List.fromList([0x7f]),
      }, schema: catSchema),
      ('rejected', 'UNDECODABLE', null),
    );
    final badDate = AvroCodec(writer: catSchema.fields[1].schema)
        .encode({'year': 2026, 'month': 13, 'day': null});
    expect(
      await received({
        'extensions/org.example.Cat/when': badDate,
      }, schema: catSchema),
      ('rejected', 'VALUE_INVALID', 'extensions/org.example.Cat/when'),
    );
    expect(
      await received({
        'extensions/org.example.Cat/nope': Uint8List.fromList([0]),
      }, schema: catSchema),
      ('rejected', 'INVALID_MESSAGE', null),
    );
  });

  test('a field within an extension is set, the others stay', () async {
    final o = await ownerOf();
    final fur = AvroCodec(writer: catSchema.fields.first.schema)
        .encode('black');
    expect(
      (await o.receive(
        await proposal({
          'extensions/org.example.Cat/fur': fur,
        }, schema: catSchema),
      )).result,
      'taken',
    );
    final made = await o.answer('p', proposalId, 'ACCEPTED');
    expect(made.update!.value['extensions'], [
      {'name': 'org.example.Other', 'data': 'c301${'00' * 8}00'},
      {'name': 'org.example.Cat', 'data': hex(catData('black'))},
    ]);
  });

  test('the proposer proposes only the parts that differ', () async {
    final values = AvroCodec(writer: noteSchema).encode({
      'relations': [relation(r1)],
      'extensions': [
        {'name': 'org.example.Cat', 'data': catData('tabby')},
        {
          'name': 'org.example.Unknown',
          'data': Uint8List.fromList([0xc3, 0x01, ...List.filled(8, 1)]),
        },
      ],
    });
    final codec = AvroCodec(writer: noteSchema);
    final decoded = codec.decode(values)! as Map<String, Object?>;
    final p = await ProposalProposer.start(
      seed: proposer.seed,
      owner: [owner.hex],
      manifests: {
        owner.hex: (revision: 1, proposals: {'org.example.Note'}),
      },
      records: [
        HeldOwnerRecord(
          id: id,
          type: 'org.example.Note',
          version: 1,
          last: 'DATA',
          schema: note,
          values: {
            for (final f in noteSchema.fields)
              f.name: AvroCodec(writer: f.schema).encode(decoded[f.name]),
          },
          deleted: false,
        ),
      ],
      proposalIds: [proposalId],
      schemas: [cat, '"string"'],
    );
    final furCodec = AvroCodec(writer: catSchema.fields.first.schema);
    final unchanged = await p.propose(id, owner.hex, {
      'a//b': Uint8List(1),
      'nolist/x': Uint8List(1),
      'relations/$r1': encodeElementPart(relationSchema, relation(r1)),
      'extensions/org.example.Cat/fur': furCodec.encode('tabby'),
      'extensions/org.example.Gone/fur': furCodec.encode('x'),
      'extensions/org.example.Unknown/fur': furCodec.encode('x'),
      'extensions/org.example.Cat/nope': furCodec.encode('x'),
    });
    expect(unchanged, isNull);
    final message = await p.propose(id, owner.hex, {
      'relations/$r1': Uint8List.fromList([0]),
    });
    final envelope = decodeMessage(message!);
    final fields =
        (decodeBody(envelope.kind, envelope.body)! as Map)['fields'] as List;
    expect((fields.single as Map)['name'], 'relations/$r1');
  });

  test('names and keys of parts', () {
    expect(partName('relations'), isNull);
    expect(partName('relations/x'), (list: 'relations', key: 'x', field: null));
    expect(() => partName('relations/'), throwsA(isA<AxtException>()));
    expect(
      elementProblem(
        ElementKey.name,
        'extensions/org.example.A',
        'org.example.A',
        {
          'name': 'org.example.B',
          'data': Uint8List.fromList([0xc3, 0x01, ...List.filled(8, 0)]),
        },
      ),
      'extensions/org.example.A.name',
    );
  });
}
