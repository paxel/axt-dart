import 'dart:convert';
import 'dart:typed_data';

import 'package:avro/avro.dart';
import 'package:axt_protocol/src/device_sets.dart';
import 'package:axt_protocol/src/envelope.dart' show axtSchema;
import 'package:axt_protocol/src/links.dart';
import 'package:axt_protocol/src/relation_index.dart';
import 'package:test/test.dart';

const r1 = '00000001-4e1a-4b0e-9c22-000000000001';
const r2 = '00000002-4e1a-4b0e-9c22-000000000002';
const t1 = '00000001-5e55-4d0e-8a11-000000000001';
const t2 = '00000002-5e55-4d0e-8a11-000000000002';
const t3 = '00000003-5e55-4d0e-8a11-000000000003';

Map<String, Object?> relation(String id, Map<String, Object?> target) => {
  'id': id,
  'kind': 'axt.related',
  'target': target,
  'note': '',
  'start': null,
  'end': null,
  'attributes': <String, String>{},
};

void main() {
  test('relations are found in nested records, lists, maps and unions', () {
    final relations = {
      'type': 'array',
      'items': jsonDecode(axtSchema('axt.Relation').jsonText),
    };
    final schema = Schema.parse(
      jsonEncode({
        'type': 'record',
        'name': 'Holder',
        'namespace': 'org.example',
        'fields': [
          {
            'name': 'inner',
            'type': [
              'null',
              {
                'type': 'record',
                'name': 'Inner',
                'fields': [
                  {'name': 'links', 'type': relations},
                ],
              },
            ],
          },
          {
            'name': 'lists',
            'type': {'type': 'array', 'items': 'org.example.Inner'},
          },
          {
            'name': 'maps',
            'type': {
              'type': 'map',
              'values': {'type': 'array', 'items': 'axt.Relation'},
            },
          },
          {
            'name': 'none',
            'type': ['null', 'org.example.Inner'],
          },
        ],
      }),
    );
    final sender = Uint8List(32)..[0] = 0xab;
    final value = {
      'inner': {
        'links': [
          relation(r1, {'id': t1, 'sender': null, 'type': '', 'text': ''}),
          relation(r2, {'uri': 'https://example.org', 'text': ''}),
        ],
      },
      'lists': [
        {
          'links': [
            relation(r2, {'id': t2, 'sender': sender, 'type': '', 'text': ''}),
          ],
        },
      ],
      'maps': {
        'a': [
          relation(r1, {'id': t3, 'sender': null, 'type': '', 'text': ''}),
        ],
      },
      'none': null,
    };
    expect(recordTargets(schema, value), [
      {'id': r1, 'sender': null, 'target': t1},
      {'id': r2, 'sender': 'ab${'00' * 31}', 'target': t2},
      {'id': r1, 'sender': null, 'target': t3},
    ]);
  });

  test('a record without its links, also nested', () {
    final relations = {
      'type': 'array',
      'items': jsonDecode(axtSchema('axt.Relation').jsonText),
    };
    final extensions = {
      'type': 'array',
      'items': jsonDecode(axtSchema('axt.Extension').jsonText),
    };
    final schema = Schema.parse(
      jsonEncode({
        'type': 'record',
        'name': 'Holder',
        'namespace': 'org.example',
        'fields': [
          {
            'name': 'inner',
            'type': [
              'null',
              {
                'type': 'record',
                'name': 'Inner',
                'fields': [
                  {'name': 'links', 'type': relations},
                  {'name': 'extensions', 'type': extensions},
                ],
              },
            ],
          },
          {
            'name': 'lists',
            'type': {'type': 'array', 'items': 'org.example.Inner'},
          },
          {
            'name': 'maps',
            'type': {'type': 'map', 'values': 'org.example.Inner'},
          },
          {'name': 'text', 'type': 'string'},
        ],
      }),
    );
    final own = Uint8List(32)..[0] = 0xab;
    Map<String, Object?> inner() => {
      'links': [
        relation(r1, {'id': t1, 'sender': null, 'type': '', 'text': ''}),
        relation(r2, {'id': t2, 'sender': own, 'type': '', 'text': ''}),
        relation(r1, {
          'id': t3,
          'sender': Uint8List(32),
          'type': '',
          'text': '',
        }),
        relation(r2, {'uri': 'https://example.org', 'text': ''}),
      ],
      'extensions': [
        {'name': 'org.example.A', 'data': Uint8List(10)},
      ],
    };
    final stripped =
        withoutLinks(
              schema,
              {
                'inner': inner(),
                'lists': [inner()],
                'maps': {'a': inner()},
                'text': 'x',
              },
              shared: {t1, t2.toUpperCase(), t3},
              ownKeys: {'AB${'00' * 31}'},
            )!
            as Map<String, Object?>;
    final expected = {
      'links': [inner()['links']! as List<Object?>][0].sublist(0, 2),
      'extensions': <Object?>[],
    };
    expect(stripped['inner'], expected);
    expect(stripped['lists'], [expected]);
    expect(stripped['maps'], {'a': expected});
    expect(stripped['text'], 'x');
  });

  test('links are sorted by holder, then by relation', () {
    final s = KnownSender(
      's',
      current: {'aa'},
      records: {
        t1: const KeptRecord(1, RecordState.there),
        t2: const KeptRecord(1, RecordState.there),
      },
    );
    final resolver = RelationResolver(
      DeviceSetReceiver(senders: [s]),
      KnownSender('me', current: {'bb'}),
    );
    HeldRelation held(String id, String holder) => (
      id: id,
      holderSender: 's',
      holderId: holder,
      targetSender: null,
      targetId: t1,
    );
    final linked = resolver.linkedFrom([
      held(r2, t3),
      held(r1, t3),
      held(r1, t2),
    ]).single;
    expect((linked.sender, linked.id), ('s', t1));
    expect(linked.from, [
      (sender: 's', id: t2, relation: r1),
      (sender: 's', id: t3, relation: r1),
      (sender: 's', id: t3, relation: r2),
    ]);
    expect(
      resolver.resolve((
        id: r1,
        holderSender: 's',
        holderId: t2,
        targetSender: null,
        targetId: 'no uuid',
      )),
      (sender: 's', resolved: false),
    );
  });
}
