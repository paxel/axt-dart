import 'dart:typed_data';

import 'package:avro/avro.dart';
import 'package:axt_protocol/src/conformance_adapter.dart';
import 'package:axt_protocol/src/envelope.dart';
import 'package:axt_protocol/src/proposals.dart';
import 'package:test/test.dart';

import 'key_fixtures.dart';
import 'live_session_test.dart' show signed, body;

const memo =
    '{"type":"record","name":"Memo","namespace":"org.example",'
    '"fields":[{"name":"text","type":"string"},{"name":"when","type":'
    '{"type":"record","name":"Date","namespace":"axt","fields":['
    '{"name":"year","type":["null","int"]},{"name":"month","type":["null","int"]},'
    '{"name":"day","type":["null","int"]}]}}]}';

final Schema memoSchema = Schema.parse(memo);

const id = '3f2c8a5e-9b1d-4c7e-8a6f-2d4b5c6e7f80';
const proposalId = '7b3e9d21-4c8a-4f6e-9a1b-5d2c8e4f6a70';

Uint8List text(String value) =>
    AvroCodec(writer: (memoSchema as RecordSchema).fields.first.schema)
        .encode(value);

void main() {
  late TestKey owner, proposer, stranger;
  setUpAll(() async {
    owner = await TestKey.named('owner');
    proposer = await TestKey.named('proposer');
    stranger = await TestKey.named('stranger');
  });

  Future<ProposalOwner> ownerOf({
    Map<String, String>? readers,
    List<OpenProposal>? open,
    Set<String> removed = const {},
  }) => ProposalOwner.start(
    seed: owner.seed,
    siblings: const {},
    proposals: const {'org.example.Memo'},
    schemas: const [memo],
    receivers: [
      ProposalReceiver('p', current: {proposer.hex}, removed: removed),
    ],
    records: [
      OwnRecord(
        id: id,
        type: 'org.example.Memo',
        version: 1,
        deleted: false,
        value: {'text': 'a'},
        shared: {'p'},
      ),
    ],
    readers: readers,
    open: open ?? [],
    answers: [],
    stops: [],
  );

  Future<Uint8List> proposal(TestKey signer, Map<String, Uint8List> values) =>
      signed(
        signer,
        Kind.proposal,
        body('axt.Proposal', {
          'to': owner.public,
          'proposal_id': proposalId,
          'fields': [
            for (final e in values.entries)
              {
                'name': e.key,
                'schema': crc64ToBytes(memoSchema.crc64),
                'value': e.value,
              },
          ],
        }),
        record: const RecordRef(id, 1),
      );

  test('the owner ignores strangers and removed keys', () async {
    final o = await ownerOf(removed: {stranger.hex});
    expect(
      (await o.receive(await proposal(proposer, {'text': text('b')}))).result,
      'taken',
    );
    final unknown = await ownerOf();
    expect(
      (await unknown.receive(
        await proposal(await TestKey.named('nobody'), {'text': text('b')}),
      )).result,
      'ignored',
    );
    expect(
      (await o.receive(await proposal(stranger, {'text': text('b')}))).result,
      'ignored',
    );
  });

  test('the owner shows values through its reader, or cannot', () async {
    final withReader = await ownerOf(readers: {'org.example.Memo': memo});
    await withReader.receive(await proposal(proposer, {'text': text('b')}));
    final made = await withReader.answer('p', proposalId, 'ACCEPTED');
    expect(made.made, isTrue);
    expect(made.update?.value['text'], 'b');
    final otherReader = await ownerOf(
      readers: {
        'org.example.Memo': '{"type":"record","name":"Memo","namespace":"org.example","fields":[{"name":"text","type":"int"}]}',
      },
    );
    await otherReader.receive(await proposal(proposer, {'text': text('b')}));
    expect(
      (await otherReader.answer('p', proposalId, 'ACCEPTED')).made,
      isFalse,
    );
    final date = AvroCodec(
      writer: (memoSchema as RecordSchema).fields[1].schema,
    ).encode({'year': null, 'month': null, 'day': null});
    final badTime = await ownerOf(readers: {'org.example.Memo': memo});
    expect(
      (await badTime.receive(await proposal(proposer, {'when': date}))).result,
      'rejected',
    );
  });

  test(
    'an open proposal of the input cannot be accepted; a sibling answer',
    () async {
      final o = await ownerOf(
        open: [
          OpenProposal(
            receiver: 'p',
            proposalId: proposalId,
            id: id,
            version: 1,
            valueBytes: 0,
          ),
        ],
      );
      expect((await o.answer('p', proposalId, 'ACCEPTED')).made, isFalse);
      o.answered('p', 'other', 'DECLINED', id, 1);
      o.answered('p', 'other', 'ACCEPTED', id, 1);
      expect(o.answers.single.answer, 'ACCEPTED');
    },
  );

  test(
    'the proposer ignores what is no reply and replies of no body',
    () async {
      final p = await ProposalProposer.start(
        seed: proposer.seed,
        owner: [owner.hex],
        manifests: {
          owner.hex: (revision: 1, proposals: {'org.example.Memo'}),
        },
        records: [
          HeldOwnerRecord(
            id: id,
            type: 'org.example.Memo',
            version: 1,
            last: 'DATA',
            schema: memo,
            values: {
              'text': Uint8List.fromList([0xff]),
            },
            deleted: false,
          ),
        ],
        proposalIds: const [proposalId],
      );
      expect(await p.propose(id, owner.hex, {'text': text('b')}), isNotNull);
      expect((await p.receive(Uint8List(3))).result, 'ignored');
      expect(
        (await p.receive(await signed(owner, Kind.error, Uint8List(3)))).result,
        'ignored',
      );
      expect(
        (await p.receive(await signed(owner, Kind.ack, Uint8List(3)))).result,
        'ignored',
      );
      p.record(id, 'DATA', 2, {'text': text('c')});
      expect(p.records.single.values['text'], text('c'));
      p.record(id, 'DATA', 1, null);
      p.record('other', 'DATA', 9, null);
    },
  );

  test('the adapter sorts open proposals of one receiver by id', () async {
    final reply = await answer({
      'id': 'o',
      'op': 'owner',
      'input': {
        'device': {
          'seed': toHex(owner.seed),
          'open': [
            {'receiver': 'p', 'proposal_id': 'b', 'id': id},
            {'receiver': 'p', 'proposal_id': 'a', 'id': id},
          ],
        },
        'steps': [
          {'query': true},
        ],
      },
    });
    final open =
        (((reply['output']! as Map)['steps'] as List).single as Map)['open']
            as List;
    expect([for (final p in open) (p as Map)['proposal_id']], ['a', 'b']);
  });
}
