import 'dart:typed_data';

import 'package:axt_protocol/src/conformance_adapter.dart';
import 'package:axt_protocol/src/errors.dart';
import 'package:axt_protocol/src/records.dart';
import 'package:test/test.dart';

const id = '3f2c8a5e-9b1d-4c7e-8a6f-2d4b5c6e7f80';

Matcher rejectedWith(ErrorCode code) =>
    throwsA(isA<AxtException>().having((e) => e.code, 'code', code));

Applied data(
  HeldRecord? held,
  int version,
  Map<String, Object?> value, {
  Map<String, Object?>? current,
  RecordPolicy policy = const RecordPolicy(),
  String type = 'a.Memo',
}) => applyRecordMessage(
  held: held,
  current: current,
  kind: RecordKind.data,
  version: version,
  policy: policy,
  type: type,
  value: value,
);

Applied removal(
  HeldRecord? held,
  int version, {
  Map<String, Object?>? current,
  RecordKind kind = RecordKind.delete,
  RecordPolicy policy = const RecordPolicy(),
}) => applyRecordMessage(
  held: held,
  current: current,
  kind: kind,
  version: version,
  policy: policy,
);

void main() {
  test('ids compare as 128-bit values and must be UUIDs', () {
    expect(recordKey(id.toUpperCase()), id);
    for (final bad in [
      'vet',
      '00000000-0000-0000-0000-000000000000',
      'FFFFFFFF-ffff-ffff-ffff-ffffffffffff',
      id.replaceAll('-', ''),
    ]) {
      expect(() => recordKey(bad), rejectedWith(ErrorCode.recordIdInvalid));
    }
  });

  test('values compare member by member', () {
    expect(
      sameValue(
        {
          'a': [
            1,
            {
              'b': Uint8List.fromList([2]),
            },
          ],
        },
        {
          'a': [
            1,
            {
              'b': Uint8List.fromList([2]),
            },
          ],
        },
      ),
      isTrue,
    );
    expect(sameValue([1, 2], [1, 3]), isFalse);
    expect(sameValue([1], [1, 2]), isFalse);
    expect(sameValue({'a': 1}, {'b': 1}), isFalse);
    expect(changedFields({'a': 1, 'b': 2}, {'a': 1, 'b': 3, 'c': 4}), [
      'b',
      'c',
    ]);
  });

  test('the version rule', () {
    final first = data(null, 2, {'t': 'x'});
    expect(first.outcome, Outcome.applied);
    expect(
      data(first.held, 2, {'t': 'x'}, current: first.value).outcome,
      Outcome.duplicate,
    );
    expect(
      data(first.held, 1, {'t': 'y'}, current: first.value).outcome,
      Outcome.stale,
    );
    expect(() => data(null, 0, {}), rejectedWith(ErrorCode.versionInvalid));
    expect(
      () => data(first.held, 3, {}, type: 'a.Other'),
      rejectedWith(ErrorCode.typeChanged),
    );
  });

  test('per field: keeps the changed fields that differ', () {
    final first = data(null, 1, {'t': 'a', 'n': 'x', 'o': 1});
    final user = {'t': 'a', 'n': 'mine', 'o': 2};
    final merged = data(first.held, 2, {
      't': 'b',
      'n': 'y',
      'o': 2,
    }, current: user);
    expect(merged.outcome, Outcome.merged);
    expect(merged.keptFields, ['n']);
    expect(merged.value, {'t': 'b', 'n': 'mine', 'o': 2});
    final same = data(first.held, 2, {
      't': 'b',
      'n': 'mine',
      'o': 2,
    }, current: user);
    expect(same.outcome, Outcome.applied);
  });

  test('whole record: keep and take', () {
    final first = data(null, 1, {'t': 'a'});
    const keep = RecordPolicy(localChanges: LocalChanges.wholeRecordKeep);
    const take = RecordPolicy(localChanges: LocalChanges.wholeRecordTake);
    final kept = data(
      first.held,
      2,
      {'t': 'b'},
      current: {'t': 'mine'},
      policy: keep,
    );
    expect(kept.outcome, Outcome.kept);
    expect(kept.value, {'t': 'mine'});
    expect(kept.held.version, 2);
    final taken = data(
      first.held,
      2,
      {'t': 'b'},
      current: {'t': 'mine'},
      policy: take,
    );
    expect(taken.outcome, Outcome.applied);
    expect(taken.value, {'t': 'b'});
  });

  test('deletions, withdrawals and tombstones', () {
    final first = data(null, 1, {'t': 'a'});
    final deleted = removal(first.held, 2, current: first.value);
    expect(deleted.held.state, HeldState.tombstone);
    expect(deleted.held.type, 'a.Memo');
    expect(data(deleted.held, 3, {'t': 'c'}).outcome, Outcome.applied);
    final keptDelete = removal(first.held, 2, current: {'t': 'mine'});
    expect(keptDelete.outcome, Outcome.kept);
    expect(keptDelete.held.state, HeldState.there);
    final dropped = removal(
      first.held,
      2,
      current: {'t': 'mine'},
      policy: const RecordPolicy(
        deleteWithLocalChanges: DeleteWithLocalChanges.delete,
      ),
    );
    expect(dropped.outcome, Outcome.applied);
    final withdrawn = removal(null, 4, kind: RecordKind.withdraw);
    expect(withdrawn.outcome, Outcome.withdrawn);
    expect(withdrawn.held.state, HeldState.withdrawn);
    expect(HeldState.withdrawn.code, 'withdrawn');
  });

  test('a record its user deleted stays deleted', () {
    const gone = HeldRecord(
      version: 1,
      state: HeldState.deletedByUser,
      type: 'a.Memo',
    );
    final data2 = data(gone, 2, {'t': 'b'});
    expect(data2.outcome, Outcome.kept);
    expect(data2.held.state, HeldState.deletedByUser);
    expect(removal(gone, 3).outcome, Outcome.applied);
    expect(
      removal(gone, 3, kind: RecordKind.withdraw).outcome,
      Outcome.withdrawn,
    );
  });

  test('the adapter plays a session', () async {
    Future<Map<String, Object?>> run(Object? input) =>
        answer({'id': 'r', 'op': 'apply', 'input': input});
    const policy = {
      'local_changes': 'whole_record_keep',
      'delete_with_local_changes': 'delete',
    };
    final reply = await run({
      'policy': policy,
      'events': [
        {
          'message': {
            'kind': 'DATA',
            'id': id,
            'version': 1,
            'type': 'a.M',
            'value': {'t': 'a'},
          },
        },
        {
          'local_change': {'id': id, 'field': 't', 'value': 'b'},
        },
        {
          'local_delete': {'id': id},
        },
        {
          'message': {'kind': 'WITHDRAW', 'id': id, 'version': 2},
        },
        {
          'message': {'kind': 'DELETE', 'id': 'x', 'version': 2},
        },
      ],
    });
    final steps = reply['output']! as Map;
    expect((steps['steps'] as List).last, {'error': 'RECORD_ID_INVALID'});
    for (final bad in [
      {'policy': 1, 'events': <Object?>[]},
      {
        'policy': {...policy, 'local_changes': 'x'},
        'events': <Object?>[],
      },
      {
        'policy': {...policy, 'delete_with_local_changes': 'x'},
        'events': <Object?>[],
      },
      {'policy': policy, 'events': 1},
      {
        'policy': policy,
        'events': [1],
      },
      {
        'policy': policy,
        'events': [<String, Object?>{}],
      },
      {
        'policy': policy,
        'events': [
          {
            'message': {'kind': 'X', 'id': id, 'version': 1},
          },
        ],
      },
      {
        'policy': policy,
        'events': [
          {
            'message': {'kind': 'DATA', 'id': id, 'version': '1'},
          },
        ],
      },
    ]) {
      expect(
        await run(bad),
        containsPair('failure', isA<String>()),
        reason: '$bad',
      );
    }
    const perField = {
      'local_changes': 'per_field',
      'delete_with_local_changes': 'keep',
    };
    expect((await run({'policy': perField, 'events': <Object?>[]}))['output'], {
      'steps': <Object?>[],
    });
    const take = {
      'local_changes': 'whole_record_take',
      'delete_with_local_changes': 'keep',
    };
    expect((await run({'policy': take, 'events': <Object?>[]}))['output'], {
      'steps': <Object?>[],
    });
  });
}
