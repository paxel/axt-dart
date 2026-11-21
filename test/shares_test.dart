import 'package:axt_protocol/src/conformance_adapter.dart';
import 'package:axt_protocol/src/records.dart';
import 'package:axt_protocol/src/shares.dart';
import 'package:test/test.dart';

void main() {
  test('owed', () {
    ({Owes owes, int? version}) of(
      bool shared, {
      bool deleted = false,
      int? withdrawal,
      Sent? last,
    }) => owed(
      shared: shared,
      deleted: deleted,
      version: 7,
      withdrawal: withdrawal,
      last: last,
    );
    expect(of(true), (owes: Owes.data, version: 7));
    expect(of(true, deleted: true), (owes: Owes.delete, version: 7));
    expect(
      of(false, withdrawal: 6, last: (kind: RecordKind.data, version: 5)),
      (owes: Owes.withdraw, version: 6),
    );
    expect(
      of(false, withdrawal: 6, last: (kind: RecordKind.data, version: 8)),
      (owes: Owes.newWithdrawal, version: null),
    );
    expect(of(false, last: (kind: RecordKind.delete, version: 4)), (
      owes: Owes.nothing,
      version: null,
    ));
  });

  test('takeVersion', () {
    expect(takeVersion(shareAgain: false, highestGiven: 3, stateStamp: 3), (
      version: 4,
      stateStamp: 3,
    ));
    expect(takeVersion(shareAgain: true, highestGiven: 4, stateStamp: 3), (
      version: 5,
      stateStamp: 5,
    ));
  });

  test('acked', () {
    ({Outcome outcome, Then then, int? toPass}) of(
      RecordKind sent,
      Outcome outcome, {
      Outcome? held,
      int rv = 6,
      bool shared = false,
      int? withdrawal = 6,
      int state = 5,
      int? siblingStamp,
      bool sibling = false,
    }) => acked(
      sent: sent,
      held: held,
      outcome: outcome,
      receiverVersion: rv,
      shared: shared,
      withdrawal: withdrawal,
      stateStamp: state,
      siblingStamp: siblingStamp,
      sibling: sibling,
    );
    expect(of(RecordKind.withdraw, Outcome.applied).outcome, Outcome.duplicate);
    expect(of(RecordKind.data, Outcome.withdrawn).outcome, Outcome.duplicate);
    expect(
      of(RecordKind.withdraw, Outcome.kept, held: Outcome.withdrawn).outcome,
      Outcome.withdrawn,
    );
    expect(
      of(RecordKind.withdraw, Outcome.withdrawn, held: Outcome.kept).outcome,
      Outcome.withdrawn,
    );
    expect(
      of(RecordKind.data, Outcome.applied, held: Outcome.merged).outcome,
      Outcome.applied,
    );
    expect(
      of(RecordKind.data, Outcome.stale, rv: 9, shared: true, state: 7).then,
      Then.sendState,
    );
    expect(
      of(RecordKind.data, Outcome.stale, rv: 9, state: 7, siblingStamp: 8).then,
      Then.newWithdrawal,
    );
    expect(
      of(RecordKind.data, Outcome.stale, rv: 8, state: 7, siblingStamp: 8).then,
      Then.nothing,
    );
    expect(
      of(RecordKind.withdraw, Outcome.stale, rv: 7, withdrawal: null).then,
      Then.newWithdrawal,
    );
    expect(of(RecordKind.withdraw, Outcome.stale, rv: 7, sibling: true), (
      outcome: Outcome.stale,
      then: Then.wait,
      toPass: 7,
    ));
  });

  test('passWithdrawal, joinReceivers, offerTypes', () {
    expect(
      passWithdrawal(
        shared: true,
        withdrawal: 6,
        toPass: 8,
        stateStamp: 9,
      ).then,
      Then.nothing,
    );
    expect(
      passWithdrawal(
        shared: true,
        withdrawal: 6,
        toPass: 8,
        stateStamp: 7,
      ).then,
      Then.sendState,
    );
    expect(
      passWithdrawal(
        shared: false,
        withdrawal: 9,
        toPass: 8,
        stateStamp: 7,
      ).then,
      Then.nothing,
    );
    expect(
      passWithdrawal(
        shared: false,
        withdrawal: null,
        toPass: 8,
        stateStamp: 7,
      ).then,
      Then.newWithdrawal,
    );
    expect(
      joinReceivers([
        (shared: true, withdrawal: null),
        (shared: false, withdrawal: 6),
      ]),
      (shared: true, withdrawal: 6, newStateStamp: true),
    );
    expect(
      joinReceivers([
        (shared: false, withdrawal: null),
        (shared: false, withdrawal: null),
      ]),
      (shared: false, withdrawal: null, newStateStamp: false),
    );
    expect(
      offerTypes([
        (type: 'b', owes: Owes.data, delivered: false),
        (type: 'a', owes: Owes.withdraw, delivered: false),
        (type: 'a', owes: Owes.nothing, delivered: false),
        (type: 'c', owes: Owes.delete, delivered: true),
      ]),
      [(type: 'a', count: 1), (type: 'b', count: 1)],
    );
  });

  test('a withdrawal kept against, then taken', () {
    const policy = RecordPolicy(
      withdrawWithLocalChanges: DeleteWithLocalChanges.keep,
      deleteWithLocalChanges: DeleteWithLocalChanges.delete,
    );
    expect(policy.withdrawWithLocalChanges, DeleteWithLocalChanges.keep);
    final first = applyRecordMessage(
      held: null,
      current: null,
      kind: RecordKind.data,
      version: 1,
      policy: policy,
      type: 'a.M',
      value: {'t': 'a'},
    );
    final kept = applyRecordMessage(
      held: first.held,
      current: {'t': 'mine'},
      kind: RecordKind.withdraw,
      version: 2,
      policy: policy,
    );
    expect(kept.outcome, Outcome.kept);
    expect(kept.held.keptAgainst, RecordKind.withdraw);
    final taken = takeKeptRemoval(kept.held)!;
    expect(taken.outcome, Outcome.withdrawn);
    expect(taken.held.state, HeldState.withdrawn);
    final deleted = applyRecordMessage(
      held: first.held,
      current: {'t': 'mine'},
      kind: RecordKind.delete,
      version: 2,
      policy: const RecordPolicy(),
    );
    expect(takeKeptRemoval(deleted.held)!.outcome, Outcome.applied);
    expect(takeKeptRemoval(first.held), isNull);
  });

  test('the adapter answers the sender operations', () async {
    Future<Object?> out(String op, Object? input) async =>
        (await answer({'id': 's', 'op': op, 'input': input}))['output'];
    expect(
      await out('take_version', {
        'occasion': 'withdraw',
        'highest_given': '3',
        'state_stamp': '3',
      }),
      {
        'accept': {'version': '4', 'state_stamp': '3'},
      },
    );
    expect(
      await out('owed', {
        'shared': false,
        'deleted': false,
        'version': '7',
        'withdrawal': '6',
        'last': {'kind': 'WITHDRAW', 'version': '6'},
      }),
      {
        'accept': {'owes': 'WITHDRAW', 'version': '6'},
      },
    );
    expect(
      await out('acked', {
        'held': null,
        'receiver_version': '7',
        'shared': false,
        'withdrawal': '6',
        'state_stamp': '5',
        'sibling_stamp': null,
        'sibling': true,
        'sent': 'WITHDRAW',
        'outcome': 'STALE',
      }),
      {
        'accept': {'outcome': 'STALE', 'then': 'wait', 'to_pass': '7'},
      },
    );
    expect(
      await out('pass_withdrawal', {
        'shared': true,
        'withdrawal': '6',
        'to_pass': '8',
        'state_stamp': '7',
      }),
      {
        'accept': {'then': 'send_state', 'to_pass': null},
      },
    );
    expect(
      await out('join_receivers', {
        'receivers': [
          {'shared': true, 'withdrawal': null},
        ],
      }),
      {
        'accept': {
          'shared': true,
          'withdrawal': null,
          'new_state_stamp': false,
        },
      },
    );
    expect(
      await out('offer_types', {
        'records': [
          {'type': 'a', 'owes': 'DATA', 'delivered': false},
        ],
      }),
      {
        'accept': {
          'types': [
            {'type': 'a', 'count': 1},
          ],
        },
      },
    );
    const id = '3f2c8a5e-9b1d-4c7e-8a6f-2d4b5c6e7f80';
    final receive = await out('receive', {
      'policy': {
        'local_changes': 'per_field',
        'delete_with_local_changes': 'delete',
        'withdraw_with_local_changes': 'keep',
      },
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
          'message': {'kind': 'WITHDRAW', 'id': id, 'version': 2},
        },
        {
          'local_take': {'id': id},
        },
      ],
    });
    expect(
      ((receive! as Map)['steps'] as List).last,
      containsPair('outcome', 'WITHDRAWN'),
    );
    for (final bad in [
      [
        'owed',
        {
          'shared': true,
          'deleted': false,
          'version': 7,
          'withdrawal': null,
          'last': null,
        },
      ],
      [
        'owed',
        {
          'shared': true,
          'deleted': false,
          'version': '7',
          'withdrawal': null,
          'last': {'kind': 'X', 'version': '1'},
        },
      ],
      [
        'join_receivers',
        {'receivers': 1},
      ],
      [
        'offer_types',
        {'records': 1},
      ],
      [
        'receive',
        {
          'policy': {
            'local_changes': 'per_field',
            'delete_with_local_changes': 'delete',
          },
          'events': [
            {
              'local_take': {'id': id},
            },
          ],
        },
      ],
    ]) {
      expect(
        await answer({'id': 's', 'op': bad[0], 'input': bad[1]}),
        containsPair('failure', isA<String>()),
        reason: '$bad',
      );
    }
  });
}
