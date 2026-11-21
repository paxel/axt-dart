/// What a sending device owes a receiver, and what it does with the outcomes
/// of its withdrawals (AXT `spec/shares.md`, sections 3.2, 5 to 7; `spec/sync.md`,
/// section 5.3). Each function works on one record and one receiver.
library;

import 'records.dart';

/// What a device owes a receiver of one record (shares.md, section 5.3).
enum Owes { data, delete, withdraw, nothing, newWithdrawal }

/// The last record message of a record that a device sent a receiver.
typedef Sent = ({RecordKind kind, int version});

/// What a device owes a receiver of a record that is [shared] with it or not,
/// [deleted] or not, under its state stamp [version], with [withdrawal], the
/// version of its last recorded withdrawal from that receiver, and [last],
/// the last record message it sent there (sections 5.3 and 6.1).
({Owes owes, int? version}) owed({
  required bool shared,
  required bool deleted,
  required int version,
  required int? withdrawal,
  required Sent? last,
}) {
  if (shared) {
    return (owes: deleted ? Owes.delete : Owes.data, version: version);
  }
  if (last != null &&
      last.kind == RecordKind.data &&
      (withdrawal == null || last.version > withdrawal)) {
    return (owes: Owes.newWithdrawal, version: null);
  }
  if (withdrawal != null) return (owes: Owes.withdraw, version: withdrawal);
  return (owes: Owes.nothing, version: null);
}

/// The next version of an installation that counts (sections 3.2 and 6.2):
/// a withdrawal leaves the state stamp, a sharing again takes it.
({int version, int stateStamp}) takeVersion({
  required bool shareAgain,
  required int highestGiven,
  required int stateStamp,
}) {
  final version = highestGiven + 1;
  return (version: version, stateStamp: shareAgain ? version : stateStamp);
}

/// What a device does next for a record and a receiver.
enum Then { nothing, newWithdrawal, sendState, wait }

/// The outcome a device holds after one entry of an `ACK` (shares.md, 5.2;
/// protocol.md, 7.4), and what it does then (shares.md, 5.3; sync.md, 5.3).
({Outcome outcome, Then then, int? toPass}) acked({
  required RecordKind sent,
  required Outcome? held,
  required Outcome outcome,
  required int receiverVersion,
  required bool shared,
  required int? withdrawal,
  required int stateStamp,
  required int? siblingStamp,
  required bool sibling,
}) {
  var taken = outcome;
  if ((sent == RecordKind.withdraw &&
          (outcome == Outcome.applied || outcome == Outcome.merged)) ||
      (sent != RecordKind.withdraw && outcome == Outcome.withdrawn)) {
    taken = Outcome.duplicate;
  }
  if (held != null &&
      held != Outcome.duplicate &&
      !(taken == Outcome.applied &&
          (held == Outcome.kept || held == Outcome.merged)) &&
      !(taken == Outcome.withdrawn && held == Outcome.kept)) {
    taken = held;
  }
  if (taken != Outcome.stale) {
    return (outcome: taken, then: Then.nothing, toPass: null);
  }
  final highest = sent == RecordKind.withdraw
      ? (withdrawal ?? 0)
      : [
          stateStamp,
          ?siblingStamp,
          ?withdrawal,
        ].reduce((a, b) => a > b ? a : b);
  if (receiverVersion <= highest) {
    return (outcome: taken, then: Then.nothing, toPass: null);
  }
  if (sibling) {
    return (outcome: taken, then: Then.wait, toPass: receiverVersion);
  }
  return (
    outcome: taken,
    then: shared ? Then.sendState : Then.newWithdrawal,
    toPass: null,
  );
}

/// What a device does with the version to pass [toPass] after it has waited
/// for its siblings (shares.md, section 5.3).
({Then then, int? toPass}) passWithdrawal({
  required bool shared,
  required int? withdrawal,
  required int toPass,
  required int stateStamp,
}) {
  if (shared) {
    return (
      then: stateStamp > toPass ? Then.nothing : Then.sendState,
      toPass: null,
    );
  }
  final dropped = withdrawal != null && withdrawal >= toPass;
  return (then: dropped ? Then.nothing : Then.newWithdrawal, toPass: null);
}

/// The record toward two receivers that join (shares.md, section 7.3).
({bool shared, int? withdrawal, bool newStateStamp}) joinReceivers(
  List<({bool shared, int? withdrawal})> receivers,
) {
  final shared = receivers.any((r) => r.shared);
  final withdrawals = [for (final r in receivers) ?r.withdrawal];
  final withdrawal = withdrawals.isEmpty
      ? null
      : withdrawals.reduce((a, b) => a > b ? a : b);
  return (
    shared: shared,
    withdrawal: withdrawal,
    newStateStamp: shared && withdrawal != null,
  );
}

/// The types a device offers a receiver of another user, with the number of
/// messages it still owes of each (shares.md, section 2.2), sorted by type.
List<({String type, int count})> offerTypes(
  List<({String type, Owes owes, bool delivered})> records,
) {
  final counts = <String, int>{};
  for (final record in records) {
    if (record.owes == Owes.nothing || record.delivered) continue;
    counts[record.type] = (counts[record.type] ?? 0) + 1;
  }
  return [
    for (final type in counts.keys.toList()..sort())
      (type: type, count: counts[type]!),
  ];
}
