/// Applying record messages: the version rule, tombstones, the receiver's own
/// changes and the outcomes (AXT `spec/records.md`, sections 2, 3 and 5 to 7).
library;

import 'errors.dart';

/// What the receiver does when its user changed a received record (section 6).
enum LocalChanges {
  /// Merges per field (section 6.1).
  perField,

  /// Keeps the whole record as its user left it (section 6.2).
  wholeRecordKeep,

  /// Takes the whole record from the message (section 6.2).
  wholeRecordTake,
}

/// What the receiver does when a deletion meets its user's changes (6.4).
enum DeleteWithLocalChanges { delete, keep }

/// How a receiver treats its user's changes.
final class RecordPolicy {
  const RecordPolicy({
    this.localChanges = LocalChanges.perField,
    this.deleteWithLocalChanges = DeleteWithLocalChanges.keep,
  });

  final LocalChanges localChanges;

  final DeleteWithLocalChanges deleteWithLocalChanges;
}

/// The kind of a record message.
enum RecordKind { data, delete, withdraw }

/// The outcome of a record message (section 7).
enum Outcome {
  applied('APPLIED'),
  merged('MERGED'),
  kept('KEPT'),
  duplicate('DUPLICATE'),
  stale('STALE'),
  withdrawn('WITHDRAWN');

  const Outcome(this.code);

  /// The outcome as the specification writes it.
  final String code;
}

/// What a receiver holds of a record.
enum HeldState {
  there,
  tombstone,
  withdrawn,
  deletedByUser;

  /// The state as the conformance vectors write it.
  String get code => switch (this) {
    HeldState.there => 'there',
    HeldState.tombstone => 'tombstone',
    HeldState.withdrawn => 'withdrawn',
    HeldState.deletedByUser => 'deleted_by_user',
  };
}

/// What a receiver keeps of one record of one sender (section 5.1).
final class HeldRecord {
  const HeldRecord({
    required this.version,
    required this.state,
    this.type,
    this.taken,
  });

  /// The receiver's version: the highest version seen in a record message.
  final int version;

  final HeldState state;

  /// The record's type, once a `DATA` has brought it.
  final String? type;

  /// The value the receiver last took from the sender, for a record there.
  final Map<String, Object?>? taken;
}

/// The result of one record message.
final class Applied {
  const Applied({
    required this.outcome,
    required this.held,
    required this.value,
    this.keptFields = const [],
  });

  final Outcome outcome;

  /// What the receiver holds now.
  final HeldRecord held;

  /// The record as the receiver now holds it, null unless it is there.
  final Map<String, Object?>? value;

  /// For `MERGED`: the fields whose values the receiver kept, sorted.
  final List<String> keptFields;
}

final RegExp _uuid = RegExp(
  r'^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$',
);

/// The id in the form by which a receiver compares ids, as 128-bit values;
/// throws [AxtException] `RECORD_ID_INVALID` for an id that is no UUID in the
/// text form, or the nil or the max UUID (section 2).
String recordKey(String id) {
  if (!_uuid.hasMatch(id)) {
    throw AxtException(ErrorCode.recordIdInvalid, '$id is no UUID');
  }
  final key = id.toLowerCase();
  if (key == '00000000-0000-0000-0000-000000000000' ||
      key == 'ffffffff-ffff-ffff-ffff-ffffffffffff') {
    throw AxtException(ErrorCode.recordIdInvalid, '$id is the nil or max UUID');
  }
  return key;
}

/// Whether two generic values are equal, member by member; bytes compare as
/// lists.
bool sameValue(Object? a, Object? b) {
  if (a is Map && b is Map) {
    return a.length == b.length &&
        a.keys.every((k) => b.containsKey(k) && sameValue(a[k], b[k]));
  }
  if (a is List && b is List) {
    if (a.length != b.length) return false;
    for (var i = 0; i < a.length; i++) {
      if (!sameValue(a[i], b[i])) return false;
    }
    return true;
  }
  return a == b;
}

/// The fields of [current] that differ from [taken]: the user's own changes.
List<String> changedFields(
  Map<String, Object?> taken,
  Map<String, Object?> current,
) => [
  for (final field in {...taken.keys, ...current.keys})
    if (!sameValue(taken[field], current[field])) field,
];

/// Applies one record message to what the receiver holds of the record,
/// [held] (null for none), with [current], the record as the receiver's user
/// left it (null when the user deleted it or it is not there).
///
/// [type] and [value] are those of a `DATA`. Throws [AxtException]
/// `VERSION_INVALID` for a version below 1 and `TYPE_CHANGED` for a `DATA`
/// of another type than the record's. The id is checked by [recordKey].
Applied applyRecordMessage({
  required HeldRecord? held,
  required Map<String, Object?>? current,
  required RecordKind kind,
  required int version,
  required RecordPolicy policy,
  String? type,
  Map<String, Object?>? value,
}) {
  if (version < 1) {
    throw AxtException(ErrorCode.versionInvalid, 'version $version is below 1');
  }
  if (kind == RecordKind.data && held?.type != null && held!.type != type) {
    throw AxtException(
      ErrorCode.typeChanged,
      'the record is a ${held.type}, not a $type',
    );
  }
  final shown = held?.state == HeldState.there ? current : null;
  if (held != null && version <= held.version) {
    return Applied(
      outcome: version == held.version ? Outcome.duplicate : Outcome.stale,
      held: held,
      value: shown,
    );
  }
  final removed = kind == RecordKind.withdraw
      ? Outcome.withdrawn
      : Outcome.applied;
  final tombstone = kind == RecordKind.withdraw
      ? HeldState.withdrawn
      : HeldState.tombstone;
  // A record the user deleted stays deleted (section 6.3).
  if (held?.state == HeldState.deletedByUser) {
    return Applied(
      outcome: kind == RecordKind.data ? Outcome.kept : removed,
      held: HeldRecord(
        version: version,
        state: HeldState.deletedByUser,
        type: held!.type ?? type,
        taken: held.taken,
      ),
      value: null,
    );
  }
  final there = held?.state == HeldState.there;
  final changes = there && current != null
      ? changedFields(held!.taken!, current)
      : const <String>[];
  if (kind != RecordKind.data) {
    if (changes.isNotEmpty &&
        policy.deleteWithLocalChanges == DeleteWithLocalChanges.keep) {
      return Applied(
        outcome: Outcome.kept,
        held: HeldRecord(
          version: version,
          state: HeldState.there,
          type: held!.type,
          taken: held.taken,
        ),
        value: current,
      );
    }
    return Applied(
      outcome: removed,
      held: HeldRecord(version: version, state: tombstone, type: held?.type),
      value: null,
    );
  }
  final message = value!;
  if (!there || changes.isEmpty) {
    return Applied(
      outcome: Outcome.applied,
      held: HeldRecord(
        version: version,
        state: HeldState.there,
        type: type,
        taken: message,
      ),
      value: message,
    );
  }
  switch (policy.localChanges) {
    case LocalChanges.wholeRecordTake:
      return Applied(
        outcome: Outcome.applied,
        held: HeldRecord(
          version: version,
          state: HeldState.there,
          type: type,
          taken: message,
        ),
        value: message,
      );
    case LocalChanges.wholeRecordKeep:
      return Applied(
        outcome: Outcome.kept,
        held: HeldRecord(
          version: version,
          state: HeldState.there,
          type: type,
          taken: held!.taken,
        ),
        value: current,
      );
    case LocalChanges.perField:
      final merged = {...message};
      final kept = <String>[];
      for (final field in changes) {
        if (sameValue(current![field], message[field])) continue;
        merged[field] = current[field];
        kept.add(field);
      }
      kept.sort();
      return Applied(
        outcome: kept.isEmpty ? Outcome.applied : Outcome.merged,
        held: HeldRecord(
          version: version,
          state: HeldState.there,
          type: type,
          taken: message,
        ),
        value: merged,
        keptFields: kept,
      );
  }
}
