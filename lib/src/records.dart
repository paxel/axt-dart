/// Applying record messages: the version rule, tombstones, the receiver's own
/// changes and the outcomes (AXT `spec/records.md`, sections 2, 3 and 5 to 7).
library;

import 'dart:typed_data';

import 'package:avro/avro.dart';

import 'errors.dart';
import 'limits.dart';

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
    DeleteWithLocalChanges? withdrawWithLocalChanges,
  }) : _withdraw = withdrawWithLocalChanges;

  final LocalChanges localChanges;

  final DeleteWithLocalChanges deleteWithLocalChanges;

  final DeleteWithLocalChanges? _withdraw;

  /// What the receiver does when a withdrawal meets its user's changes
  /// (shares.md, section 4.3); as for a deletion unless chosen otherwise.
  DeleteWithLocalChanges get withdrawWithLocalChanges =>
      _withdraw ?? deleteWithLocalChanges;
}

/// The kind of a record message.
enum RecordKind { data, delete, withdraw }

/// The key by which the elements of a list merged per element are told
/// apart (sync.md, section 25.1).
enum ElementKey {
  /// A relation, by its `id`, compared as 128-bit values.
  id,

  /// An extension, by its `name`.
  name,
}

/// What a receiver needs to merge lists per element (section 6.1): the
/// top-level fields that are such lists, and the schemas of the extension
/// types it knows.
final class ElementMerge {
  const ElementMerge({
    this.lists = const {},
    this.writers = const {},
    this.own = const {},
  });

  /// The lists merged per element, by field name.
  final Map<String, ElementKey> lists;

  /// The writer schemas of extensions that the receiver holds, by
  /// fingerprint.
  final Map<int, Schema> writers;

  /// The receiver's own schema of each extension type it knows, by full
  /// name.
  final Map<String, Schema> own;
}

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
    this.keptAgainst,
  });

  /// The receiver's version: the highest version seen in a record message.
  final int version;

  final HeldState state;

  /// The record's type, once a `DATA` has brought it.
  final String? type;

  /// The value the receiver last took from the sender, for a record there.
  final Map<String, Object?>? taken;

  /// The kind of the message of the receiver's version that the receiver
  /// kept the record against, `DELETE` or `WITHDRAW`; null otherwise.
  final RecordKind? keptAgainst;
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
  ElementMerge elements = const ElementMerge(),
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
    final keep = kind == RecordKind.withdraw
        ? policy.withdrawWithLocalChanges
        : policy.deleteWithLocalChanges;
    if (changes.isNotEmpty && keep == DeleteWithLocalChanges.keep) {
      return Applied(
        outcome: Outcome.kept,
        held: HeldRecord(
          version: version,
          state: HeldState.there,
          type: held!.type,
          taken: held.taken,
          keptAgainst: kind,
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
        final key = elements.lists[field];
        final mine = key == null
            ? current![field]
            : _mergeElements(
                key,
                elements,
                taken: held!.taken![field] as List<Object?>? ?? const [],
                user: current![field] as List<Object?>? ?? const [],
                message: message[field] as List<Object?>? ?? const [],
              );
        if (sameValue(mine, message[field])) continue;
        merged[field] = mine;
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

/// The receiver's user takes after all the `DELETE` or the `WITHDRAW` of the
/// receiver's version that it kept the record against (protocol.md, section
/// 7.3); null when the record is kept against neither.
Applied? takeKeptRemoval(HeldRecord held) {
  final against = held.keptAgainst;
  if (against == null) return null;
  final withdraw = against == RecordKind.withdraw;
  return Applied(
    outcome: withdraw ? Outcome.withdrawn : Outcome.applied,
    held: HeldRecord(
      version: held.version,
      state: withdraw ? HeldState.withdrawn : HeldState.tombstone,
      type: held.type,
    ),
    value: null,
  );
}

/// The top-level fields of [schema] that are lists merged per element: the
/// lists of relations and of extensions.
Map<String, ElementKey> elementListsOf(Schema schema) => {
  if (schema is RecordSchema)
    for (final field in schema.fields)
      if (field.schema case ArraySchema(items: RecordSchema(:final fullName)))
        if (fullName == 'axt.Relation')
          field.name: ElementKey.id
        else if (fullName == 'axt.Extension')
          field.name: ElementKey.name,
};

/// What a receiver merges per element in a record of [schema], with the
/// extension types it knows: the [writers] it holds and its [readers], its
/// own schemas, by full name.
ElementMerge elementMergeOf(
  Schema schema, {
  required Iterable<Schema> writers,
  required Map<String, Schema> readers,
}) => ElementMerge(
  lists: elementListsOf(schema),
  writers: {
    for (final w in writers) w.crc64: w,
    for (final r in readers.values) r.crc64: r,
  },
  own: readers,
);

Object? _elementKey(ElementKey key, Object? element) {
  final map = element! as Map<String, Object?>;
  return switch (key) {
    ElementKey.id => recordKey(map['id']! as String),
    ElementKey.name => map['name'],
  };
}

/// The list merged per element from [taken], the list the receiver last
/// took from the sender, [user], its user's list, and [message] (section
/// 6.1).
List<Object?> _mergeElements(
  ElementKey key,
  ElementMerge elements, {
  required List<Object?> taken,
  required List<Object?> user,
  required List<Object?> message,
}) {
  final before = {for (final e in taken) _elementKey(key, e): e};
  final mine = {for (final e in user) _elementKey(key, e): e};
  final changed = {
    for (final MapEntry(key: k, value: e) in mine.entries)
      if (!before.containsKey(k) || !sameValue(before[k], e)) k,
  };
  final removed = {
    for (final k in before.keys)
      if (!mine.containsKey(k)) k,
  };
  final merged = <Object?>[];
  final placed = <Object?>{};
  for (final e in message) {
    final k = _elementKey(key, e);
    placed.add(k);
    if (removed.contains(k)) continue;
    if (!changed.contains(k)) {
      merged.add(e);
    } else if (key == ElementKey.name && before.containsKey(k)) {
      merged.add(_mergeExtension(elements, before[k], mine[k], e));
    } else {
      merged.add(mine[k]);
    }
  }
  for (final MapEntry(key: k, value: e) in mine.entries) {
    if (changed.contains(k) && !placed.contains(k)) merged.add(e);
  }
  final max = limit(
    key == ElementKey.id ? 'fields.relations' : 'fields.extensions',
  );
  return merged.length > max ? merged.sublist(0, max) : merged;
}

/// The extension that the user changed, [user], merged field by field with
/// [message] where the receiver knows the writer schemas of all three and
/// has its own schema of the type (fields.md, section 12.4); the user's
/// extension whole otherwise.
Object? _mergeExtension(
  ElementMerge elements,
  Object? taken,
  Object? user,
  Object? message,
) {
  final name = (user! as Map<String, Object?>)['name']! as String;
  final own = elements.own[name];
  Map<String, Object?>? decode(Object? extension) {
    final data = (extension! as Map<String, Object?>)['data']! as Uint8List;
    final SingleObjectHeader header;
    try {
      header = SingleObjectHeader.parse(data);
    } on DecodeException {
      return null;
    }
    final writer = elements.writers[header.fingerprint];
    if (writer == null || own == null) return null;
    try {
      return AvroCodec(writer: writer, reader: own).decode(header.payload)
          as Map<String, Object?>?;
    } on AvroException {
      return null;
    }
  }

  final before = decode(taken);
  final mine = decode(user);
  final theirs = decode(message);
  if (before == null || mine == null || theirs == null) return user;
  final merged = {
    for (final MapEntry(:key, :value) in theirs.entries)
      key: sameValue(mine[key], before[key]) ? value : mine[key],
  };
  return {
    'name': name,
    'data': AvroCodec(writer: own!).encodeSingleObject(merged),
  };
}
