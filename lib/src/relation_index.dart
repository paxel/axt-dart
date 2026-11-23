/// Relations across senders: which record a relation points at, and which
/// relations point at a record (AXT `spec/records.md`, section 10).
library;

import 'package:avro/avro.dart';

import 'device_sets.dart';
import 'records.dart' show recordKey;
import 'errors.dart';

/// A relation with a record target that a receiver holds.
typedef HeldRelation = ({
  /// The relation's id.
  String id,

  /// The record that holds it: the name of its sender, or of the own set,
  /// and its id.
  String holderSender,
  String holderId,

  /// The key in the target's `sender`, as hexadecimal text, or null.
  String? targetSender,
  String targetId,
});

/// What a relation resolves to: the sender it names, or null for a key of no
/// known sender, and whether the receiver holds the target record, not as a
/// tombstone.
typedef Resolution = ({String? sender, bool resolved});

/// A record a relation points at, and the relations that point at it.
typedef LinkedFrom = ({
  String sender,
  String id,
  List<({String sender, String id, String relation})> from,
});

String? _key(String id) {
  try {
    return recordKey(id);
  } on AxtException {
    return null;
  }
}

/// Resolves relations as a receiver that knows the senders of [receiver]
/// and its own set [own] (records.md, section 10.2).
final class RelationResolver {
  RelationResolver(this.receiver, this.own);

  final DeviceSetReceiver receiver;

  /// The receiver's own device set and its records.
  final KnownSender own;

  KnownSender? _sender(String name) {
    final current = receiver.senderNamed(name);
    if (current == own.name) return own;
    return receiver.senders.where((s) => s.name == current).firstOrNull;
  }

  /// The sender that [relation] names, and whether it resolves.
  Resolution resolve(HeldRelation relation) {
    final key = relation.targetSender;
    final KnownSender? sender;
    if (key == null) {
      sender = _sender(relation.holderSender);
    } else if (own.current.contains(key) || own.removed.contains(key)) {
      sender = own;
    } else if (receiver.stateOf(key) == KeyState.refused) {
      sender = null;
    } else {
      sender = receiver.senderOf(key);
    }
    if (sender == null) return (sender: null, resolved: false);
    final id = _key(relation.targetId);
    final held = sender.records.entries
        .where((e) => _key(e.key) == id)
        .firstOrNull
        ?.value;
    return (
      sender: sender.name,
      resolved: id != null && held?.state == RecordState.there,
    );
  }

  /// The records to which at least one of [relations] resolves, with the
  /// relations, sorted by sender and id, their relations by holder and id.
  List<LinkedFrom> linkedFrom(List<HeldRelation> relations) {
    final out = <String, LinkedFrom>{};
    for (final relation in relations) {
      final resolution = resolve(relation);
      if (!resolution.resolved) continue;
      final sender = resolution.sender!;
      final id = recordKey(relation.targetId);
      out
          .putIfAbsent(
            '$sender\u0000$id',
            () => (sender: sender, id: id, from: []),
          )
          .from
          .add((
            sender: receiver.senderNamed(relation.holderSender),
            id: recordKey(relation.holderId),
            relation: relation.id,
          ));
    }
    int byText(String a, String b) => a.compareTo(b);
    final sorted = out.values.toList()
      ..sort(
        (a, b) => a.sender != b.sender
            ? byText(a.sender, b.sender)
            : byText(a.id, b.id),
      );
    for (final linked in sorted) {
      linked.from.sort(
        (a, b) => a.sender != b.sender
            ? byText(a.sender, b.sender)
            : a.id != b.id
            ? byText(a.id, b.id)
            : byText(a.relation, b.relation),
      );
    }
    return sorted;
  }
}

/// The relations with a record target in [value], a record of [schema], in
/// the order of the encoding: each as its `id`, the target's `sender` as
/// hexadecimal text or null, and the target's id as `target`.
List<Map<String, Object?>> recordTargets(Schema schema, Object? value) {
  final out = <Map<String, Object?>>[];
  void walk(Schema schema, Object? value) {
    switch (schema) {
      case ArraySchema(items: RecordSchema(fullName: 'axt.Relation')):
        for (final r
            in (value! as List<Object?>).cast<Map<String, Object?>>()) {
          // A value the app built may hold the target as a branch.
          final target = switch (r['target']) {
            Branch(:final value) => value! as Map<String, Object?>,
            final value => value! as Map<String, Object?>,
          };
          if (!target.containsKey('id')) continue;
          final sender = target['sender'] as List<int>?;
          out.add({
            'id': r['id'],
            'sender': sender == null
                ? null
                : [for (final b in sender) b.toRadixString(16).padLeft(2, '0')]
                      .join(),
            'target': target['id'],
          });
        }
      case RecordSchema(:final fields):
        final record = value! as Map<String, Object?>;
        for (final f in fields) {
          walk(f.schema, record[f.name]);
        }
      case ArraySchema(:final items):
        for (final item in value! as List<Object?>) {
          walk(items, item);
        }
      case MapSchema(:final values):
        for (final v in (value! as Map<String, Object?>).values) {
          walk(values, v);
        }
      case UnionSchema(:final branches) when value != null:
        // A derived schema has unions of null and one type only.
        walk(branches.last, value);
      default:
        break;
    }
  }

  walk(schema, value);
  return out;
}
