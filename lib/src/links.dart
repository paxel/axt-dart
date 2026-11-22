/// The rules of relations and extensions that every receiver checks (AXT
/// `spec/fields.md`, sections 11.4 and 12.3).
library;

import 'dart:convert';
import 'dart:typed_data';

import 'errors.dart';
import 'limits.dart';
import 'records.dart' show recordKey;
import 'time_values.dart';

/// The named types of `axt.Relation` and `axt.Extension`, which a type
/// defines only as published (sections 11.6 and 12.5).
const Set<String> linkTypes = {
  'axt.Relation',
  'axt.RelationRecordTarget',
  'axt.RelationRecordTargetSender',
  'axt.RelationOutsideTarget',
  'axt.Extension',
};

final RegExp _fullName = RegExp(
  r'^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)+$',
);

int _bytes(String text) => utf8.encode(text).length;

bool _isFullName(String text, int max) =>
    _bytes(text) <= max && _fullName.hasMatch(text);

/// The key of a UUID [id], or null for one that is not valid.
String? _key(String id) {
  try {
    return recordKey(id);
  } on AxtException {
    return null;
  }
}

/// The path of the first value of the list of relations [list] at [path]
/// that breaks a rule, in the order of the encoding, or null.
String? relationsProblem(List<Object?> list, String path) {
  if (list.length > limit('fields.relations')) return path;
  final ids = <String>{};
  for (var i = 0; i < list.length; i++) {
    final at = '$path[$i]';
    final relation = list[i]! as Map<String, Object?>;
    final key = _key(relation['id']! as String);
    if (key == null || !ids.add(key)) return '$at.id';
    final found = _relationProblem(relation, at);
    if (found != null) return found;
  }
  return null;
}

String? _relationProblem(Map<String, Object?> relation, String at) {
  final name = limit('fields.relation_name');
  final textMax = limit('fields.relation_text');
  if (!_isFullName(relation['kind']! as String, name)) return '$at.kind';
  final target = relation['target']! as Map<String, Object?>;
  if (target.containsKey('uri')) {
    final uri = _bytes(target['uri']! as String);
    if (uri < 1 || uri > limit('fields.relation_uri')) return '$at.target.uri';
  } else {
    if (_key(target['id']! as String) == null) return '$at.target.id';
    final type = target['type']! as String;
    if (type.isNotEmpty && !_isFullName(type, name)) return '$at.target.type';
  }
  if (_bytes(target['text']! as String) > textMax) return '$at.target.text';
  if (_bytes(relation['note']! as String) > limit('fields.relation_note')) {
    return '$at.note';
  }
  for (final member in ['start', 'end']) {
    final time = relation[member] as Map<String, Object?>?;
    if (time != null && !isValidTimeValue('axt.DateTime', time)) {
      return '$at.$member';
    }
  }
  final attributes = (relation['attributes']! as Map<String, Object?>);
  final nameMax = limit('fields.relation_attribute_name');
  final valueMax = limit('fields.relation_attribute_value');
  if (attributes.length > limit('fields.relation_attributes') ||
      attributes.entries.any(
        (e) =>
            e.key.isEmpty ||
            _bytes(e.key) > nameMax ||
            _bytes(e.value! as String) > valueMax,
      )) {
    return '$at.attributes';
  }
  return null;
}

/// The path of the first value of the list of extensions [list] at [path]
/// that breaks a rule, in the order of the encoding, or null.
String? extensionsProblem(List<Object?> list, String path) {
  if (list.length > limit('fields.extensions')) return path;
  final names = <String>{};
  for (var i = 0; i < list.length; i++) {
    final extension = list[i]! as Map<String, Object?>;
    final name = extension['name']! as String;
    if (!_isFullName(name, limit('fields.extension_name')) ||
        !names.add(name)) {
      return '$path[$i].name';
    }
    final data = extension['data']! as Uint8List;
    if (data.length < 10 ||
        data.length > limit('fields.extension_data') ||
        data[0] != 0xc3 ||
        data[1] != 0x01) {
      return '$path[$i].data';
    }
  }
  return null;
}
