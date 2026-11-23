/// Proposals of single elements: element parts and parts within an
/// extension (AXT `spec/shares.md`, sections 19.3 and 20; `spec/sync.md`,
/// sections 25.1, 25.2 and 25.9).
library;

import 'dart:typed_data';

import 'package:avro/avro.dart';

import 'errors.dart';
import 'links.dart';
import 'records.dart';

/// The name of an entry that is a part: the list, the key text of the
/// element, and for a part within an extension the field's name.
typedef PartName = ({String list, String key, String? field});

/// [name] as a part, or null for a top-level field.
///
/// Throws [AxtException] `INVALID_MESSAGE` for a name with a `/` that is no
/// part.
PartName? partName(String name) {
  final segments = name.split('/');
  if (segments.length == 1) return null;
  if (segments.length > 3 || segments.any((s) => s.isEmpty)) {
    throw AxtException(ErrorCode.invalidMessage, '$name is no part');
  }
  return (
    list: segments[0],
    key: segments[1],
    field: segments.length == 3 ? segments[2] : null,
  );
}

/// The key text of [element] of a list keyed by [key] (sync.md, 25.1).
String keyText(ElementKey key, Map<String, Object?> element) => switch (key) {
  ElementKey.id => (element['id']! as String).toLowerCase(),
  ElementKey.name => element['name']! as String,
};

/// The element of [list] whose key text is [text], or null.
Map<String, Object?>? elementOf(
  ElementKey key,
  List<Object?> list,
  String text,
) => list
    .cast<Map<String, Object?>>()
    .where((e) => keyText(key, e) == text)
    .firstOrNull;

/// Whether the elements of a list keyed by [key] goes to a receiver whose
/// shares leave out the links (shares.md, section 19.1).
bool goesWithoutLinks(
  ElementKey key,
  Map<String, Object?> element, {
  required Set<String> shared,
  required Set<String> ownKeys,
}) =>
    key == ElementKey.id &&
    sharedRelations([element], shared: shared, ownKeys: ownKeys).isNotEmpty;

/// The value of an element part: null for a removal mark, or the element.
///
/// Throws [AxtException] `UNDECODABLE` for bytes that are neither.
Object? decodeElementPart(Schema items, Uint8List bytes) {
  if (bytes.length == 1 && bytes[0] == 0) return null;
  if (bytes.isEmpty || bytes[0] != 2) {
    throw const AxtException(ErrorCode.undecodable, 'no union of an element');
  }
  try {
    return AvroCodec(writer: items).decode(Uint8List.sublistView(bytes, 1));
  } on AvroException catch (e) {
    throw AxtException(ErrorCode.undecodable, e.message);
  }
}

/// The bytes of the element part of [element] under [items]: the removal
/// mark for null.
Uint8List encodeElementPart(Schema items, Object? element) => element == null
    ? Uint8List.fromList([0])
    : Uint8List.fromList([2, ...AvroCodec(writer: items).encode(element)]);

/// The path of the first value of [element], the value of the element part
/// [name] of a list keyed by [key], that breaks a rule of its type or whose
/// key is not the key text of the name; null when it keeps them
/// (shares.md, section 20.1, step 9).
String? elementProblem(
  ElementKey key,
  String name,
  String text,
  Map<String, Object?> element,
) {
  final member = key == ElementKey.id ? 'id' : 'name';
  final problem = key == ElementKey.id
      ? relationsProblem([element], '')
      : extensionsProblem([element], '');
  if (problem != null) return '$name${problem.substring(3)}';
  if (keyText(key, element) != text) return '$name.$member';
  return null;
}
