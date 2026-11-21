/// Reading a record of a type: its writer schema, the receiver's reader
/// schema and the body (AXT `spec/types.md`, sections 5 and 5.7,
/// `spec/envelope.md`, section 6, and `spec/time.md`, sections 3.1 and 8).
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:avro/avro.dart';

import 'envelope.dart' show axtSchema, withoutLogicalTypes;
import 'errors.dart';
import 'time_values.dart';

/// The deepest record a receiver decodes (types.md, section 5.7).
const int maxDataDepth = 32;

/// The longest field path an error names (metadata.md, section 7.2).
const int maxFieldPathBytes = 1024;

/// Parses a schema text with its logical types left out, so that its values
/// decode to the underlying types; the fingerprint stays that of the text.
///
/// Throws [AxtException] `DOES_NOT_RESOLVE` for a text that is not a schema.
Schema parseTypeSchema(String text) {
  try {
    return Schema.parse(jsonEncode(withoutLogicalTypes(jsonDecode(text))));
  } on FormatException catch (e) {
    throw AxtException(ErrorCode.doesNotResolve, 'not JSON: ${e.message}');
  } on AvroException catch (e) {
    throw AxtException(ErrorCode.doesNotResolve, e.message);
  }
}

/// Throws [AxtException] `DOES_NOT_RESOLVE` when [schema] defines a named
/// type in the namespace `axt` other than a time type with its published
/// Parsing Canonical Form (time.md, section 3.1).
void checkAxtNames(Schema schema) {
  final seen = <String>{};
  void walk(Schema s) {
    switch (s) {
      case NamedSchema(:final fullName) when !seen.add(fullName):
        return;
      case NamedSchema(:final namespace, :final fullName)
          when namespace == 'axt':
        if (!timeTypes.contains(fullName) ||
            s.canonicalForm != axtSchema(fullName).canonicalForm) {
          throw AxtException(
            ErrorCode.doesNotResolve,
            '$fullName is reserved for the published time types',
          );
        }
      case RecordSchema(:final fields):
        for (final field in fields) {
          walk(field.schema);
        }
      case ArraySchema(:final items):
        walk(items);
      case MapSchema(:final values):
        walk(values);
      case UnionSchema(:final branches):
        branches.forEach(walk);
      case PrimitiveSchema() || EnumSchema() || FixedSchema() || NamedSchema():
        break;
    }
  }

  walk(schema);
}

/// Decodes [body], a single-object encoding written with [writer], as
/// [reader], or as [writer] when [reader] is null.
///
/// Throws [AxtException] with `SCHEMA_UNKNOWN` when the body's fingerprint is
/// not the writer schema's, `DOES_NOT_RESOLVE` when the schemas do not
/// resolve, `UNDECODABLE` when the bytes are no value of the writer schema or
/// nest deeper than [maxDataDepth], and `VALUE_INVALID` for a time value that
/// is not valid.
Object? decodeRecord(Schema writer, Schema? reader, Uint8List body) {
  checkAxtNames(writer);
  if (reader != null) {
    checkAxtNames(reader);
    _checkTypeNames(writer, reader);
  }
  final SingleObjectHeader header;
  try {
    header = SingleObjectHeader.parse(body);
  } on DecodeException catch (e) {
    throw AxtException(ErrorCode.undecodable, e.message);
  }
  if (header.fingerprint != writer.crc64) {
    throw const AxtException(
      ErrorCode.schemaUnknown,
      "the body's fingerprint is not the writer schema's",
    );
  }
  final AvroCodec codec;
  try {
    codec = AvroCodec(writer: writer, reader: reader);
  } on ResolutionException catch (e) {
    throw AxtException(ErrorCode.doesNotResolve, '${e.path}: ${e.message}');
  }
  final Object? value;
  try {
    value = codec.decode(header.payload);
  } on AvroException catch (e) {
    throw AxtException(ErrorCode.undecodable, e.message);
  }
  if (_depth(codec.reader, value) > maxDataDepth) {
    throw const AxtException(
      ErrorCode.undecodable,
      'the record nests deeper than $maxDataDepth',
    );
  }
  final invalid = _firstInvalidTime(codec.reader, value, '');
  if (invalid != null) {
    throw AxtException(
      ErrorCode.valueInvalid,
      'the time value at "${invalid.path}" is not valid',
      field: utf8.encode(invalid.path).length > maxFieldPathBytes
          ? null
          : invalid.path,
    );
  }
  return value;
}

/// Throws [AxtException] `DOES_NOT_RESOLVE` unless the full names of the two
/// record schemas match or the writer's is one of the reader's aliases
/// (envelope.md, section 6). Avro itself compares only the unqualified names.
void _checkTypeNames(Schema writer, Schema reader) {
  if (writer is! RecordSchema || reader is! RecordSchema) return;
  // Avro keeps the aliases as full names.
  if (writer.fullName != reader.fullName &&
      !reader.aliases.contains(writer.fullName)) {
    throw AxtException(
      ErrorCode.doesNotResolve,
      '${writer.fullName} is neither ${reader.fullName} nor one of its aliases',
    );
  }
}

/// The branch of [union] that [value] was decoded with.
Schema? _branch(UnionSchema union, Object? value) {
  for (final branch in union.branches) {
    final fits = switch (branch) {
      PrimitiveSchema(type: 'null') => value == null,
      PrimitiveSchema(type: 'boolean') => value is bool,
      PrimitiveSchema(type: 'int' || 'long') => value is int,
      PrimitiveSchema(type: 'float' || 'double') => value is double,
      PrimitiveSchema(type: 'string') || EnumSchema() => value is String,
      PrimitiveSchema(type: 'bytes') || FixedSchema() => value is Uint8List,
      ArraySchema() => value is List<Object?>,
      RecordSchema() || MapSchema() => value is Map<String, Object?>,
      _ => false,
    };
    if (fits) return branch;
  }
  return null;
}

/// The data depth of [value] (types.md, section 5.7).
int _depth(Schema schema, Object? value) => switch (schema) {
  RecordSchema(:final fields) =>
    1 +
        _max([
          for (final field in fields)
            _depth(field.schema, (value! as Map<String, Object?>)[field.name]),
        ]),
  ArraySchema(:final items) =>
    1 + _max([for (final item in value! as List<Object?>) _depth(items, item)]),
  MapSchema(:final values) =>
    1 +
        _max([
          for (final v in (value! as Map<String, Object?>).values)
            _depth(values, v),
        ]),
  UnionSchema() => switch (_branch(schema, value)) {
    final Schema branch => _depth(branch, value),
    null => 0,
  },
  _ => 0,
};

int _max(List<int> depths) => depths.fold(0, (a, b) => a > b ? a : b);

/// The first time value that is not valid, in the order of the encoding.
({String path})? _firstInvalidTime(Schema schema, Object? value, String path) {
  switch (schema) {
    case RecordSchema(:final fullName, :final fields):
      final record = value! as Map<String, Object?>;
      if (timeTypes.contains(fullName)) {
        return isValidTimeValue(fullName, record) ? null : (path: path);
      }
      for (final field in fields) {
        final found = _firstInvalidTime(
          field.schema,
          record[field.name],
          path.isEmpty ? field.name : '$path.${field.name}',
        );
        if (found != null) return found;
      }
    case ArraySchema(:final items):
      final list = value! as List<Object?>;
      for (var i = 0; i < list.length; i++) {
        final found = _firstInvalidTime(items, list[i], '$path[$i]');
        if (found != null) return found;
      }
    case MapSchema(:final values):
      for (final entry in (value! as Map<String, Object?>).entries) {
        final found = _firstInvalidTime(
          values,
          entry.value,
          '$path[${jsonEncode(entry.key)}]',
        );
        if (found != null) return found;
      }
    case UnionSchema():
      final branch = _branch(schema, value);
      if (branch != null) return _firstInvalidTime(branch, value, path);
    default:
      break;
  }
  return null;
}
