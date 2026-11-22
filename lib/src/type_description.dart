/// A type as an app gives it: its description, with the schema derived from
/// it (AXT `spec/fields.md`, sections 9 and 10).
library;

import 'dart:convert';

import 'package:avro/avro.dart';

import 'bricks.dart';
import 'record_decoder.dart' show parseTypeSchema;

/// A valid description of a type and the schema derived from it.
final class TypeDescription {
  TypeDescription._(this.datum, this.schemaText)
    : schema = parseTypeSchema(schemaText) as RecordSchema;

  /// The description in its JSON form ([spec/fields.md], section 10.3), as
  /// `jsonDecode` gives it.
  ///
  /// Throws [AxtException] `DESCRIPTION_INVALID` for JSON that is not a
  /// description in that form, or a description that is not valid.
  factory TypeDescription.fromJson(Object? json) =>
      TypeDescription.of(descriptionFromJson(json));

  /// The description [datum], a decoded `axt.Field`.
  ///
  /// Throws [AxtException] `DESCRIPTION_INVALID` for one that is not valid.
  factory TypeDescription.of(Description datum) =>
      TypeDescription._(datum, deriveSchema(datum));

  /// The description, a decoded `axt.Field`.
  final Description datum;

  /// The derived schema as text (section 9.3).
  final String schemaText;

  /// The derived schema, with its logical types left out.
  final RecordSchema schema;

  /// The type's full name.
  String get name => schema.fullName;

  /// The fingerprint of the derived schema.
  int get fingerprint => schema.crc64;

  /// The description in its JSON form.
  Object? toJson() => descriptionToJson(datum);

  /// The entry of the type in `axt.schemas` of a file (section 10.2).
  Map<String, Object?> get fileEntry => {
    'description': toJson(),
    'schema': jsonDecode(schemaText),
  };
}
