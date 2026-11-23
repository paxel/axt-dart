/// Typed fields as Avro bricks: descriptions, their validity, the schema
/// derived from them, what a receiver shows of them, and the checks of their
/// values (AXT `spec/fields.md`; `spec/metadata.md`, sections 4 to 7).
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:avro/avro.dart';

import 'envelope.dart' show axtRawSchema, axtSchemaText;
import 'errors.dart';
import 'iregexp.dart';
import 'limits.dart';
import 'links.dart';
import 'manifest.dart' show isLanguageTag, lookup;
import 'record_decoder.dart' show decodeRecord, fieldPath, parseTypeSchema;
import 'time_values.dart';

/// A description: the decoded datum of `axt.Field`, unions as [Branch].
typedef Description = Map<String, Object?>;

final AvroCodec _fieldCodec = AvroCodec(
  writer: axtRawSchema('axt.Field'),
  decodeBranches: true,
);

/// Decodes a description from its Avro encoding; throws [AxtException]
/// `UNDECODABLE` for bytes that are not a datum of `axt.Field`.
Description decodeDescription(Uint8List bytes) {
  try {
    return _fieldCodec.decode(bytes)! as Description;
  } on AvroException catch (e) {
    throw AxtException(ErrorCode.undecodable, e.message);
  }
}

/// Encodes a description as a datum of `axt.Field`.
Uint8List encodeDescription(Description description) =>
    _fieldCodec.encode(description);

/// A description from its JSON form (fields.md, section 10.3): the branch of
/// each union as an object of one member named by its full name, bytes as
/// lower-case hexadecimal.
///
/// Throws [AxtException] `DESCRIPTION_INVALID` for JSON that is not a datum
/// of `axt.Field` in that form.
Description descriptionFromJson(Object? json) {
  try {
    final description =
        _fromJson(axtRawSchema('axt.Field'), json)! as Description;
    // The encoder checks every value against its schema.
    encodeDescription(description);
    return description;
  } on _NotTheForm catch (e) {
    throw AxtException(ErrorCode.descriptionInvalid, e.message);
  } on AvroException catch (e) {
    throw AxtException(ErrorCode.descriptionInvalid, e.message);
  } on TypeError catch (e) {
    throw AxtException(ErrorCode.descriptionInvalid, '$e');
  }
}

final class _NotTheForm implements Exception {
  const _NotTheForm(this.message);
  final String message;
}

final RegExp _lowerHex = RegExp(r'^([0-9a-f]{2})*$');

/// The datum of [json] for [schema]; a cast that fails throws a [TypeError].
Object? _fromJson(Schema schema, Object? json) => switch (schema) {
  RecordSchema(:final fields) => _record(
    fields,
    json! as Map<Object?, Object?>,
  ),
  ArraySchema(:final items) => [
    for (final v in json! as List) _fromJson(items, v),
  ],
  MapSchema(:final values) => <String, Object?>{
    for (final e in (json! as Map).entries)
      e.key as String: _fromJson(values, e.value),
  },
  UnionSchema() when json == null => null,
  // A union of null and one unnamed type: the value as it is.
  UnionSchema(:final branches) when branches.length == 2 => _fromJson(
    branches.last,
    json,
  ),
  UnionSchema(:final branches) => _branch(
    branches,
    json! as Map<Object?, Object?>,
  ),
  PrimitiveSchema(type: 'bytes') => _unhex(json! as String),
  PrimitiveSchema(type: 'double') => (json! as num).toDouble(),
  _ => json,
};

Map<String, Object?> _record(List<Field> fields, Map<Object?, Object?> json) =>
    {
      for (final f in fields)
        f.name: json.containsKey(f.name)
            ? _fromJson(f.schema, json[f.name])
            : f.hasDefault
            ? f.defaultValue
            : throw _NotTheForm('no member ${f.name}'),
    };

Uint8List _unhex(String text) {
  if (!_lowerHex.hasMatch(text)) throw const _NotTheForm('not hexadecimal');
  return Uint8List.fromList([
    for (var i = 0; i < text.length; i += 2)
      int.parse(text.substring(i, i + 2), radix: 16),
  ]);
}

/// The branch of a brick: an object of one member, named by its full name.
Branch _branch(List<Schema> branches, Map<Object?, Object?> json) {
  if (json.length != 1) throw const _NotTheForm('not one brick');
  final MapEntry(:key, :value) = json.entries.single;
  final brick = branches
      .whereType<NamedSchema>()
      .where((b) => b.fullName == key)
      .firstOrNull;
  if (brick == null) throw _NotTheForm('no brick $key');
  return Branch(key as String, _fromJson(brick, value));
}

/// [description] in its JSON form (fields.md, section 10.3).
Object? descriptionToJson(Description description) => _toJson(description);

Object? _toJson(Object? value) => switch (value) {
  Branch(:final name, :final value) => <String, Object?>{name: _toJson(value)},
  Uint8List() => [
    for (final b in value) b.toRadixString(16).padLeft(2, '0'),
  ].join(),
  Map() => <String, Object?>{
    for (final e in value.entries) e.key as String: _toJson(e.value),
  },
  List() => <Object?>[for (final v in value) _toJson(v)],
  _ => value,
};

AxtException _invalid(String path, String why) =>
    AxtException(ErrorCode.descriptionInvalid, '$path: $why', field: path);

int _utf8(String text) => utf8.encode(text).length;

bool _oneLine(String text, int max) {
  if (_utf8(text) > max) return false;
  for (final r in text.runes) {
    if (r < 0x20 || (r >= 0x7f && r <= 0x9f) || r == 0x2028 || r == 0x2029) {
      return false;
    }
  }
  return true;
}

final RegExp _snake = RegExp(r'^[a-z][a-z0-9]*(_[a-z0-9]+)*$');
final RegExp _upperCamel = RegExp(r'^[A-Z][A-Za-z0-9]*$');
final RegExp _upperSnake = RegExp(r'^[A-Z][A-Z0-9]*(_[A-Z0-9]+)*$');
final RegExp _groupKey = RegExp(r'^[a-z][a-z0-9]*(_[a-z0-9]+)*$');
final RegExp _avroName = RegExp(r'^[A-Za-z_][A-Za-z0-9_]*$');

const Set<int> _whiteSpace = {
  0x20, 0xa0, 0x1680, 0x2028, 0x2029, 0x202f, 0x205f, 0x3000, //
};

bool _emoji(String emoji) {
  final runes = emoji.runes.toList();
  if (runes.isEmpty || runes.length > limit('metadata.emoji')) return false;
  for (var i = 0; i < runes.length; i++) {
    final r = runes[i];
    if (r < 0x20 ||
        (r >= 0x7f && r <= 0x9f) ||
        _whiteSpace.contains(r) ||
        (r >= 0x2000 && r <= 0x200a)) {
      return false;
    }
    if (r < 0x80) {
      final keycap =
          i == 0 &&
          (r == 0x23 || r == 0x2a || (r >= 0x30 && r <= 0x39)) &&
          ((runes.length == 2 && runes[1] == 0x20e3) ||
              (runes.length == 3 && runes[1] == 0xfe0f && runes[2] == 0x20e3));
      if (!keycap) return false;
    }
  }
  return true;
}

void _texts(Map<String, Object?> texts, String path) {
  final label = texts['label']! as String;
  final help = texts['help']! as String;
  if (!_oneLine(label, limit('metadata.label'))) {
    throw _invalid('$path.label', 'not one line');
  }
  if (!_oneLine(help, limit('metadata.help'))) {
    throw _invalid('$path.help', 'not one line');
  }
  for (final (name, english, max) in [
    ('label_translations', label, limit('metadata.label')),
    ('help_translations', help, limit('metadata.help')),
  ]) {
    final map = (texts[name]! as Map<String, Object?>).cast<String, String>();
    if (map.isEmpty) continue;
    if (english.isEmpty) {
      throw _invalid('$path.$name', 'translations without an English text');
    }
    final seen = <String>{};
    if (map.length > limit('metadata.translations')) {
      throw _invalid('$path.$name', 'too many');
    }
    for (final MapEntry(:key, :value) in map.entries) {
      if (key.length > limit('manifest.language_tag') ||
          !isLanguageTag(key) ||
          key.toLowerCase() == 'en' ||
          !seen.add(key.toLowerCase()) ||
          value.isEmpty ||
          !_oneLine(value, max)) {
        throw _invalid('$path.$name', 'a key or a text breaks its rules');
      }
    }
  }
  final emoji = texts['emoji']! as String;
  if (emoji.isNotEmpty && !_emoji(emoji)) {
    throw _invalid('$path.emoji', 'not an emoji');
  }
}

const Set<String> _semantic = {
  'axt.MarkdownField',
  'axt.EmailField',
  'axt.PhoneField',
  'axt.UrlField',
  'axt.UriField', //
  'axt.ColourField',
  'axt.IbanField',
  'axt.BicField',
  'axt.CountryField',
  'axt.LanguageField', //
  'axt.CurrencyField', 'axt.MediaTypeField', 'axt.UcumField', //
};

const Map<String, String> _formats = {
  'axt.MarkdownField': 'markdown',
  'axt.EmailField': 'email',
  'axt.PhoneField': 'phone', //
  'axt.UrlField': 'url', 'axt.UriField': 'uri', 'axt.ColourField': 'colour', //
  'axt.IbanField': 'iban',
  'axt.BicField': 'bic',
  'axt.CountryField': 'country', //
  'axt.LanguageField': 'language', 'axt.CurrencyField': 'currency', //
  'axt.MediaTypeField': 'media-type', 'axt.UcumField': 'ucum', //
};

bool _isText(String brick) =>
    brick == 'axt.StringField' || _semantic.contains(brick);

/// The full names that a description may not give an object or an enum.
final Set<String> _reserved = {
  'axt.Date', 'axt.Time', 'axt.DateTime', 'axt.Duration', //
  'axt.Relation',
  'axt.RelationRecordTarget',
  'axt.RelationRecordTargetSender', //
  'axt.RelationOutsideTarget', //
};

/// Checks that [description] is valid (fields.md, sections 3 to 6 and 9.1).
///
/// Throws [AxtException] `DESCRIPTION_INVALID`, whose `field` names the
/// member that breaks a rule.
void validateDescription(Description description) {
  final kind = description['kind']! as Branch;
  if (kind.name != 'axt.ObjectField') {
    throw _invalid('kind', 'the root is not an object');
  }
  if (description['required'] == true ||
      description['order'] != null ||
      description['group'] != '' ||
      description['sensitive'] == true ||
      description['advanced'] == true) {
    throw _invalid(
      '',
      'a root with required, an order, a group, sensitive or advanced',
    );
  }
  if ((description['doc']! as String).trim().isEmpty) {
    throw _invalid('doc', 'empty');
  }
  _texts(description['texts']! as Map<String, Object?>, 'texts');
  final root = kind.value! as Map<String, Object?>;
  final name = root['name']! as String;
  final parts = name.split('.');
  if (parts.length < 2 ||
      parts.any((p) => !_avroName.hasMatch(p)) ||
      !_upperCamel.hasMatch(parts.last)) {
    throw _invalid('kind.name', "the root's name has no namespace");
  }
  final version = root['version'] as int?;
  if (version == null || version < 1) {
    throw _invalid('kind.version', 'no version of at least 1');
  }
  final namespace = parts.sublist(0, parts.length - 1).join('.');
  final names = <String>{name};
  _object(root, 'kind', namespace, names, depth: 1, isRoot: true);
  final size = encodeDescription(description).length;
  final schema = canonicalJson(deriveSchemaJson(description));
  if (size > limit('envelope.schema') ||
      _utf8(schema) > limit('envelope.schema')) {
    throw _invalid(
      '',
      'a description or its derived schema of more than 256 KiB',
    );
  }
  if (_jsonDepth(jsonDecode(schema)) > limit('envelope.schema_depth')) {
    throw _invalid('', 'a derived schema nested deeper than 64');
  }
}

int _jsonDepth(Object? json) => switch (json) {
  Map() => 1 + json.values.fold<int>(0, (m, v) => _maxInt(m, _jsonDepth(v))),
  List() => 1 + json.fold<int>(0, (m, v) => _maxInt(m, _jsonDepth(v))),
  _ => 0,
};

int _maxInt(int a, int b) => a > b ? a : b;

void _object(
  Map<String, Object?> object,
  String path,
  String namespace,
  Set<String> names, {
  required int depth,
  required bool isRoot,
}) {
  if (!isRoot) {
    final name = object['name']! as String;
    if (name.contains('.')) {
      throw _invalid('$path.name', 'a nested name with a namespace');
    }
    if (!_upperCamel.hasMatch(name)) {
      throw _invalid('$path.name', 'not an Avro name in UpperCamelCase');
    }
    final full = '$namespace.$name';
    if (!names.add(full) || _reserved.contains(full)) {
      throw _invalid(
        '$path.name',
        'a full name that another object or enum has',
      );
    }
    if (object['version'] != null) {
      throw _invalid('$path.version', 'a version in a nested object');
    }
  }
  final fields = (object['fields']! as List<Object?>).cast<Description>();
  if (fields.isEmpty) throw _invalid('$path.fields', 'no field');
  final groups = (object['groups']! as List<Object?>)
      .cast<Map<String, Object?>>();
  final keys = <String>{};
  for (var i = 0; i < groups.length; i++) {
    final key = groups[i]['key']! as String;
    if (!_groupKey.hasMatch(key) ||
        _utf8(key) > limit('metadata.group_key') ||
        !keys.add(key)) {
      throw _invalid(
        '$path.groups[$i].key',
        'not a group key, or a second time',
      );
    }
    _texts(
      groups[i]['texts']! as Map<String, Object?>,
      '$path.groups[$i].texts',
    );
  }
  final fieldNames = <String>{};
  final used = <String>{};
  for (var i = 0; i < fields.length; i++) {
    final field = fields[i];
    final fieldPath = '$path.fields[$i]';
    final name = field['name']! as String;
    if (!_snake.hasMatch(name)) {
      throw _invalid('$fieldPath.name', 'not a field name in snake_case');
    }
    if (!fieldNames.add(name)) {
      throw _invalid('$fieldPath.name', 'a second field of this name');
    }
    final group = field['group']! as String;
    if (group.isNotEmpty) {
      if (!keys.contains(group)) {
        throw _invalid('$fieldPath.group', "not a key of the object's groups");
      }
      used.add(group);
    }
    _field(field, fieldPath, namespace, names, depth: depth + 1);
  }
  for (var i = 0; i < groups.length; i++) {
    if (!used.contains(groups[i]['key'])) {
      throw _invalid('$path.groups[$i]', 'a group that no field names');
    }
  }
  final title = object['title']! as String;
  if (title.isNotEmpty &&
      !fields.any(
        (f) => f['name'] == title && _isText((f['kind']! as Branch).name),
      )) {
    throw _invalid(
      '$path.title',
      'not the name of a field of text of the object',
    );
  }
}

void _field(
  Description field,
  String path,
  String namespace,
  Set<String> names, {
  required int depth,
}) {
  if (depth > limit('fields.depth')) {
    throw _invalid('', 'typed fields nested deeper than 64');
  }
  if ((field['doc']! as String).trim().isEmpty) {
    throw _invalid('$path.doc', 'empty');
  }
  _texts(field['texts']! as Map<String, Object?>, '$path.texts');
  final kind = field['kind']! as Branch;
  final brick = kind.name;
  final value = kind.value! as Map<String, Object?>;
  final k = '$path.kind';
  switch (brick) {
    case final text when _isText(text):
      _lengths(value, k);
      final pattern = value['pattern'] as String?;
      if (pattern != null && _compile(pattern) == null) {
        throw _invalid('$k.pattern', 'not an I-Regexp within its limits');
      }
      final preferred = value['preferred_length'] as int?;
      final max = value['max_length'] as int?;
      if (preferred != null &&
          (preferred < 1 || (max != null && preferred > max))) {
        throw _invalid('$k.preferred_length', 'below 1 or above max_length');
      }
      _placeholder(value, k);
      final example = value['example']! as String;
      if (_utf8(example) > limit('metadata.example') ||
          example.runes.any(
            (r) => (r < 0x20 && r != 0x0a) || (r >= 0x7f && r <= 0x9f),
          )) {
        throw _invalid(
          '$k.example',
          'more than 1,024 bytes, or a control character other than LF',
        );
      }
      if (example.isNotEmpty && checkFieldValue(field, example, '') != null) {
        throw _invalid('$k.example', 'breaks a check of the field');
      }
      final def = value['default'];
      if (def != null && checkFieldValue(field, def, '') != null) {
        throw _invalid('$k.default', 'breaks a check of the field');
      }
    case 'axt.IntField' || 'axt.LongField' || 'axt.DoubleField':
      final min = value['min'] as num?;
      final max = value['max'] as num?;
      final def = value['default'] as num?;
      if (brick == 'axt.DoubleField') {
        if (min != null && !min.isFinite) {
          throw _invalid('$k.min', 'not a finite number');
        }
        if (max != null && !max.isFinite) {
          throw _invalid('$k.max', 'not a finite number');
        }
      }
      if (min != null && max != null && min > max) {
        throw _invalid('$k.min', 'larger than max');
      }
      if (def != null &&
          (!def.isFinite ||
              (brick == 'axt.LongField' &&
                  def.abs() > limit('fields.long_default')))) {
        throw _invalid(
          '$k.default',
          'not a finite number, or a long above 2^53 in magnitude',
        );
      }
      if (def != null && checkFieldValue(field, def, '') != null) {
        throw _invalid('$k.default', 'breaks a check of the field');
      }
      final unit = value['unit']! as String;
      if (unit.isNotEmpty && !_ucum(unit)) {
        throw _invalid('$k.unit', 'not a UCUM code');
      }
      _placeholder(value, k);
      final example = value['example']! as String;
      if (_utf8(example) > limit('metadata.example') ||
          example.runes.any(
            (r) => (r < 0x20 && r != 0x0a) || (r >= 0x7f && r <= 0x9f),
          )) {
        throw _invalid(
          '$k.example',
          'more than 1,024 bytes, or a control character other than LF',
        );
      }
    case 'axt.BytesField':
      _lengths(value, k);
      final def = value['default'];
      if (def != null && checkFieldValue(field, def, '') != null) {
        throw _invalid('$k.default', 'breaks a check of the field');
      }
    case 'axt.EnumField':
      final name = value['name']! as String;
      if (!_upperCamel.hasMatch(name)) {
        throw _invalid('$k.name', 'not an Avro name in UpperCamelCase');
      }
      if (!names.add('$namespace.$name') ||
          _reserved.contains('$namespace.$name')) {
        throw _invalid(
          '$k.name',
          'a full name that another object or enum has',
        );
      }
      final symbols = (value['symbols']! as List<Object?>)
          .cast<Map<String, Object?>>();
      if (symbols.isEmpty) throw _invalid('$k.symbols', 'no symbol');
      final seen = <String>{};
      for (var i = 0; i < symbols.length; i++) {
        final symbol = symbols[i]['symbol']! as String;
        if (!_upperSnake.hasMatch(symbol) || !seen.add(symbol)) {
          throw _invalid(
            '$k.symbols[$i].symbol',
            'not a symbol in UPPER_SNAKE_CASE, or a second time',
          );
        }
        _texts(
          symbols[i]['texts']! as Map<String, Object?>,
          '$k.symbols[$i].texts',
        );
      }
      if (!seen.contains(value['fallback'])) {
        throw _invalid('$k.fallback', 'not one of the symbols');
      }
      final def = value['default'];
      if (def != null && !seen.contains(def)) {
        throw _invalid('$k.default', 'not one of the symbols');
      }
    case 'axt.ListField' || 'axt.MapField':
      final member = brick == 'axt.ListField' ? 'items' : 'values';
      final item = value[member]! as Description;
      if (item['name'] != field['name']) {
        throw _invalid('$k.$member.name', 'not the name of its list or map');
      }
      if (item['order'] != null ||
          item['group'] != '' ||
          item['sensitive'] == true ||
          item['advanced'] == true) {
        throw _invalid(
          '$k.$member',
          'an order, group, sensitive or advanced of its own',
        );
      }
      _field(item, '$k.$member', namespace, names, depth: depth + 1);
    case 'axt.ObjectField':
      _object(value, k, namespace, names, depth: depth, isRoot: false);
    default:
      break;
  }
}

void _lengths(Map<String, Object?> value, String k) {
  final min = value['min_length'] as int?;
  final max = value['max_length'] as int?;
  if (min != null && min < 0) throw _invalid('$k.min_length', 'below 0');
  if (max != null && max < 0) throw _invalid('$k.max_length', 'below 0');
  if (min != null && max != null && min > max) {
    throw _invalid('$k.min_length', 'larger than max_length');
  }
}

void _placeholder(Map<String, Object?> value, String k) {
  if (!_oneLine(
    value['placeholder']! as String,
    limit('metadata.placeholder'),
  )) {
    throw _invalid('$k.placeholder', 'not one line of at most 256 bytes');
  }
}

final Map<String, IRegexp?> _patterns = {};

IRegexp? _compile(String pattern) => _patterns.putIfAbsent(
  pattern,
  () => compileIRegexp(
    pattern,
    maxBytes: limit('metadata.pattern'),
    maxQuantifier: limit('metadata.pattern_quantifier'),
  ),
);

bool _ucum(String code) =>
    code.isNotEmpty && code.codeUnits.every((c) => c >= 0x21 && c <= 0x7e);

// ---------------------------------------------------------------- formats

final RegExp _atext = RegExp(
  r"^[A-Za-z0-9!#$%&'*+/=?^_`{|}~\u0080-\u{10FFFF}-]+$",
  unicode: true,
);

bool _dotAtom(String text) =>
    text.isNotEmpty && text.split('.').every(_atext.hasMatch);

bool _email(String v) {
  final at = v.lastIndexOf('@');
  if (at <= 0 || at == v.length - 1) return false;
  final local = v.substring(0, at);
  final domain = v.substring(at + 1);
  return _dotAtom(local) &&
      _dotAtom(domain) &&
      _utf8(local) <= 64 &&
      _utf8(v) <= 254;
}

const String _unreserved = r"A-Za-z0-9\-._~";
const String _subDelims = r"!$&'()*+,;=";
final String _pchar = "(?:[$_unreserved$_subDelims:@]|%[0-9A-Fa-f]{2})";
final RegExp _uri = RegExp(
  '^([A-Za-z][A-Za-z0-9+.\\-]*):'
  '(?://((?:(?:[$_unreserved$_subDelims:]|%[0-9A-Fa-f]{2})*@)?'
  '(\\[[0-9A-Fa-f:.vV$_unreserved$_subDelims]*\\]|(?:[$_unreserved$_subDelims]|%[0-9A-Fa-f]{2})*)'
  '(?::[0-9]*)?)'
  '(?:/$_pchar*)*'
  '|/(?:$_pchar+(?:/$_pchar*)*)?'
  '|$_pchar+(?:/$_pchar*)*'
  '|)'
  '(?:\\?(?:$_pchar|[/?])*)?'
  '(?:#(?:$_pchar|[/?])*)?\$',
);

bool _url(String v) {
  final m = _uri.firstMatch(v);
  if (m == null) return false;
  final scheme = m.group(1)!.toLowerCase();
  final host = m.group(3);
  return (scheme == 'http' || scheme == 'https') &&
      host != null &&
      host.isNotEmpty;
}

bool _iban(String v) {
  if (!RegExp(r'^[A-Z]{2}[0-9]{2}[A-Z0-9]{11,30}$').hasMatch(v)) return false;
  final moved = v.substring(4) + v.substring(0, 4);
  var rest = 0;
  for (final c in moved.codeUnits) {
    final digits = c >= 0x41 ? '${c - 55}' : String.fromCharCode(c);
    for (final d in digits.codeUnits) {
      rest = (rest * 10 + d - 0x30) % 97;
    }
  }
  return rest == 1;
}

final RegExp _restricted = RegExp(r"^[A-Za-z0-9][A-Za-z0-9!#$&\-^_.+]{0,126}$");

bool _format(String format, String v) => switch (format) {
  'markdown' => true,
  'email' => _email(v),
  'phone' => RegExp(r'^\+[1-9][0-9]{1,14}$').hasMatch(v),
  'url' => _url(v),
  'uri' => v.codeUnits.every((c) => c < 0x80) && _uri.hasMatch(v),
  'colour' => RegExp(r'^#[0-9A-Fa-f]{6}$').hasMatch(v),
  'iban' => _iban(v),
  'bic' => RegExp(r'^[A-Z]{6}[A-Z0-9]{2}([A-Z0-9]{3})?$').hasMatch(v),
  'country' => RegExp(r'^[A-Z]{2}$').hasMatch(v),
  'language' => v.length <= 35 && isLanguageTag(v),
  'currency' => RegExp(r'^[A-Z]{3}$').hasMatch(v),
  'media-type' => () {
    final parts = v.split('/');
    return parts.length == 2 && parts.every(_restricted.hasMatch);
  }(),
  _ => _ucum(v),
};

// ---------------------------------------------------------------- checks

/// The path of the first value of [field] in [value] that breaks a check or
/// a rule of time values, relations and extensions, in the order of the
/// encoding, or null (fields.md, section 7).
String? checkFieldValue(Description field, Object? value, String path) {
  final kind = field['kind']! as Branch;
  final brick = kind.name;
  final b = kind.value! as Map<String, Object?>;
  final required = field['required'] == true;
  if (required &&
      (value == null ||
          (value is String && value.isEmpty) ||
          (value is Uint8List && value.isEmpty) ||
          (value is List && value.isEmpty) ||
          (value is Map && value.isEmpty && brick != 'axt.ObjectField'))) {
    return path;
  }
  if (value == null) return null;
  switch (brick) {
    case final text when _isText(text):
      final text = value as String;
      final format = _formats[brick];
      if (format != null && text.isNotEmpty && !_format(format, text)) {
        return path;
      }
      final pattern = b['pattern'] as String?;
      if (pattern != null &&
          text.isNotEmpty &&
          !(_compile(pattern)?.hasMatch(text) ?? true)) {
        return path;
      }
      final length = text.runes.length;
      if (b['min_length'] != null && length < (b['min_length']! as int)) {
        return path;
      }
      if (b['max_length'] != null && length > (b['max_length']! as int)) {
        return path;
      }
    case 'axt.BytesField':
      final length = (value as Uint8List).length;
      if (b['min_length'] != null && length < (b['min_length']! as int)) {
        return path;
      }
      if (b['max_length'] != null && length > (b['max_length']! as int)) {
        return path;
      }
    case 'axt.IntField' || 'axt.LongField' || 'axt.DoubleField':
      final n = value as num;
      final min = b['min'] as num?;
      final max = b['max'] as num?;
      if (min != null && (n.isNaN || n < min)) return path;
      if (max != null && (n.isNaN || n > max)) return path;
    case 'axt.ListField':
      final item = b['items']! as Description;
      final list = value as List<Object?>;
      for (var i = 0; i < list.length; i++) {
        final found = checkFieldValue(item, list[i], '$path[$i]');
        if (found != null) return found;
      }
    case 'axt.MapField':
      final item = b['values']! as Description;
      for (final e in (value as Map<String, Object?>).entries) {
        final found = checkFieldValue(
          item,
          e.value,
          '$path[${jsonEncode(e.key)}]',
        );
        if (found != null) return found;
      }
    case 'axt.DateField' ||
        'axt.TimeField' ||
        'axt.DateTimeField' ||
        'axt.DurationField':
      final type = 'axt.${brick.substring(4, brick.length - 5)}';
      if (!isValidTimeValue(type, value as Map<String, Object?>)) return path;
    case 'axt.RelationField':
      return relationsProblem(value as List<Object?>, path);
    case 'axt.ExtensionField':
      return extensionsProblem(value as List<Object?>, path);
    case 'axt.ObjectField':
      final record = value as Map<String, Object?>;
      for (final f in (b['fields']! as List<Object?>).cast<Description>()) {
        final name = f['name']! as String;
        final found = checkFieldValue(
          f,
          record[name],
          path.isEmpty ? name : '$path.$name',
        );
        if (found != null) return found;
      }
    default:
      break;
  }
  return null;
}

// ---------------------------------------------------------------- derivation

/// The schema derived from [description] as JSON (fields.md, section 9.2).
Map<String, Object?> deriveSchemaJson(Description description) {
  final defined = <String>{};
  final root = (description['kind']! as Branch).value! as Map<String, Object?>;
  final name = root['name']! as String;
  final cut = name.lastIndexOf('.');
  defined.add(name);
  return {
    'type': 'record',
    'name': name.substring(cut + 1),
    'namespace': name.substring(0, cut),
    'doc': description['doc'],
    'axt.version': root['version'],
    'fields': [
      for (final f in (root['fields']! as List<Object?>).cast<Description>())
        _derivedField(f, defined),
    ],
  };
}

Map<String, Object?> _derivedField(Description field, Set<String> defined) {
  final kind = field['kind']! as Branch;
  final brick = kind.name;
  final b = kind.value! as Map<String, Object?>;
  final type = _derivedType(field, defined);
  final list =
      brick == 'axt.ListField' ||
      brick == 'axt.RelationField' ||
      brick == 'axt.ExtensionField';
  final out = <String, Object?>{'name': field['name'], 'doc': field['doc']};
  final hasDefault = b.containsKey('default') && b['default'] != null;
  if (list) {
    out['type'] = type;
    out['default'] = <Object?>[];
  } else if (brick == 'axt.MapField') {
    out['type'] = type;
    out['default'] = <String, Object?>{};
  } else if (hasDefault) {
    out['type'] = type;
    final def = b['default'];
    out['default'] = def is Uint8List ? String.fromCharCodes(def) : def;
  } else if (field['required'] == true) {
    out['type'] = type;
  } else {
    out['type'] = ['null', type];
    out['default'] = null;
  }
  return out;
}

Object? _derivedType(Description field, Set<String> defined) {
  final kind = field['kind']! as Branch;
  final brick = kind.name;
  final b = kind.value! as Map<String, Object?>;
  Object? itemType(Description item) {
    final t = _derivedType(item, defined);
    final itemBrick = (item['kind']! as Branch).name;
    final nested =
        itemBrick == 'axt.ListField' ||
        itemBrick == 'axt.MapField' ||
        itemBrick == 'axt.RelationField' ||
        itemBrick == 'axt.ExtensionField';
    final itemB = (item['kind']! as Branch).value! as Map<String, Object?>;
    if (nested ||
        item['required'] == true ||
        (itemB.containsKey('default') && itemB['default'] != null)) {
      return t;
    }
    return ['null', t];
  }

  switch (brick) {
    case 'axt.IntField':
      return 'int';
    case 'axt.LongField':
      return 'long';
    case 'axt.DoubleField':
      return 'double';
    case 'axt.BooleanField':
      return 'boolean';
    case 'axt.BytesField':
      return 'bytes';
    case 'axt.EnumField':
      return {
        'type': 'enum',
        'name': b['name'],
        'doc': field['doc'],
        'symbols': [
          for (final s
              in (b['symbols']! as List<Object?>).cast<Map<String, Object?>>())
            s['symbol'],
        ],
        'default': b['fallback'],
      };
    case 'axt.ListField':
      return {'type': 'array', 'items': itemType(b['items']! as Description)};
    case 'axt.MapField':
      return {'type': 'map', 'values': itemType(b['values']! as Description)};
    case 'axt.ObjectField':
      return {
        'type': 'record',
        'name': b['name'],
        'doc': field['doc'],
        'fields': [
          for (final f in (b['fields']! as List<Object?>).cast<Description>())
            _derivedField(f, defined),
        ],
      };
    case 'axt.DateField':
      return _published('axt.Date', defined);
    case 'axt.TimeField':
      return _published('axt.Time', defined);
    case 'axt.DateTimeField':
      return _published('axt.DateTime', defined);
    case 'axt.DurationField':
      return _published('axt.Duration', defined);
    case 'axt.RelationField':
      return {'type': 'array', 'items': _published('axt.Relation', defined)};
    case 'axt.ExtensionField':
      return {'type': 'array', 'items': _published('axt.Extension', defined)};
    default:
      return 'string';
  }
}

/// A published schema defined in place: its JSON, with every named type that
/// is already defined replaced by its full name, or its full name.
Object? _published(String fullName, Set<String> defined) {
  if (defined.contains(fullName)) return fullName;
  Object? walk(Object? json, String namespace) {
    if (json is Map<String, Object?>) {
      final type = json['type'];
      if (type == 'record' || type == 'enum' || type == 'fixed') {
        final ns = (json['namespace'] as String?) ?? namespace;
        final name = json['name']! as String;
        final full = name.contains('.') ? name : '$ns.$name';
        if (defined.contains(full)) return full;
        defined.add(full);
        return {
          for (final e in json.entries)
            e.key: e.key == 'fields'
                ? [
                    for (final f
                        in (e.value! as List<Object?>)
                            .cast<Map<String, Object?>>())
                      {
                        for (final fe in f.entries)
                          fe.key: fe.key == 'type'
                              ? walk(fe.value, ns)
                              : fe.value,
                      },
                  ]
                : e.value,
        };
      }
      // The published schemas hold no named type inside an array or a map.
      return json;
    }
    if (json is List) return [for (final b in json) walk(b, namespace)];
    if (json is String &&
        !const {
          'null',
          'boolean',
          'int',
          'long',
          'float',
          'double',
          'bytes',
          'string',
        }.contains(json)) {
      return json.contains('.') ? json : '$namespace.$json';
    }
    return json;
  }

  return walk(jsonDecode(axtSchemaText(fullName)), 'axt');
}

/// JSON in the canonical form of RFC 8785.
String canonicalJson(Object? json) {
  final out = StringBuffer();
  void write(Object? v) {
    switch (v) {
      case null:
        out.write('null');
      case bool():
        out.write(v);
      case int():
        out.write(v);
      case double():
        out.write(_number(v));
      case String():
        out.write(_string(v));
      case List():
        out.write('[');
        for (var i = 0; i < v.length; i++) {
          if (i > 0) out.write(',');
          write(v[i]);
        }
        out.write(']');
      case Map():
        final keys = v.keys.cast<String>().toList()..sort();
        out.write('{');
        for (var i = 0; i < keys.length; i++) {
          if (i > 0) out.write(',');
          out
            ..write(_string(keys[i]))
            ..write(':');
          write(v[keys[i]]);
        }
        out.write('}');
      default:
        throw ArgumentError.value(v, 'json');
    }
  }

  write(json);
  return out.toString();
}

/// [v] as ECMAScript writes a number (ECMA-262, Number::toString), from
/// the shortest digits that Dart gives.
String _number(double v) {
  if (v == 0) return '0';
  if (v < 0) return '-${_number(-v)}';
  // Dart writes the shortest digits, either as d.ddd or with an exponent.
  final text = v.toString();
  final cut = text.indexOf('e');
  final mantissa = cut < 0 ? text : text.substring(0, cut);
  final exponent = cut < 0 ? 0 : int.parse(text.substring(cut + 1));
  final point = mantissa.indexOf('.');
  final whole = point < 0 ? mantissa : mantissa.substring(0, point);
  final fraction = point < 0 ? '' : mantissa.substring(point + 1);
  var digits = whole + fraction;
  var n = whole.length + exponent;
  final lead = digits.length - digits.replaceFirst(RegExp('^0+'), '').length;
  digits = digits.substring(lead).replaceFirst(RegExp(r'0+$'), '');
  n -= lead;
  final k = digits.length;
  if (k <= n && n <= 21) return digits + '0' * (n - k);
  if (0 < n && n <= 21) {
    return '${digits.substring(0, n)}.${digits.substring(n)}';
  }
  if (-6 < n && n <= 0) return '0.${'0' * -n}$digits';
  final e = n - 1;
  final sign = e < 0 ? '-' : '+';
  final m = k == 1 ? digits : '${digits[0]}.${digits.substring(1)}';
  return '${m}e$sign${e.abs()}';
}

String _string(String s) {
  final out = StringBuffer('"');
  for (final c in s.codeUnits) {
    switch (c) {
      case 0x22:
        out.write(r'\"');
      case 0x5c:
        out.write(r'\\');
      case 0x08:
        out.write(r'\b');
      case 0x0c:
        out.write(r'\f');
      case 0x0a:
        out.write(r'\n');
      case 0x0d:
        out.write(r'\r');
      case 0x09:
        out.write(r'\t');
      default:
        if (c < 0x20) {
          out.write('\\u${c.toRadixString(16).padLeft(4, '0')}');
        } else {
          out.writeCharCode(c);
        }
    }
  }
  out.write('"');
  return out.toString();
}

/// The derived schema of [description] as text (section 9.3), after
/// checking that the description is valid.
String deriveSchema(Description description) {
  validateDescription(description);
  return canonicalJson(deriveSchemaJson(description));
}

// ---------------------------------------------------------------- describe

String? _text(Map<String, Object?> texts, String name, List<String> languages) {
  final english = texts[name]! as String;
  final translations = (texts['${name}_translations']! as Map<String, Object?>)
      .cast<String, String>();
  final tag = lookup(languages, [...translations.keys, 'en']);
  final chosen = tag == null || tag == 'en' ? english : translations[tag]!;
  return chosen.isEmpty ? null : chosen;
}

Map<String, Object?> _shown(
  Map<String, Object?> texts,
  List<String> languages,
) => {
  'label': _text(texts, 'label', languages),
  'help': _text(texts, 'help', languages),
  'emoji': (texts['emoji']! as String).isEmpty ? null : texts['emoji'],
};

/// What a receiver shows of an object (metadata.md, sections 4 and 5).
Map<String, Object?> describeObject(
  Map<String, Object?> texts,
  Map<String, Object?> object,
  List<String> languages,
) {
  final fields = (object['fields']! as List<Object?>).cast<Description>();
  final indexed = [for (var i = 0; i < fields.length; i++) (i, fields[i])];
  indexed.sort((a, b) {
    final oa = a.$2['order'] as int?;
    final ob = b.$2['order'] as int?;
    if (oa != null && ob != null && oa != ob) return oa.compareTo(ob);
    if (oa != null && ob == null) return -1;
    if (oa == null && ob != null) return 1;
    return a.$1.compareTo(b.$1);
  });
  final ordered = <String>[];
  final placed = <String>{};
  for (final (_, f) in indexed) {
    final group = f['group']! as String;
    if (group.isEmpty) {
      ordered.add(f['name']! as String);
    } else if (placed.add(group)) {
      for (final (_, g) in indexed) {
        if (g['group'] == group) ordered.add(g['name']! as String);
      }
    }
  }
  final groups = (object['groups']! as List<Object?>)
      .cast<Map<String, Object?>>();
  return {
    ..._shown(texts, languages),
    'fields': ordered,
    'groups': {
      for (final g in groups)
        if (placed.contains(g['key']))
          g['key']! as String: _shown(
            g['texts']! as Map<String, Object?>,
            languages,
          ),
    },
  };
}

/// What a receiver shows of a typed field.
Map<String, Object?> describeField(Description field, List<String> languages) {
  final kind = field['kind']! as Branch;
  final b = kind.value! as Map<String, Object?>;
  return {
    ..._shown(field['texts']! as Map<String, Object?>, languages),
    'brick': kind.name,
    'symbols': kind.name == 'axt.EnumField'
        ? {
            for (final s
                in (b['symbols']! as List<Object?>)
                    .cast<Map<String, Object?>>())
              s['symbol']! as String: _shown(
                s['texts']! as Map<String, Object?>,
                languages,
              ),
          }
        : null,
    'record': kind.name == 'axt.ObjectField'
        ? describeObject(field['texts']! as Map<String, Object?>, b, languages)
        : null,
    'items': kind.name == 'axt.ListField' || kind.name == 'axt.MapField'
        ? describeField(
            b[kind.name == 'axt.ListField' ? 'items' : 'values']!
                as Description,
            languages,
          )
        : null,
  };
}

/// The typed field at [path], the names from the root joined by `.`, going
/// through the items of lists and maps of objects.
Description? fieldAt(Description description, String path) {
  var current = description;
  for (final name in path.split('.')) {
    var kind = current['kind']! as Branch;
    while (kind.name == 'axt.ListField' || kind.name == 'axt.MapField') {
      current =
          (kind.value! as Map<String, Object?>)[kind.name == 'axt.ListField'
                  ? 'items'
                  : 'values']!
              as Description;
      kind = current['kind']! as Branch;
    }
    if (kind.name != 'axt.ObjectField') return null;
    final fields =
        ((kind.value! as Map<String, Object?>)['fields']! as List<Object?>)
            .cast<Description>();
    final next = fields.where((f) => f['name'] == name).firstOrNull;
    if (next == null) return null;
    current = next;
  }
  return current;
}

/// Decodes [body], a record in single-object encoding of the type of
/// [description], and checks its values (fields.md, section 7).
///
/// Throws [AxtException] `DESCRIPTION_INVALID` for a description that is not
/// valid, the errors of [decodeRecord], and `VALUE_INVALID` naming the first
/// value that breaks a check.
Map<String, Object?> checkRecord(Description description, Uint8List body) {
  final schema = parseTypeSchema(deriveSchema(description));
  final value =
      decodeRecord(schema, null, body, check: false)! as Map<String, Object?>;
  final path = checkFieldValue({...description, 'required': false}, value, '');
  if (path != null) {
    throw AxtException(
      ErrorCode.valueInvalid,
      'the value at "$path" breaks a check',
      field: fieldPath(path),
    );
  }
  return value;
}
