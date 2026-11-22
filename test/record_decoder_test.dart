import 'dart:convert';
import 'dart:typed_data';

import 'package:avro/avro.dart';
import 'package:axt_protocol/src/envelope.dart' show axtSchema;
import 'package:axt_protocol/src/errors.dart';
import 'package:axt_protocol/src/record_decoder.dart';
import 'package:test/test.dart';

Matcher rejectedWith(ErrorCode code) =>
    throwsA(isA<AxtException>().having((e) => e.code, 'code', code));

Uint8List body(Schema schema, Object? value) =>
    AvroCodec(writer: schema).encodeSingleObject(value);

final String dateTimeText = axtSchema('axt.DateTime').jsonText;

Schema memo({
  String name = 'Memo',
  String? extraField,
  List<String>? aliases,
}) => parseTypeSchema(
  jsonEncode({
    'type': 'record',
    'name': name,
    'namespace': 'org.example',
    'aliases': ?aliases,
    'fields': [
      {'name': 'text', 'type': 'string'},
      {'name': 'due', 'type': jsonDecode(dateTimeText)},
      {
        'name': 'tags',
        'type': {'type': 'array', 'items': 'string'},
      },
      if (extraField != null) {'name': extraField, 'type': 'int', 'default': 7},
    ],
  }),
);

Map<String, Object?> due({int instant = 1795510800000}) => {
  'year': 2026,
  'month': 11,
  'day': 24,
  'hour': 10,
  'minute': 0,
  'second': 0,
  'millisecond': 0,
  'zone': 'Europe/Berlin',
  'offset_seconds': 3600,
  'instant_ms': instant,
};

void main() {
  final writer = memo();
  final good = body(writer, {
    'text': 'vet',
    'due': due(),
    'tags': ['a'],
  });

  test('reads a record with its writer schema', () {
    final value = decodeRecord(writer, null, good)! as Map<String, Object?>;
    expect(value['text'], 'vet');
    expect(value['tags'], ['a']);
  });

  test('resolves against a reader with a field more', () {
    final value =
        decodeRecord(writer, memo(extraField: 'n'), good)!
            as Map<String, Object?>;
    expect(value['n'], 7);
  });

  test('takes a writer named by an alias of the reader', () {
    final reader = memo(name: 'Note', aliases: ['Memo']);
    expect(decodeRecord(writer, reader, good), isA<Map<String, Object?>>());
    final full = memo(name: 'Note', aliases: ['org.example.Memo']);
    expect(decodeRecord(writer, full, good), isA<Map<String, Object?>>());
  });

  test('rejects a reader of another name without an alias', () {
    expect(
      () => decodeRecord(writer, memo(name: 'Note'), good),
      rejectedWith(ErrorCode.doesNotResolve),
    );
  });

  test('rejects schemas that do not resolve', () {
    final reader = parseTypeSchema(
      jsonEncode({
        'type': 'record',
        'name': 'Memo',
        'namespace': 'org.example',
        'fields': [
          {'name': 'missing', 'type': 'int'},
        ],
      }),
    );
    expect(
      () => decodeRecord(writer, reader, good),
      rejectedWith(ErrorCode.doesNotResolve),
    );
  });

  test('rejects a body of another fingerprint', () {
    final other = body(parseTypeSchema('"string"'), 'x');
    expect(
      () => decodeRecord(writer, null, other),
      rejectedWith(ErrorCode.schemaUnknown),
    );
  });

  test('rejects bytes that are no value', () {
    expect(
      () => decodeRecord(writer, null, Uint8List.sublistView(good, 0, 12)),
      rejectedWith(ErrorCode.undecodable),
    );
    expect(
      () => decodeRecord(writer, null, Uint8List(3)),
      rejectedWith(ErrorCode.undecodable),
    );
  });

  test('rejects a time value that is not valid, naming it', () {
    final bad = body(writer, {
      'text': 'vet',
      'due': due(instant: 1),
      'tags': <String>[],
    });
    expect(
      () => decodeRecord(writer, null, bad),
      throwsA(
        isA<AxtException>()
            .having((e) => e.code, 'code', ErrorCode.valueInvalid)
            .having((e) => e.field, 'field', 'due'),
      ),
    );
  });

  test('names time values in arrays, maps and unions by their path', () {
    final schema = parseTypeSchema(
      jsonEncode({
        'type': 'record',
        'name': 'Plan',
        'fields': [
          {
            'name': 'when',
            'type': {'type': 'array', 'items': jsonDecode(dateTimeText)},
          },
          {
            'name': 'by',
            'type': {'type': 'map', 'values': 'axt.DateTime'},
          },
          {
            'name': 'maybe',
            'type': ['null', 'axt.DateTime'],
          },
        ],
      }),
    );
    void expectField(Map<String, Object?> value, String? field) {
      final bytes = body(schema, value);
      if (field == null) {
        expect(decodeRecord(schema, null, bytes), isNotNull);
      } else {
        expect(
          () => decodeRecord(schema, null, bytes),
          throwsA(isA<AxtException>().having((e) => e.field, 'field', field)),
        );
      }
    }

    expectField({
      'when': [due()],
      'by': {'tax': due()},
      'maybe': null,
    }, null);
    expectField({
      'when': [due(), due(instant: 1)],
      'by': <String, Object?>{},
      'maybe': null,
    }, 'when[1]');
    expectField({
      'when': <Object?>[],
      'by': {'tax': due(instant: 1)},
      'maybe': due(),
    }, 'by["tax"]');
    expectField({
      'when': <Object?>[],
      'by': <String, Object?>{},
      'maybe': due(instant: 1),
    }, 'maybe');
  });

  test('reports no field for a path above 1,024 bytes', () {
    final name = 'f' * 1100;
    final schema = parseTypeSchema(
      jsonEncode({
        'type': 'record',
        'name': 'Long',
        'fields': [
          {'name': name, 'type': jsonDecode(dateTimeText)},
        ],
      }),
    );
    expect(
      () => decodeRecord(schema, null, body(schema, {name: due(instant: 1)})),
      throwsA(
        isA<AxtException>()
            .having((e) => e.code, 'code', ErrorCode.valueInvalid)
            .having((e) => e.field, 'field', isNull),
      ),
    );
  });

  test('rejects a record deeper than 32', () {
    final schema = parseTypeSchema(
      jsonEncode({
        'type': 'record',
        'name': 'Node',
        'fields': [
          {
            'name': 'next',
            'type': ['null', 'Node'],
          },
          {
            'name': 'side',
            'type': {
              'type': 'map',
              'values': {'type': 'array', 'items': 'boolean'},
            },
          },
        ],
      }),
    );
    Map<String, Object?> chain(int depth) => {
      'next': depth == 1 ? null : chain(depth - 1),
      'side': {
        'k': [true, 1.0 == 1.0],
      },
    };
    expect(decodeRecord(schema, null, body(schema, chain(30))), isNotNull);
    expect(
      () => decodeRecord(schema, null, body(schema, chain(32))),
      rejectedWith(ErrorCode.undecodable),
    );
  });

  test('rejects named types of the namespace axt but the time types', () {
    final other = parseTypeSchema(
      '{"type":"record","name":"Mine","namespace":"axt","fields":[]}',
    );
    expect(
      () => decodeRecord(other, null, body(other, <String, Object?>{})),
      rejectedWith(ErrorCode.doesNotResolve),
    );
    final changed = parseTypeSchema(
      '{"type":"record","name":"Host","fields":[{"name":"d","type":'
      '{"type":"record","name":"Date","namespace":"axt","fields":[]}}]}',
    );
    expect(
      () => decodeRecord(
        changed,
        null,
        body(changed, {'d': <String, Object?>{}}),
      ),
      rejectedWith(ErrorCode.doesNotResolve),
    );
    final enums = parseTypeSchema(
      '{"type":"record","name":"E","fields":[{"name":"e","type":'
      '{"type":"enum","name":"S","symbols":["A"]}},{"name":"f","type":'
      '{"type":"fixed","name":"F","size":1}},{"name":"g","type":"S"}]}',
    );
    expect(
      decodeRecord(
        enums,
        null,
        body(enums, {'e': 'A', 'f': Uint8List(1), 'g': 'A'}),
      ),
      isNotNull,
    );
  });

  test('takes axt.Extension as published and checks its rules', () {
    final host = parseTypeSchema(
      jsonEncode({
        'type': 'record',
        'name': 'Host',
        'namespace': 'org.example',
        'fields': [
          {
            'name': 'extensions',
            'type': {
              'type': 'array',
              'items': jsonDecode(axtSchema('axt.Extension').jsonText),
            },
          },
        ],
      }),
    );
    Map<String, Object?> extension(List<int> data) => {
      'extensions': [
        {'name': 'org.example.A', 'data': Uint8List.fromList(data)},
      ],
    };
    final data = [0xc3, 0x01, 0, 0, 0, 0, 0, 0, 0, 0];
    expect(decodeRecord(host, null, body(host, extension(data))), isNotNull);
    expect(
      () => decodeRecord(host, null, body(host, extension(data.sublist(2)))),
      throwsA(
        isA<AxtException>().having(
          (e) => e.field,
          'field',
          'extensions[0].data',
        ),
      ),
    );
  });

  test('parseTypeSchema rejects what is no schema', () {
    expect(() => parseTypeSchema('{'), rejectedWith(ErrorCode.doesNotResolve));
    expect(
      () => parseTypeSchema('{"type":"nope"}'),
      rejectedWith(ErrorCode.doesNotResolve),
    );
  });
}
