import 'dart:typed_data';

import 'package:avro/avro.dart';
import 'package:axt_protocol/axt_protocol.dart';
import 'package:axt_protocol/src/bricks.dart';
import 'package:axt_protocol/src/iregexp.dart';
import 'package:axt_protocol/src/limits.dart';
import 'package:axt_protocol/src/links.dart';
import 'package:test/test.dart' hide Description;

Map<String, Object?> texts({
  String label = '',
  Map<String, String> labels = const {},
  String emoji = '',
}) => {
  'label': label,
  'label_translations': labels,
  'help': '',
  'help_translations': <String, String>{},
  'emoji': emoji,
};

Description field(
  String name,
  String brick,
  Map<String, Object?> members, {
  bool required = false,
  int? order,
  String group = '',
  Map<String, Object?>? fieldTexts,
}) => {
  'name': name,
  'doc': 'The $name.',
  'texts': fieldTexts ?? texts(),
  'required': required,
  'order': order,
  'group': group,
  'sensitive': false,
  'advanced': false,
  'kind': Branch(brick, members),
};

Map<String, Object?> text({
  String? def,
  int? minLength,
  int? maxLength,
  String? pattern,
  String example = '',
}) => {
  'default': def,
  'min_length': minLength,
  'max_length': maxLength,
  'pattern': pattern,
  'multiline': false,
  'preferred_length': null,
  'placeholder': '',
  'example': example,
};

Map<String, Object?> number({
  num? def,
  num? min,
  num? max,
  String example = '',
}) => {
  'default': def,
  'min': min,
  'max': max,
  'unit': '',
  'placeholder': '',
  'example': example,
};

Map<String, Object?> object(
  String name,
  List<Description> fields, {
  List<Map<String, Object?>> groups = const [],
  int? version,
}) => {
  'name': name,
  'fields': fields,
  'groups': groups,
  'version': version,
  'title': '',
};

Description root(List<Description> fields, {String doc = 'A type.'}) => {
  ...field(
    'root',
    'axt.ObjectField',
    object('com.example.T', fields, version: 1),
  ),
  'doc': doc,
};

Description stringField(String name) => field(name, 'axt.StringField', text());

Matcher invalid([String? path]) => throwsA(
  isA<AxtException>()
      .having((e) => e.code, 'code', ErrorCode.descriptionInvalid)
      .having((e) => e.field, 'field', path ?? anything),
);

void main() {
  group('descriptions', () {
    test('bytes that are no description are undecodable', () {
      expect(
        () => decodeDescription(Uint8List.fromList([0xff])),
        throwsA(
          isA<AxtException>().having(
            (e) => e.code,
            'code',
            ErrorCode.undecodable,
          ),
        ),
      );
    });

    test('a description encodes and decodes again', () {
      final description = root([stringField('a')]);
      expect(decodeDescription(encodeDescription(description))['name'], 'root');
    });

    test('a root doc of white space only is empty', () {
      expect(
        () => validateDescription(root([stringField('a')], doc: ' ')),
        invalid('doc'),
      );
    });

    test('a keycap is an emoji, a digit alone is not', () {
      for (final emoji in ['#⃣', '1️⃣']) {
        validateDescription(
          root([
            field(
              'a',
              'axt.StringField',
              text(),
              fieldTexts: texts(emoji: emoji),
            ),
          ]),
        );
      }
      expect(
        () => validateDescription(
          root([
            field(
              'a',
              'axt.StringField',
              text(),
              fieldTexts: texts(emoji: '1'),
            ),
          ]),
        ),
        invalid('kind.fields[0].texts.emoji'),
      );
    });

    test('more translations than the limit break the rules', () {
      final labels = {
        for (var i = 0; i <= limit('metadata.translations'); i++)
          'x-a${i.toString().padLeft(3, '0')}': 'A',
      };
      expect(
        () => validateDescription(
          root([
            field(
              'a',
              'axt.StringField',
              text(),
              fieldTexts: texts(label: 'A', labels: labels),
            ),
          ]),
        ),
        invalid('kind.fields[0].texts.label_translations'),
      );
    });

    test('an infinite max of a double is not valid', () {
      expect(
        () => validateDescription(
          root([field('a', 'axt.DoubleField', number(max: double.infinity))]),
        ),
        invalid('kind.fields[0].kind.max'),
      );
    });

    test('an example of a number with a control character is not valid', () {
      expect(
        () => validateDescription(
          root([field('a', 'axt.IntField', number(example: '1\t2'))]),
        ),
        invalid('kind.fields[0].kind.example'),
      );
    });

    test('a default of bytes that breaks a check is not valid', () {
      expect(
        () => validateDescription(
          root([
            field('a', 'axt.BytesField', {
              'default': Uint8List(2),
              'min_length': null,
              'max_length': 1,
            }),
          ]),
        ),
        invalid('kind.fields[0].kind.default'),
      );
    });

    test('an enum with the name of an object is not valid', () {
      expect(
        () => validateDescription(
          root([
            field('a', 'axt.EnumField', {
              'name': 'T',
              'symbols': [
                {'symbol': 'A', 'texts': texts()},
              ],
              'fallback': 'A',
              'default': null,
            }),
          ]),
        ),
        invalid('kind.fields[0].kind.name'),
      );
    });
  });

  group('describe', () {
    test('fields with an order come first, by their order', () {
      final shown = describeObject(
        texts(),
        object('T', [
          stringField('a'),
          field('b', 'axt.StringField', text(), order: 2),
          field('c', 'axt.StringField', text(), order: 1),
          stringField('d'),
        ]),
        ['en'],
      );
      expect(shown['fields'], ['c', 'b', 'a', 'd']);
      final first = describeObject(
        texts(),
        object('T', [
          field('a', 'axt.StringField', text(), order: 1),
          stringField('b'),
        ]),
        ['en'],
      );
      expect(first['fields'], ['a', 'b']);
    });

    test('a path goes through lists of objects', () {
      final description = root([
        field('items', 'axt.ListField', {
          'items': field(
            'items',
            'axt.ObjectField',
            object('Item', [stringField('code')]),
          ),
        }),
        stringField('name'),
      ]);
      expect(fieldAt(description, 'items.code')?['name'], 'code');
      expect(fieldAt(description, 'items.none'), isNull);
      expect(fieldAt(description, 'name.code'), isNull);
    });
  });

  group('canonical JSON', () {
    test('numbers and strings are written as ECMAScript writes them', () {
      expect(
        canonicalJson([123.456, 1.5e-7, 1e-6, 1.23e22, 5e-324, '\b\f\r\n']),
        r'[123.456,1.5e-7,0.000001,1.23e+22,5e-324,"\b\f\r\n"]',
      );
    });

    test('a value that is not JSON is rejected', () {
      expect(() => canonicalJson(Object()), throwsArgumentError);
    });
  });

  group('I-Regexp', () {
    RegExp? compile(String pattern) =>
        compileIRegexp(pattern, maxBytes: 1024, maxQuantifier: 1000);

    test('the escapes of line feed, carriage return and tab', () {
      expect(compile(r'\n\r\t')!.hasMatch('\n\r\t'), isTrue);
    });

    test('a range that ends in a category is not valid', () {
      expect(compile(r'[a-\p{L}]'), isNull);
    });

    test('a pattern above the limit of bytes is not valid', () {
      expect(compileIRegexp('ä', maxBytes: 1, maxQuantifier: 1000), isNull);
    });
  });

  group('links', () {
    Map<String, Object?> relation({
      String text = '',
      String note = '',
      Map<String, Object?>? start,
      Map<String, String> attributes = const {},
    }) => {
      'id': '3e8a5b14-7c29-4d6e-a0f3-1b9d2c7e5a46',
      'kind': 'axt.related',
      'target': {'uri': 'https://example.org', 'text': text},
      'note': note,
      'start': start,
      'end': null,
      'attributes': attributes,
    };

    test('a relation that breaks a limit is named by its member', () {
      expect(relationsProblem([relation()], 'r'), isNull);
      expect(
        relationsProblem([relation(text: 'x' * 257)], 'r'),
        'r[0].target.text',
      );
      expect(relationsProblem([relation(note: 'x' * 4097)], 'r'), 'r[0].note');
      expect(
        relationsProblem([
          relation(
            start: {
              'year': 2026, 'month': 13, 'day': 1, 'hour': 0, 'minute': 0, //
              'second': 0, 'millisecond': 0, 'zone': null,
              'offset_seconds': null, 'instant_ms': null,
            },
          ),
        ], 'r'),
        'r[0].start',
      );
      expect(
        relationsProblem([
          relation(attributes: {'': 'x'}),
        ], 'r'),
        'r[0].attributes',
      );
    });

    Map<String, Object?> extension(String name, List<int> data) => {
      'name': name,
      'data': Uint8List.fromList(data),
    };

    final data = [0xc3, 0x01, 0, 0, 0, 0, 0, 0, 0, 0];

    test('extensions keep their rules', () {
      expect(
        extensionsProblem([extension('org.example.A', data)], 'e'),
        isNull,
      );
      expect(
        extensionsProblem([
          for (var i = 0; i <= limit('fields.extensions'); i++)
            extension('org.example.A$i', data),
        ], 'e'),
        'e',
      );
      expect(extensionsProblem([extension('A', data)], 'e'), 'e[0].name');
      expect(
        extensionsProblem([
          extension('org.example.A', data),
          extension('org.example.A', data),
        ], 'e'),
        'e[1].name',
      );
      expect(
        extensionsProblem([
          extension('org.example.A', [0xc3, 0x01]),
        ], 'e'),
        'e[0].data',
      );
      expect(
        extensionsProblem([
          extension('org.example.A', [0xc3, 0x00, ...data.skip(2)]),
        ], 'e'),
        'e[0].data',
      );
    });
  });
}
