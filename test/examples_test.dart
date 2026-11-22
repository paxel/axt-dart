import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:avro/avro.dart';
import 'package:axt_protocol/examples.dart';
import 'package:test/test.dart';

/// A generic value of AvroCodec in the JSON form of the vectors.
Object? json(Object? value) => switch (value) {
  Branch(:final value) => json(value),
  Uint8List() => [
    for (final b in value) b.toRadixString(16).padLeft(2, '0'),
  ].join(),
  Map() => {for (final e in value.entries) e.key: json(e.value)},
  List() => [for (final v in value) json(v)],
  _ => value,
};

Uint8List unhex(String text) => Uint8List.fromList([
  for (var i = 0; i < text.length; i += 2)
    int.parse(text.substring(i, i + 2), radix: 16),
]);

/// What [value] and an equal copy of it, [copy], show of the generated
/// equality, hash code and text.
void same<T extends Object>(T value, T copy) {
  expect(copy, value);
  expect(copy.hashCode, value.hashCode);
  expect('$copy', '$value');
  expect(value == Object(), isFalse);
}

/// The typed values of the records of the vectors, by type.
final Map<String, List<Object>> decoded = {};

/// Decodes [body], written with [writer], as [type], compares it with the
/// generic value, and encodes and decodes it again.
void check<T extends Object>(AvroType<T> type, Schema writer, Uint8List body) {
  final payload = SingleObjectHeader.parse(body).payload;
  final value = TypedCodec(type, writer: writer).decode(payload);
  final generic = AvroCodec(
    writer: writer,
    reader: type.schema,
    decodeBranches: true,
  ).decode(payload);
  expect(json(type.toAvro(value)), json(generic));
  final own = TypedCodec(type);
  expect(own.decode(own.encode(value)), value);
  (decoded[(type.schema as NamedSchema).fullName] ??= []).add(value);
}

void main() {
  final vectors =
      (jsonDecode(File('test/vectors/types.json').readAsStringSync())
              as Map<String, Object?>)['vectors']!
          as List<Object?>;
  for (final vector in vectors.cast<Map<String, Object?>>()) {
    final input = vector['input']! as Map<String, Object?>;
    final expected = vector['expected']! as Map<String, Object?>;
    if (vector['op'] != 'decode_record' || !expected.containsKey('accept')) {
      continue;
    }
    final writer = Schema.parse(input['writer_schema']! as String);
    final name = (writer as NamedSchema).fullName;
    if (!name.startsWith('axt.example.v1.')) continue;
    test(vector['id'], () {
      final body = unhex(input['body']! as String);
      switch (name) {
        case 'axt.example.v1.Appointment':
          check(Appointment.avroType, writer, body);
        case 'axt.example.v1.Car':
          check(Car.avroType, writer, body);
        case 'axt.example.v1.Document':
          check(Document.avroType, writer, body);
        case 'axt.example.v1.Measurement':
          check(Measurement.avroType, writer, body);
        case 'axt.example.v1.Note':
          check(Note.avroType, writer, body);
        case 'axt.example.v1.Person':
          check(Person.avroType, writer, body);
        case 'axt.example.v1.Pet':
          check(Pet.avroType, writer, body);
        default:
          check(Task.avroType, writer, body);
      }
    });
  }

  test('every class compares, hashes, shows and copies itself', () {
    List<T> all<T>(String type) => decoded[type]!.cast<T>();
    final relations = <AxtRelation>[];
    final extensions = <AxtExtension>[];
    for (final a in all<Appointment>('axt.example.v1.Appointment')) {
      same(a, a.copyWith());
      same(a.start, a.start.copyWith());
      for (final r in a.reminders) {
        same(r, r.copyWith());
      }
      relations.addAll(a.relations);
      extensions.addAll(a.extensions);
    }
    for (final c in all<Car>('axt.example.v1.Car')) {
      same(c, c.copyWith());
      relations.addAll(c.relations);
    }
    for (final d in all<Document>('axt.example.v1.Document')) {
      same(d, d.copyWith());
      if (d.dated case final dated?) same(dated, dated.copyWith());
    }
    for (final m in all<Measurement>('axt.example.v1.Measurement')) {
      same(m, m.copyWith());
    }
    for (final n in all<Note>('axt.example.v1.Note')) {
      same(n, n.copyWith());
      relations.addAll(n.relations);
    }
    for (final p in all<Person>('axt.example.v1.Person')) {
      same(p, p.copyWith());
      for (final x in p.phones) {
        same(x, x.copyWith());
      }
      for (final x in p.emails) {
        same(x, x.copyWith());
      }
      for (final x in p.addresses) {
        same(x, x.copyWith());
      }
    }
    for (final p in all<Pet>('axt.example.v1.Pet')) {
      same(p, p.copyWith());
      relations.addAll(p.relations);
      extensions.addAll(p.extensions);
    }
    for (final t in all<Task>('axt.example.v1.Task')) {
      same(t, t.copyWith());
    }
    for (final e in extensions) {
      same(e, e.copyWith());
    }
    for (final relation in relations) {
      same(relation, relation.copyWith());
      switch (relation.target) {
        case AxtRelationTargetRelationRecordTarget(:final value):
          same(relation.target, AxtRelationTargetRelationRecordTarget(value));
          same(value, value.copyWith());
        case AxtRelationTargetRelationOutsideTarget(:final value):
          same(relation.target, AxtRelationTargetRelationOutsideTarget(value));
          same(value, value.copyWith());
      }
    }
  });

  test('lists and maps that differ are not equal', () {
    final appointment = decoded['axt.example.v1.Appointment']!
        .cast<Appointment>()
        .firstWhere((a) => a.reminders.length > 1);
    final relation = decoded.values
        .expand((v) => v)
        .whereType<Pet>()
        .expand((p) => p.relations)
        .first;
    expect(
      appointment ==
          appointment.copyWith(reminders: appointment.reminders.sublist(1)),
      isFalse,
    );
    expect(
      appointment ==
          appointment.copyWith(
            reminders: appointment.reminders.reversed.toList(),
          ),
      isFalse,
    );
    expect(
      relation ==
          relation.copyWith(attributes: {...relation.attributes, 'x': 'y'}),
      isFalse,
    );
    expect(
      relation.copyWith(attributes: {'a': 'b'}) ==
          relation.copyWith(attributes: {'c': 'b'}),
      isFalse,
    );
  });

  test('every type takes extensions; a target of no branch is no relation', () {
    final extension = {
      'name': 'org.example.A',
      'data': Uint8List.fromList([0xc3, 0x01, ...List.filled(8, 0)]),
    };
    void withExtension<T extends Object>(AvroType<T> type, String name) {
      final generic =
          type.toAvro(decoded[name]!.cast<T>().first)! as Map<String, Object?>;
      final value = type.fromAvro({
        ...generic,
        'extensions': [extension],
        if (generic.containsKey('updated')) 'updated': generic['created'],
      });
      expect(
        json(type.toAvro(value)),
        json({
          ...generic,
          'extensions': [extension],
          if (generic.containsKey('updated')) 'updated': generic['created'],
        }),
      );
    }

    withExtension(Appointment.avroType, 'axt.example.v1.Appointment');
    withExtension(Car.avroType, 'axt.example.v1.Car');
    withExtension(Document.avroType, 'axt.example.v1.Document');
    withExtension(Measurement.avroType, 'axt.example.v1.Measurement');
    withExtension(Note.avroType, 'axt.example.v1.Note');
    withExtension(Person.avroType, 'axt.example.v1.Person');
    withExtension(Task.avroType, 'axt.example.v1.Task');
    final relation =
        AxtRelation.avroType.toAvro(
              decoded.values
                  .expand((v) => v)
                  .whereType<Pet>()
                  .expand((p) => p.relations)
                  .first,
            )!
            as Map<String, Object?>;
    expect(
      () => AxtRelation.avroType.fromAvro({
        ...relation,
        'target': const Branch('axt.Nope', <String, Object?>{}),
      }),
      throwsArgumentError,
    );
  });

  test('enums know their symbols, and no other', () {
    for (final (values, fromSymbol) in <(List<Enum>, Enum Function(String))>[
      (CarDistanceUnit.values, CarDistanceUnit.fromSymbol),
      (NoteFormat.values, NoteFormat.fromSymbol),
      (PetSex.values, PetSex.fromSymbol),
      (TaskPriority.values, TaskPriority.fromSymbol),
    ]) {
      for (final value in values) {
        expect(fromSymbol((value as dynamic).symbol as String), value);
      }
      expect(() => fromSymbol('NOPE'), throwsArgumentError);
    }
  });
}
