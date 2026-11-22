import 'dart:convert';
import 'dart:io';

import 'package:axt_protocol/src/conformance_adapter.dart';
import 'package:test/test.dart';

/// [value] without the members `note`, which the runner does not compare.
Object? withoutNotes(Object? value) => switch (value) {
  Map() => {
    for (final e in value.entries)
      if (e.key != 'note') e.key: withoutNotes(e.value),
  },
  List() => [for (final v in value) withoutNotes(v)],
  _ => value,
};

/// Answers every vector of the vendored [file] and compares the answer with
/// the expected result, as the runner does for these categories.
void replay(String file) {
  final vectors =
      (jsonDecode(File('test/vectors/$file').readAsStringSync())
              as Map<String, Object?>)['vectors']!
          as List<Object?>;
  for (final vector in vectors.cast<Map<String, Object?>>()) {
    test(vector['id'], () async {
      final reply = await answer({
        'id': vector['id'],
        'op': vector['op'],
        'input': vector['input'],
      });
      expect(reply, contains('output'), reason: '$reply');
      expect(withoutNotes(reply['output']), withoutNotes(vector['expected']));
    });
  }
}

void main() => replay('bricks.json');
