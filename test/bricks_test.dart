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

void main() {
  final vectors =
      (jsonDecode(File('test/vectors/bricks.json').readAsStringSync())
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
