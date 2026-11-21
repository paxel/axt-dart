import 'dart:convert';
import 'dart:io';

import 'package:axt_protocol/src/conformance_adapter.dart';
import 'package:test/test.dart';

/// The members of an expected step that the adapter's answer gives as they
/// are, without messages to decode.
const List<String> plain = ['result', 'made', 'status', 'resend'];

void main() {
  final vectors =
      (jsonDecode(File('test/vectors/shares.json').readAsStringSync())
              as Map<String, Object?>)['vectors']!
          as List<Object?>;
  for (final vector in vectors.cast<Map<String, Object?>>()) {
    final op = vector['op'];
    if (op != 'owner' && op != 'proposer') continue;
    test(vector['id'], () async {
      final reply = await answer({
        'id': vector['id'],
        'op': op,
        'input': vector['input'],
      });
      final expected = ((vector['expected']! as Map)['steps']! as List)
          .cast<Map<String, Object?>>();
      final steps = ((reply['output']! as Map)['steps']! as List)
          .cast<Map<String, Object?>>();
      expect(steps, hasLength(expected.length));
      for (var i = 0; i < expected.length; i++) {
        for (final key in plain) {
          if (expected[i].containsKey(key)) {
            expect(steps[i][key], expected[i][key], reason: 'step $i $key');
          }
        }
        for (final key in ['replies', 'messages']) {
          if (expected[i][key] case final List<Object?> list) {
            expect(
              (steps[i][key]! as List).length,
              list.length,
              reason: 'step $i $key',
            );
          }
        }
      }
    });
  }
}
