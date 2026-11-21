import 'package:test/test.dart';

import '../tool/adapter.dart';

void main() {
  test('hello names the library and its categories', () {
    expect(
      answer({
        'id': 'hello',
        'op': 'hello',
        'input': {'format': 1},
      }),
      {
        'id': 'hello',
        'output': {
          'name': 'axt_protocol (AXT 0.1.0)',
          'categories': implementedCategories,
        },
      },
    );
  });

  test('hello with another vector format fails', () {
    final reply = answer({
      'id': 'hello',
      'op': 'hello',
      'input': {'format': 2},
    });
    expect(reply['id'], 'hello');
    expect(reply['failure'], isA<String>());
  });

  test('an operation it cannot perform is unsupported', () {
    expect(
      answer({'id': 'v1', 'op': 'fingerprint', 'input': <String, Object?>{}}),
      {'id': 'v1', 'unsupported': true},
    );
  });

  test('a request that is not an object fails', () {
    expect(answer(<Object?>[]), containsPair('failure', isA<String>()));
  });
}
