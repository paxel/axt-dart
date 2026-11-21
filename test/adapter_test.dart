import 'dart:io';

import 'package:axt_protocol/src/conformance_adapter.dart';
import 'package:crypto/crypto.dart';
import 'package:test/test.dart';

import 'envelope_test.dart' show deleteHex, unhex;

Map<String, Object?> run(String op, Object? input) =>
    answer({'id': 'v', 'op': op, 'input': input});

Object? output(String op, Object? input) {
  final reply = run(op, input);
  expect(reply, contains('output'), reason: '$reply');
  return reply['output'];
}

String hex(List<int> bytes) =>
    [for (final b in bytes) b.toRadixString(16).padLeft(2, '0')].join();

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
    expect(run('nope', <String, Object?>{}), {'id': 'v', 'unsupported': true});
  });

  test('a request or an input that is not an object fails', () {
    expect(answer(<Object?>[]), containsPair('failure', isA<String>()));
    expect(run('fingerprint', 'x'), containsPair('failure', isA<String>()));
  });

  test('fingerprint gives the canonical form and the CRC-64-AVRO', () {
    expect(output('fingerprint', {'schema': '{"type":"int"}'}), {
      'accept': {'canonical_form': '"int"', 'fingerprint': '8f5c393f1ad57572'},
    });
    expect(
      run('fingerprint', {'schema': '{'}),
      containsPair('failure', isA<String>()),
    );
    expect(run('fingerprint', {}), containsPair('failure', isA<String>()));
  });

  test('decode_message accepts, rejects, and reads deflated bytes', () {
    final accepted = output('decode_message', {'message': deleteHex});
    expect(accepted, {
      'accept': {
        'format': 1,
        'kind': 'DELETE',
        'sender':
            '1b84a600f3503e22bbcc99e63202a7194bf6bd69aff1471cce6410d53c26ec4a',
        'record': {'id': 'd4c3b2a1-0f9e-4d8c-b7a6-5f4e3d2c1b0a', 'version': 4},
        'body': '',
        'signature': deleteHex.substring(deleteHex.length - 128),
      },
    });
    expect(output('decode_message', {'message': '00'}), {
      'reject': {'error': 'INVALID_MESSAGE'},
    });
    final bytes = unhex(deleteHex);
    final deflated = {
      'deflate': hex(ZLibEncoder(raw: true).convert(bytes)),
      'length': bytes.length,
      'sha256': hex(sha256.convert(bytes).bytes),
    };
    expect(output('decode_message', {'message': deflated}), accepted);
  });

  test('bad bytes fail', () {
    for (final message in [
      'abc',
      'zz',
      42,
      {'deflate': '00'},
      {
        'deflate': hex(ZLibEncoder(raw: true).convert([1])),
        'length': 2,
        'sha256': '',
      },
    ]) {
      expect(
        run('decode_message', {'message': message}),
        containsPair('failure', isA<String>()),
        reason: '$message',
      );
    }
  });

  test('decode_body gives the value in its JSON form', () {
    expect(
      output('decode_body', {
        'kind': 'WITHDRAW',
        'body':
            'c301d57da92315f555e3da9e54c9aa2db43244df99889d9138c1ca7175d4ca09'
            '08168f63530e4a7dedb7',
      }),
      {
        'accept': {
          'value': {
            'to': 'da9e54c9aa2db43244df99889d9138c1ca7175d4ca0908168f63530e4a7dedb7',
          },
        },
      },
    );
    expect(output('decode_body', {'kind': 'ACK', 'body': ''}), {
      'reject': {'error': 'INVALID_MESSAGE'},
    });
    expect(
      run('decode_body', {'kind': 'DATA', 'body': ''}),
      containsPair('failure', isA<String>()),
    );
  });

  test('decode_body writes arrays as arrays', () {
    final reply = output('decode_body', {
      'kind': 'ACK',
      'body':
          'c3015ce076801909dd381b84a600f3503e22bbcc99e63202a7194bf6bd69aff1471c'
          'ce6410d53c26ec4a024861326434663662382d316333652d346135622d396437662d'
          '3065326334613662386431660200020000',
    });
    expect(reply, isA<Map<String, Object?>>());
    final value = (reply! as Map)['accept']['value'] as Map;
    expect(value.values.whereType<List<Object?>>(), isNotEmpty);
  });

  test('encode_message writes the message decode_message read', () {
    final fields =
        (output('decode_message', {'message': deleteHex})! as Map)['accept']
            as Map<String, Object?>;
    expect(output('encode_message', fields), {
      'accept': {'message': deleteHex},
    });
    expect(
      output('encode_message', {...fields, 'record': null}),
      isA<Map<String, Object?>>(),
    );
    expect(
      run('encode_message', {...fields, 'record': 'x'}),
      containsPair('failure', isA<String>()),
    );
    expect(
      run('encode_message', {...fields, 'format': 2}),
      containsPair('failure', isA<String>()),
    );
  });
}
