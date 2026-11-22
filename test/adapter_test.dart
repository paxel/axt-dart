import 'dart:convert';
import 'dart:io';

import 'package:axt_protocol/src/conformance_adapter.dart';
import 'package:crypto/crypto.dart';
import 'package:test/test.dart';

import 'envelope_test.dart' show deleteHex, unhex;

Future<Map<String, Object?>> run(String op, Object? input) =>
    answer({'id': 'v', 'op': op, 'input': input});

Future<Object?> output(String op, Object? input) async {
  final reply = await run(op, input);
  expect(reply, contains('output'), reason: '$reply');
  return reply['output'];
}

String hex(List<int> bytes) =>
    [for (final b in bytes) b.toRadixString(16).padLeft(2, '0')].join();

void main() {
  test('hello names the library and its categories', () async {
    expect(
      await answer({
        'id': 'hello',
        'op': 'hello',
        'input': {'format': 1},
      }),
      {
        'id': 'hello',
        'output': {
          'name': 'axt_protocol (AXT 0.2.0)',
          'categories': implementedCategories,
        },
      },
    );
  });

  test('hello with another vector format fails', () async {
    final reply = await answer({
      'id': 'hello',
      'op': 'hello',
      'input': {'format': 2},
    });
    expect(reply['id'], 'hello');
    expect(reply['failure'], isA<String>());
  });

  test('an operation it cannot perform is unsupported', () async {
    expect(await run('nope', <String, Object?>{}), {
      'id': 'v',
      'unsupported': true,
    });
  });

  test('describe fails for languages or a field of the wrong form', () async {
    final vectors =
        (jsonDecode(File('test/vectors/bricks.json').readAsStringSync())
                as Map<String, Object?>)['vectors']!
            as List<Object?>;
    final description =
        ((vectors.cast<Map<String, Object?>>().firstWhere(
              (v) => v['op'] == 'describe',
            ))['input']!
            as Map)['description'];
    for (final input in [
      {'description': description, 'field': null, 'languages': 'en'},
      {
        'description': description,
        'field': 1,
        'languages': ['en'],
      },
      {
        'description': description,
        'field': 'nope',
        'languages': ['en'],
      },
    ]) {
      expect(
        await run('describe', input),
        containsPair('failure', isA<String>()),
        reason: '$input',
      );
    }
  });

  test('a request or an input that is not an object fails', () async {
    expect(await answer(<Object?>[]), containsPair('failure', isA<String>()));
    expect(
      await run('fingerprint', 'x'),
      containsPair('failure', isA<String>()),
    );
  });

  test('fingerprint gives the canonical form and the CRC-64-AVRO', () async {
    expect(await output('fingerprint', {'schema': '{"type":"int"}'}), {
      'accept': {'canonical_form': '"int"', 'fingerprint': '8f5c393f1ad57572'},
    });
    expect(
      await run('fingerprint', {'schema': '{'}),
      containsPair('failure', isA<String>()),
    );
    expect(
      await run('fingerprint', {}),
      containsPair('failure', isA<String>()),
    );
  });

  test('decode_message accepts, rejects, and reads deflated bytes', () async {
    final accepted = await output('decode_message', {'message': deleteHex});
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
    expect(await output('decode_message', {'message': '00'}), {
      'reject': {'error': 'INVALID_MESSAGE'},
    });
    final bytes = unhex(deleteHex);
    final deflated = {
      'deflate': hex(ZLibEncoder(raw: true).convert(bytes)),
      'length': bytes.length,
      'sha256': hex(sha256.convert(bytes).bytes),
    };
    expect(await output('decode_message', {'message': deflated}), accepted);
  });

  test('bad bytes fail', () async {
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
        await run('decode_message', {'message': message}),
        containsPair('failure', isA<String>()),
        reason: '$message',
      );
    }
  });

  test('decode_body gives the value in its JSON form', () async {
    expect(
      await output('decode_body', {
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
    expect(await output('decode_body', {'kind': 'ACK', 'body': ''}), {
      'reject': {'error': 'INVALID_MESSAGE'},
    });
    expect(
      await run('decode_body', {'kind': 'DATA', 'body': ''}),
      containsPair('failure', isA<String>()),
    );
  });

  test('decode_body writes arrays as arrays', () async {
    final reply = await output('decode_body', {
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

  test('encode_message writes the message decode_message read', () async {
    final fields =
        ((await output('decode_message', {'message': deleteHex}))!
                as Map)['accept']
            as Map<String, Object?>;
    expect(await output('encode_message', fields), {
      'accept': {'message': deleteHex},
    });
    expect(
      await output('encode_message', {...fields, 'record': null}),
      isA<Map<String, Object?>>(),
    );
    expect(
      await run('encode_message', {...fields, 'record': 'x'}),
      containsPair('failure', isA<String>()),
    );
    expect(
      await run('encode_message', {...fields, 'format': 2}),
      containsPair('failure', isA<String>()),
    );
  });

  test('decode_record reads a record and rejects with a field', () async {
    const writer =
        '{"type":"record","name":"R","fields":[{"name":"n","type":"int"}]}';
    expect(
      await output('decode_record', {
        'writer_schema': writer,
        'reader_schema': null,
        'body': 'c301${'0' * 16}02',
      }),
      {
        'reject': {'error': 'SCHEMA_UNKNOWN'},
      },
    );
    expect(
      await run('decode_record', {
        'writer_schema': writer,
        'reader_schema': 3,
        'body': '',
      }),
      containsPair('failure', isA<String>()),
    );
    expect(
      await output('decode_record', {
        'writer_schema': writer,
        'reader_schema': writer,
        'body': '',
      }),
      {
        'reject': {'error': 'UNDECODABLE'},
      },
    );
  });

  test('decode_record gives the value it read', () async {
    const writer =
        '{"type":"record","name":"R","fields":[{"name":"n","type":"int"}]}';
    final fingerprint =
        ((await output('fingerprint', {'schema': writer}))!
            as Map)['accept']['fingerprint'];
    expect(
      await output('decode_record', {
        'writer_schema': writer,
        'reader_schema': null,
        'body': 'c301${fingerprint}02',
      }),
      {
        'accept': {
          'value': {'n': 1},
        },
      },
    );
  });

  test('resolve_date_time and add_duration', () async {
    const floating = {
      'year': 2026,
      'month': 7,
      'day': 1,
      'hour': 10,
      'minute': 0,
      'second': 0,
      'millisecond': 0,
      'zone': null,
      'offset_seconds': null,
      'instant_ms': null,
    };
    expect(
      await output('resolve_date_time', {
        'date_time': floating,
        'anchor': 'local',
      }),
      {
        'accept': {'date_time': floating},
      },
    );
    expect(
      await output('resolve_date_time', {
        'date_time': floating,
        'anchor': 'instant',
      }),
      {
        'accept': {'date_time': floating},
      },
    );
    expect(
      await run('resolve_date_time', {'date_time': floating, 'anchor': 'x'}),
      containsPair('failure', isA<String>()),
    );
    expect(
      await run('resolve_date_time', {'date_time': 1, 'anchor': 'local'}),
      containsPair('failure', isA<String>()),
    );
    const none = {'months': 0, 'days': 0, 'millis': 0};
    expect(
      await output('add_duration', {'date_time': floating, 'duration': none}),
      {
        'accept': {'date_time': floating},
      },
    );
    expect(
      await run('add_duration', {
        'date_time': {...floating, 'year': 9999, 'month': 12},
        'duration': {...none, 'months': 1},
      }),
      containsPair('failure', isA<String>()),
    );
  });
}
