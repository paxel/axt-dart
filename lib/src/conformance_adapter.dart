/// The answers of the conformance adapter (AXT `spec/conformance.md`,
/// section 6). Not exported: only `tool/adapter.dart` uses it.
library;

import 'dart:io';
import 'dart:typed_data';

import 'package:avro/avro.dart';
import 'package:crypto/crypto.dart';

import '../axt_protocol.dart';
import 'envelope.dart';
import 'errors.dart';

/// The categories of `spec/conformance.md`, section 2.1, that the adapter
/// answers. A category is listed only once all of its vectors pass.
const List<String> implementedCategories = ['encoding'];

/// The version of the vector file format the adapter reads.
const int vectorFormat = 1;

/// A request the adapter cannot read: a fault of the input, not of the library.
final class _BadRequest implements Exception {
  const _BadRequest(this.message);
  final String message;
}

/// Answers one request of the runner.
Map<String, Object?> answer(Object? request) {
  if (request is! Map<String, Object?>) {
    return {'id': null, 'failure': 'the request is not a JSON object'};
  }
  final id = request['id'];
  final op = request['op'];
  final input = request['input'];
  final operation = _operations[op];
  if (op == 'hello') {
    final format = input is Map<String, Object?> ? input['format'] : null;
    if (format != vectorFormat) {
      return {
        'id': id,
        'failure': 'vector format $format is not $vectorFormat',
      };
    }
    return {
      'id': id,
      'output': {
        'name': 'axt_protocol (AXT $axtVersion)',
        'categories': implementedCategories,
      },
    };
  }
  if (operation == null) return {'id': id, 'unsupported': true};
  if (input is! Map<String, Object?>) {
    return {'id': id, 'failure': 'the input is not a JSON object'};
  }
  try {
    return {'id': id, 'output': operation(input)};
  } on AxtException catch (e) {
    return {
      'id': id,
      'output': {
        'reject': {'error': e.code.code},
      },
    };
  } on _BadRequest catch (e) {
    return {'id': id, 'failure': e.message};
  }
}

typedef _Operation = Map<String, Object?> Function(Map<String, Object?> input);

final Map<String, _Operation> _operations = {
  'fingerprint': _fingerprint,
  'decode_message': _decodeMessage,
  'decode_body': _decodeBody,
  'encode_message': _encodeMessage,
};

Map<String, Object?> _accept(Object? value) => {'accept': value};

Map<String, Object?> _fingerprint(Map<String, Object?> input) {
  final Schema schema;
  try {
    schema = Schema.parse(_string(input, 'schema'));
  } on AvroException catch (e) {
    throw _BadRequest('not a schema: ${e.message}');
  }
  return _accept({
    'canonical_form': schema.canonicalForm,
    'fingerprint': _hex(crc64ToBytes(schema.crc64)),
  });
}

Map<String, Object?> _decodeMessage(Map<String, Object?> input) {
  final envelope = decodeMessage(_bytes(input['message']));
  final record = envelope.record;
  return _accept({
    'format': envelope.format,
    'kind': envelope.kind.symbol,
    'sender': _hex(envelope.sender),
    'record': record == null
        ? null
        : {'id': record.id, 'version': record.version},
    'body': _hex(envelope.body),
    'signature': _hex(envelope.signature),
  });
}

Map<String, Object?> _decodeBody(Map<String, Object?> input) {
  final kind = Kind.ofSymbol(_string(input, 'kind'));
  if (kind.bodySchema == null) {
    throw _BadRequest('decode_body takes no ${kind.symbol}');
  }
  return _accept({'value': _json(decodeBody(kind, _bytes(input['body'])))});
}

Map<String, Object?> _encodeMessage(Map<String, Object?> input) {
  final record = input['record'];
  final RecordRef? ref;
  if (record == null) {
    ref = null;
  } else if (record is Map<String, Object?> &&
      record['id'] is String &&
      record['version'] is int) {
    ref = RecordRef(record['id']! as String, record['version']! as int);
  } else {
    throw const _BadRequest('record is neither null nor an id and a version');
  }
  if (input['format'] != 1) {
    throw _BadRequest('format ${input['format']} is not 1');
  }
  final message = encodeMessage(
    Envelope(
      kind: Kind.ofSymbol(_string(input, 'kind')),
      sender: _bytes(input['sender']),
      record: ref,
      body: _bytes(input['body']),
      signature: _bytes(input['signature']),
    ),
  );
  return _accept({'message': _hex(message)});
}

String _string(Map<String, Object?> input, String name) {
  final value = input[name];
  if (value is! String) throw _BadRequest('$name is not a string');
  return value;
}

/// Bytes in either form of `spec/conformance.md`, section 3.2.
Uint8List _bytes(Object? value) {
  if (value is String) return _unhex(value);
  if (value is Map<String, Object?>) {
    final deflated = value['deflate'];
    final length = value['length'];
    final digest = value['sha256'];
    if (deflated is! String || length is! int || digest is! String) {
      throw const _BadRequest('bytes need deflate, length and sha256');
    }
    final bytes = Uint8List.fromList(
      ZLibDecoder(raw: true).convert(_unhex(deflated)),
    );
    if (bytes.length != length || _hex(sha256.convert(bytes).bytes) != digest) {
      throw const _BadRequest(
        'the inflated bytes do not match length and sha256',
      );
    }
    return bytes;
  }
  throw const _BadRequest('bytes are neither a hex string nor deflated');
}

Uint8List _unhex(String text) {
  if (text.length.isOdd) throw const _BadRequest('hex of odd length');
  final out = Uint8List(text.length ~/ 2);
  for (var i = 0; i < out.length; i++) {
    final byte = int.tryParse(text.substring(2 * i, 2 * i + 2), radix: 16);
    if (byte == null) throw const _BadRequest('not hex');
    out[i] = byte;
  }
  return out;
}

String _hex(List<int> bytes) {
  final out = StringBuffer();
  for (final b in bytes) {
    out.write(b.toRadixString(16).padLeft(2, '0'));
  }
  return out.toString();
}

/// A decoded Avro value in the JSON form of `spec/conformance.md`, section 3.3.
Object? _json(Object? value) => switch (value) {
  Uint8List() => _hex(value),
  Map<String, Object?>() => {
    for (final entry in value.entries) entry.key: _json(entry.value),
  },
  List<Object?>() => [for (final item in value) _json(item)],
  _ => value,
};
