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
import 'record_decoder.dart';
import 'zone_rules.dart';
import 'device_sets.dart';
import 'ed25519.dart' as ed25519;
import 'manifest.dart';
import 'sealing.dart' as sealing;
import 'signing.dart';

/// The categories of `spec/conformance.md`, section 2.1, that the adapter
/// answers. A category is listed only once all of its vectors pass.
const List<String> implementedCategories = [
  'encoding',
  'types',
  'time',
  'keys',
  'manifest',
];

/// The version of the vector file format the adapter reads.
const int vectorFormat = 1;

/// A request the adapter cannot read: a fault of the input, not of the library.
final class _BadRequest implements Exception {
  const _BadRequest(this.message);
  final String message;
}

/// Answers one request of the runner.
Future<Map<String, Object?>> answer(Object? request) async {
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
    return {'id': id, 'output': await operation(input)};
  } on AxtException catch (e) {
    return {
      'id': id,
      'output': {
        'reject': {
          'error': e.code.code,
          if (e.code == ErrorCode.valueInvalid) 'field': e.field,
        },
      },
    };
  } on _BadRequest catch (e) {
    return {'id': id, 'failure': e.message};
  }
}

typedef _Operation = Future<Map<String, Object?>> Function(
  Map<String, Object?> input,
);

final Map<String, _Operation> _operations = {
  'fingerprint': _fingerprint,
  'decode_message': _decodeMessage,
  'decode_body': _decodeBody,
  'encode_message': _encodeMessage,
  'decode_record': _decodeRecord,
  'resolve_date_time': _resolveDateTime,
  'add_duration': _addDuration,
  'public_key': _publicKey,
  'sign': _sign,
  'verify': _verify,
  'check_signing_key': _checkSigningKey,
  'check_encryption_key': _checkEncryptionKey,
  'short_fingerprint': _shortFingerprint,
  'verify_message': _verifyMessage,
  'device_add': _deviceAdd,
  'device_join': _deviceJoin,
  'join_chain': _joinChain,
  'device_sets': _deviceSets,
  'padded_length': _paddedLength,
  'seal': _seal,
  'open': _open,
  'check_manifest': _checkManifest,
  'fit': _fit,
};

/// The zone rules of the vectors: the IANA time zone database 2026e.
final ZoneRules _rules = TzdbZoneRules();

Map<String, Object?> _accept(Object? value) => {'accept': value};

Future<Map<String, Object?>> _fingerprint(Map<String, Object?> input) async {
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

Future<Map<String, Object?>> _decodeMessage(Map<String, Object?> input) async {
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

Future<Map<String, Object?>> _decodeBody(Map<String, Object?> input) async {
  final kind = Kind.ofSymbol(_string(input, 'kind'));
  if (kind.bodySchema == null) {
    throw _BadRequest('decode_body takes no ${kind.symbol}');
  }
  return _accept({'value': _json(decodeBody(kind, _bytes(input['body'])))});
}

Future<Map<String, Object?>> _encodeMessage(Map<String, Object?> input) async {
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

Future<Map<String, Object?>> _decodeRecord(Map<String, Object?> input) async {
  final reader = input['reader_schema'];
  if (reader != null && reader is! String) {
    throw const _BadRequest('reader_schema is neither a string nor null');
  }
  final value = decodeRecord(
    parseTypeSchema(_string(input, 'writer_schema')),
    reader == null ? null : parseTypeSchema(reader as String),
    _bytes(input['body']),
  );
  return _accept({'value': _json(value)});
}

Map<String, Object?> _object(Map<String, Object?> input, String name) {
  final value = input[name];
  if (value is! Map<String, Object?>) {
    throw _BadRequest('$name is not an object');
  }
  return value;
}

Future<Map<String, Object?>> _resolveDateTime(
  Map<String, Object?> input,
) async {
  final anchor = switch (input['anchor']) {
    'local' => Anchor.local,
    'instant' => Anchor.instant,
    final other => throw _BadRequest('no anchor $other'),
  };
  return _accept({
    'date_time': resolveDateTime(_rules, _object(input, 'date_time'), anchor),
  });
}

Future<Map<String, Object?>> _addDuration(Map<String, Object?> input) async {
  try {
    return _accept({
      'date_time': addDuration(
        _rules,
        _object(input, 'date_time'),
        _object(input, 'duration'),
      ),
    });
  } on RangeError catch (e) {
    throw _BadRequest('the sum is out of range: ${e.message}');
  }
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

Map<String, Object?> _reject(String code) => {
  'reject': {'error': code},
};

Future<Map<String, Object?>> _publicKey(Map<String, Object?> input) async =>
    _accept({
      'public_key': _hex(await ed25519.publicKeyOf(_bytes(input['seed']))),
    });

Future<Map<String, Object?>> _sign(Map<String, Object?> input) async =>
    _accept({
      'signature': _hex(
        await ed25519.sign(_bytes(input['seed']), _bytes(input['data'])),
      ),
    });

Future<Map<String, Object?>> _verify(Map<String, Object?> input) async {
  final verifies = await ed25519.verifyStrict(
    _bytes(input['public_key']),
    _bytes(input['data']),
    _bytes(input['signature']),
  );
  return verifies ? _accept(<String, Object?>{}) : _reject('SIGNATURE_INVALID');
}

Future<Map<String, Object?>> _checkSigningKey(
  Map<String, Object?> input,
) async => ed25519.isPointOfOrderL(_bytes(input['public_key']))
    ? _accept(<String, Object?>{})
    : _reject('KEY_INVALID');

Future<Map<String, Object?>> _checkEncryptionKey(
  Map<String, Object?> input,
) async =>
    await sealing.isSmallOrderEncryptionKey(_bytes(input['encryption_key']))
    ? _reject('ENCRYPTION_KEY_INVALID')
    : _accept(<String, Object?>{});

Future<Map<String, Object?>> _shortFingerprint(
  Map<String, Object?> input,
) async => _accept({
  'short_fingerprint': shortFingerprint(_bytes(input['public_key'])),
});

Future<Map<String, Object?>> _verifyMessage(Map<String, Object?> input) async {
  final message = _bytes(input['message']);
  final envelope = decodeMessage(message);
  return await verifyLiveMessage(message, envelope.sender)
      ? _accept(<String, Object?>{})
      : _reject('SIGNATURE_INVALID');
}

Future<Map<String, Object?>> _deviceAdd(Map<String, Object?> input) async {
  final change = DeviceChange.decode(_bytes(input['message']));
  if (!change.isAdd) throw const _BadRequest('not a DEVICE_ADD');
  if (!await change.signatureVerifies()) return _reject('SIGNATURE_INVALID');
  if (!await change.deviceVerifies()) return _reject('DEVICE_REJECTED');
  return _accept({
    'member': _hex(change.signer),
    'device': _hex(change.device),
  });
}

Set<String> _keys(Object? value) {
  if (value is! List<Object?> || value.any((k) => k is! String)) {
    throw const _BadRequest('keys are not a list of strings');
  }
  return {for (final key in value) key! as String};
}

Future<Map<String, Object?>> _deviceJoin(Map<String, Object?> input) async {
  final message = _bytes(input['message']);
  final member = _object(input, 'member');
  final first = input['first'];
  final JoinAction action;
  try {
    action = await answerDeviceJoin(
      message,
      member: _bytes(member['key']),
      current: _keys(member['current']),
      removed: _keys(member['removed']),
      first: first == null ? null : _bytes(first),
    );
  } on AxtException catch (e) {
    return _reject(e.code.code);
  }
  return _accept({
    'device': _hex(decodeMessage(message).sender),
    'action': switch (action) {
      JoinAction.ask => 'ask',
      JoinAction.sendChain => 'send_chain',
      JoinAction.ignore => 'ignore',
    },
  });
}

List<Uint8List> _chain(Object? value) {
  if (value is! List<Object?>) throw const _BadRequest('chain is not a list');
  return [for (final message in value) _bytes(message)];
}

Future<Map<String, Object?>> _joinChain(Map<String, Object?> input) async {
  final takes = await takesJoinChain(
    _chain(input['chain']),
    member: _bytes(input['member']),
    device: _bytes(input['device']),
  );
  return takes ? _accept(<String, Object?>{}) : _reject('JOIN_INVALID');
}

KnownSender _knownSender(Object? value) {
  if (value is! Map<String, Object?>) {
    throw const _BadRequest('a sender is not an object');
  }
  final records = value['records'];
  if (records is! List<Object?>) throw const _BadRequest('records is no list');
  return KnownSender(
    _string(value, 'name'),
    current: _keys(value['current']),
    removed: _keys(value['removed']),
    records: {
      for (final record in records.cast<Map<String, Object?>>())
        _string(record, 'id'): KeptRecord(
          record['version']! as int,
          record['state'] == 'tombstone'
              ? RecordState.tombstone
              : RecordState.there,
        ),
    },
  );
}

List<Map<String, Object?>> _senders(DeviceSetReceiver receiver) {
  final senders = List.of(receiver.senders)
    ..sort((a, b) => a.name.compareTo(b.name));
  return [
    for (final sender in senders)
      {
        'name': sender.name,
        'current': sender.current.toList()..sort(),
        'removed': sender.removed.toList()..sort(),
        'records': [
          for (final id in sender.records.keys.toList()..sort())
            {
              'id': id,
              'version': sender.records[id]!.version,
              'state': sender.records[id]!.state.name,
            },
        ],
      },
  ];
}

Future<Map<String, Object?>> _deviceSets(Map<String, Object?> input) async {
  final senders = input['senders'];
  final steps = input['steps'];
  if (senders is! List<Object?> || steps is! List<Object?>) {
    throw const _BadRequest('senders and steps must be lists');
  }
  final receiver = DeviceSetReceiver(
    senders: [for (final sender in senders) _knownSender(sender)],
    refused: _keys(input['refused']),
  );
  final results = <Map<String, Object?>>[];
  for (final step in steps) {
    if (step is! Map<String, Object?>) {
      throw const _BadRequest('a step is no object');
    }
    final outcome = await receiver.receiveChain(_chain(step['chain']));
    final key = step['key'];
    if (key != null && key is! String) {
      throw const _BadRequest('key is no string');
    }
    final state = key == null ? null : receiver.stateOf(key as String);
    results.add({
      'results': [for (final result in outcome.results) result.code],
      'key_state': state?.name,
      'key_sender': key == null
          ? null
          : receiver.currentSenderOf(key as String)?.name,
      'senders': _senders(receiver),
    });
  }
  return {'steps': results};
}

Future<Map<String, Object?>> _paddedLength(Map<String, Object?> input) async {
  final length = input['length'];
  if (length is! int) throw const _BadRequest('length is no integer');
  return _accept({'padded_length': sealing.paddedLength(length)});
}

Future<Map<String, Object?>> _seal(Map<String, Object?> input) async =>
    _accept({
      'sealed': _hex(
        await sealing.seal(
          _bytes(input['message']),
          _bytes(input['encryption_key']),
        ),
      ),
    });

Future<Map<String, Object?>> _open(Map<String, Object?> input) async {
  final keys = input['private_keys'];
  if (keys is! List<Object?>) {
    throw const _BadRequest('private_keys is no list');
  }
  return _accept({
    'message': _hex(
      await sealing.open(_bytes(input['sealed']), [
        for (final k in keys) _bytes(k),
      ]),
    ),
  });
}

Future<Map<String, Object?>> _checkManifest(Map<String, Object?> input) async {
  final format = input['envelope_format'];
  if (format is! int) throw const _BadRequest('envelope_format is no integer');
  return _accept({
    'manifest': _json(await checkManifest(_bytes(input['body']), format)),
  });
}

Future<Map<String, Object?>> _fit(Map<String, Object?> input) async {
  final languages = input['languages'];
  if (languages is! List<Object?> || languages.any((l) => l is! String)) {
    throw const _BadRequest('languages is not a list of strings');
  }
  final manifest =
      decodeBody(Kind.manifest, _bytes(input['manifest']))!
          as Map<String, Object?>;
  final result = fit(
    manifest,
    _string(input, 'schema'),
    languages.cast<String>(),
  );
  return _accept({'fits': result.fits, 'purpose': result.purpose});
}
