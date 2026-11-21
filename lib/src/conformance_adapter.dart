/// The answers of the conformance adapter (AXT `spec/conformance.md`,
/// section 6). Not exported: only `tool/adapter.dart` uses it.
library;

import 'dart:io';
import 'dart:typed_data';

import 'package:avro/avro.dart';
import 'package:crypto/crypto.dart';

import '../axt_protocol.dart';
import 'envelope.dart';
import 'record_decoder.dart';
import 'zone_rules.dart';
import 'device_sets.dart';
import 'ed25519.dart' as ed25519;
import 'file_reader.dart';
import 'live_session.dart';
import 'manifest.dart';
import 'records.dart';
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
  'records',
  'file',
  'protocol',
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
  'apply': _apply,
  'read_file': _readFile,
  'choose_format': _chooseFormat,
  'contact_key': _contactKey,
  'resend_after_removal': _resendAfterRemoval,
  'session': _session,
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

RecordPolicy _policy(Object? value) {
  if (value is! Map<String, Object?>) {
    throw const _BadRequest('policy is no object');
  }
  return RecordPolicy(
    localChanges: switch (value['local_changes']) {
      'per_field' => LocalChanges.perField,
      'whole_record_keep' => LocalChanges.wholeRecordKeep,
      'whole_record_take' => LocalChanges.wholeRecordTake,
      final other => throw _BadRequest('no policy $other'),
    },
    deleteWithLocalChanges: switch (value['delete_with_local_changes']) {
      'delete' => DeleteWithLocalChanges.delete,
      'keep' => DeleteWithLocalChanges.keep,
      final other => throw _BadRequest('no policy $other'),
    },
  );
}

/// One receiver and the records of one sender, starting empty (records.md,
/// sections 5 to 7); its user's changes are kept as the current values.
Future<Map<String, Object?>> _apply(Map<String, Object?> input) async {
  final policy = _policy(input['policy']);
  final events = input['events'];
  if (events is! List<Object?>) throw const _BadRequest('events is no list');
  final held = <String, HeldRecord>{};
  final current = <String, Map<String, Object?>?>{};
  final steps = <Object?>[];
  for (final event in events) {
    if (event is! Map<String, Object?>) {
      throw const _BadRequest('an event is no object');
    }
    final message = event['message'];
    final change = event['local_change'];
    final delete = event['local_delete'];
    if (change is Map<String, Object?>) {
      final key = recordKey(_string(change, 'id'));
      current[key] = {
        ...?current[key],
        _string(change, 'field'): change['value'],
      };
      steps.add(<String, Object?>{});
    } else if (delete is Map<String, Object?>) {
      final key = recordKey(_string(delete, 'id'));
      final record = held[key]!;
      held[key] = HeldRecord(
        version: record.version,
        state: HeldState.deletedByUser,
        type: record.type,
      );
      current[key] = null;
      steps.add(<String, Object?>{});
    } else if (message is Map<String, Object?>) {
      try {
        final key = recordKey(_string(message, 'id'));
        final version = message['version'];
        if (version is! int) throw const _BadRequest('version is no integer');
        final applied = applyRecordMessage(
          held: held[key],
          current: current[key],
          kind: switch (message['kind']) {
            'DATA' => RecordKind.data,
            'DELETE' => RecordKind.delete,
            'WITHDRAW' => RecordKind.withdraw,
            final other => throw _BadRequest('no record kind $other'),
          },
          version: version,
          policy: policy,
          type: message['type'] as String?,
          value: message['value'] as Map<String, Object?>?,
        );
        held[key] = applied.held;
        current[key] = applied.value;
        steps.add({
          'outcome': applied.outcome.code,
          'receiver_version': applied.held.version,
          'kept_fields': applied.keptFields,
          'state': applied.held.state.code,
          'value': applied.value,
        });
      } on AxtException catch (e) {
        steps.add({'error': e.code.code});
      }
    } else {
      throw const _BadRequest('an event of no known form');
    }
  }
  return {'steps': steps};
}

Map<String, String> _schemaTexts(Object? value) {
  if (value is! Map<String, Object?> || value.values.any((v) => v is! String)) {
    throw const _BadRequest('readers is not an object of schema texts');
  }
  return value.cast<String, String>();
}

/// Reads a file as a reader whose user accepted its sender, that knows the
/// sender by the key in `axt.sender` alone and holds no record of it yet.
Future<Map<String, Object?>> _readFile(Map<String, Object?> input) async {
  final readerInput = _object(input, 'reader');
  final keys = readerInput['keys'];
  final ownKeys = keys is Map<String, Object?> ? keys : null;
  final reader = FileReader(
    manifest:
        decodeBody(Kind.manifest, _bytes(readerInput['manifest']))!
            as Map<String, Object?>,
    readers: _schemaTexts(readerInput['readers'] ?? <String, Object?>{}),
    current: ownKeys == null ? const {} : _keys(ownKeys['current']),
    removed: ownKeys == null ? const {} : _keys(ownKeys['removed']),
  );
  final CheckedFile file;
  try {
    file = await checkFile(_bytes(input['file']));
  } on AxtException catch (e) {
    return _reject(e.code.code);
  }
  final sender = _hex(file.sender);
  final receiver = DeviceSetReceiver(
    senders: [
      KnownSender('sender', current: {sender}),
    ],
  );
  final outcome = await receiver.receiveChain(file.chain);
  final chain = [
    for (var i = 0; i < file.chain.length; i++)
      () {
        final change = DeviceChange.decode(file.chain[i]);
        return {
          'kind': change.kind.symbol,
          'signer': _hex(change.signer),
          'device': _hex(change.device),
          'result': outcome.results[i].code,
        };
      }(),
  ];
  final removed = receiver.stateOf(sender) == KeyState.removed;
  final manifestBody = file.manifest;
  String manifest;
  if (manifestBody == null) {
    manifest = 'none';
  } else {
    try {
      await checkManifest(manifestBody, 1);
      manifest = 'used';
    } on AxtException {
      manifest = 'invalid';
    }
  }
  final List<Map<String, Object?>> records;
  if (removed) {
    records = [
      for (final message in file.records)
        {
          'id': message.envelope.record!.id,
          'version': message.envelope.record!.version,
          'result': 'SENDER_REMOVED',
        },
    ];
  } else {
    records = [
      for (final result in await readFileRecords(
        file,
        reader,
        held: {},
        current: {},
      ))
        {'id': result.id, 'version': result.version, 'result': result.result},
    ];
  }
  return _accept({
    'sender': sender,
    'chain': chain,
    'manifest': manifest,
    'records': records,
  });
}

List<int> _ints(Object? value) {
  if (value is! List<Object?> || value.any((v) => v is! int)) {
    throw const _BadRequest('not a list of integers');
  }
  return value.cast<int>();
}

Future<Map<String, Object?>> _chooseFormat(Map<String, Object?> input) async {
  final theirs = _ints(input['theirs']).toSet();
  final common = [
    for (final f in _ints(input['own']))
      if (theirs.contains(f)) f,
  ];
  return _accept({
    'format': common.isEmpty ? null : common.reduce((a, b) => a > b ? a : b),
  });
}

/// The key to which a sender offers (protocol.md, section 9.1).
Future<Map<String, Object?>> _contactKey(Map<String, Object?> input) async {
  final current = _keys(input['current']);
  final manifests = _keys(input['manifests']);
  final got = input['got'];
  if (got is! List<Object?>) throw const _BadRequest('got is no list');
  String? last;
  for (final message in got.cast<Map<String, Object?>>()) {
    final key = _string(message, 'key');
    final kind = message['kind'];
    if (!current.contains(key) ||
        !manifests.contains(key) ||
        kind == 'DEVICE_ADD' ||
        kind == 'DEVICE_REMOVE' ||
        kind == 'MANIFEST') {
      continue;
    }
    last = key;
  }
  final keys = last != null
      ? [last]
      : ([
          for (final key in current)
            if (manifests.contains(key)) key,
        ]..sort());
  return _accept({'keys': keys});
}

Future<Map<String, Object?>> _resendAfterRemoval(
  Map<String, Object?> input,
) async {
  final removed = _keys(input['removed']);
  final records = input['records'];
  if (records is! List<Object?>) throw const _BadRequest('records is no list');
  return _accept({
    'ids': [
      for (final record in records.cast<Map<String, Object?>>())
        if (((record['outcomes'] ?? <String, Object?>{})
                as Map<String, Object?>)
            .keys
            .every(removed.contains))
          record['id'],
    ],
  });
}

Future<Map<String, Object?>> _session(Map<String, Object?> input) async {
  final appInput = _object(input, 'app');
  final takes = appInput['user_takes'];
  if (takes is! List<Object?>) throw const _BadRequest('user_takes is no list');
  final app = await LiveApp.open(
    seed: _bytes(appInput['seed']),
    manifestBody: _bytes(appInput['manifest']),
    formats: _ints(appInput['formats']),
    readers: _schemaTexts(appInput['readers'] ?? <String, Object?>{}),
    userTakes: takes.cast<String>().toSet(),
    peer: _bytes(appInput['peer']),
  );
  final steps = input['steps'];
  if (steps is! List<Object?>) throw const _BadRequest('steps is no list');
  final answers = <Object?>[];
  for (final step in steps.cast<Map<String, Object?>>()) {
    if (step.containsKey('receive')) {
      final received = await app.receive(_bytes(step['receive']));
      answers.add({
        'outcome': received.outcome?.code,
        'close': received.close,
        'replies': [for (final r in received.replies) _hex(r)],
      });
    } else if (step.containsKey('flush_acks')) {
      final (_, replies) = await app.flushAcks();
      answers.add({
        'replies': [for (final r in replies) _hex(r)],
      });
    } else if (step.containsKey('offer')) {
      final offer = _object(step, 'offer');
      final types = offer['types'];
      if (types is! List<Object?>) throw const _BadRequest('types is no list');
      final message = await app.offer(_string(offer, 'offer_id'), [
        for (final t in types.cast<Map<String, Object?>>())
          (schema: _string(t, 'schema'), count: t['count']! as int),
      ]);
      answers.add({'message': _hex(message)});
    } else if (step.containsKey('close')) {
      app.closeConnection();
      answers.add(<String, Object?>{});
    } else if (step.containsKey('query')) {
      final query = _object(step, 'query');
      if (query.containsKey('accepted')) {
        answers.add({'accepted': app.accepted(_string(query, 'accepted'))});
      } else if (query.containsKey('outcome')) {
        final of = _object(query, 'outcome');
        answers.add({
          'outcome': app
              .outcomeOf(_string(of, 'id'), of['version']! as int)
              ?.code,
        });
      } else if (query.containsKey('record')) {
        final held = app.record(_string(query, 'record'));
        answers.add({
          'record': held == null
              ? null
              : {'version': held.version, 'state': held.state.code},
        });
      } else {
        answers.add({'errors': app.errors});
      }
    } else {
      throw const _BadRequest('a step of no known form');
    }
  }
  return {'steps': answers};
}
