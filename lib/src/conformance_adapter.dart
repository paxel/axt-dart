/// The answers of the conformance adapter (AXT `spec/conformance.md`,
/// section 6). Not exported: only `tool/adapter.dart` uses it.
library;

import 'dart:io';
import 'dart:typed_data';

import 'package:avro/avro.dart';
import 'package:crypto/crypto.dart';

import '../axt_protocol.dart';
import 'bricks.dart';
import 'envelope.dart';
import 'record_decoder.dart';
import 'zone_rules.dart';
import 'device_sets.dart';
import 'ed25519.dart' as ed25519;
import 'file_reader.dart';
import 'links.dart';
import 'live_session.dart';
import 'manifest.dart';
import 'proposals.dart';
import 'records.dart';
import 'relation_index.dart';
import 'sealing.dart' as sealing;
import 'shares.dart';
import 'signing.dart';

/// The categories of `spec/conformance.md`, section 2.1, that the adapter
/// answers. A category is listed only once all of its vectors pass.
const List<String> implementedCategories = [
  'encoding',
  'bricks',
  'types',
  'time',
  'keys',
  'manifest',
  'records',
  'file',
  'protocol',
  'shares',
];

/// Categories under construction that a local run asks for too, with
/// `tool/adapter.dart --also <category>`; never set in CI.
final List<String> extraCategories = [];

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
        'categories': [...implementedCategories, ...extraCategories],
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
  'derive': _derive,
  'describe': _describe,
  'check_record': _checkRecord,
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
  'relations': _relations,
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
  'receive': _apply,
  'take_version': _takeVersion,
  'owed': _owed,
  'acked': _acked,
  'pass_withdrawal': _passWithdrawal,
  'join_receivers': _joinReceivers,
  'offer_types': _offerTypes,
  'shared_value': _sharedValue,
  'owner': _owner,
  'proposer': _proposer,
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

Future<Map<String, Object?>> _derive(Map<String, Object?> input) async {
  final text = deriveSchema(decodeDescription(_bytes(input['description'])));
  final schema = Schema.parse(text);
  return _accept({
    'schema': text,
    'canonical_form': schema.canonicalForm,
    'fingerprint': _hex(crc64ToBytes(schema.crc64)),
  });
}

Future<Map<String, Object?>> _describe(Map<String, Object?> input) async {
  final description = decodeDescription(_bytes(input['description']));
  validateDescription(description);
  final languages = input['languages'];
  if (languages is! List<Object?> || languages.any((l) => l is! String)) {
    throw const _BadRequest('languages is not a list of strings');
  }
  final tags = languages.cast<String>();
  final path = input['field'];
  if (path == null) {
    final root =
        (description['kind']! as Branch).value! as Map<String, Object?>;
    return _accept(
      describeObject(description['texts']! as Map<String, Object?>, root, tags),
    );
  }
  if (path is! String) throw const _BadRequest('field is not a string');
  final field = fieldAt(description, path);
  if (field == null) throw _BadRequest('no field $path');
  return _accept(describeField(field, tags));
}

Future<Map<String, Object?>> _checkRecord(Map<String, Object?> input) async {
  checkRecord(
    decodeDescription(_bytes(input['description'])),
    _bytes(input['body']),
  );
  return _accept(<String, Object?>{});
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
  Branch(:final name, :final value) => {name: _json(value)},
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

Future<Map<String, Object?>> _relations(Map<String, Object?> input) async {
  final senders = input['senders'];
  final relations = input['relations'];
  final steps = input['steps'];
  if (senders is! List<Object?> ||
      relations is! List<Object?> ||
      steps is! List<Object?>) {
    throw const _BadRequest('senders, relations and steps must be lists');
  }
  final receiver = DeviceSetReceiver(
    senders: [for (final sender in senders) _knownSender(sender)],
    refused: _keys(input['refused']),
  );
  final resolver = RelationResolver(receiver, _knownSender(input['own']));
  final held = <HeldRelation>[
    for (final r in relations.cast<Map<String, Object?>>())
      (
        id: _string(r, 'id'),
        holderSender: _string(_object(r, 'holder'), 'sender'),
        holderId: _string(_object(r, 'holder'), 'id'),
        targetSender: _object(r, 'target')['sender'] as String?,
        targetId: _string(_object(r, 'target'), 'id'),
      ),
  ];
  final results = <Map<String, Object?>>[];
  for (final step in steps.cast<Map<String, Object?>>()) {
    if (step.containsKey('chain')) {
      final outcome = await receiver.receiveChain(_chain(step['chain']));
      results.add({
        'results': [for (final result in outcome.results) result.code],
      });
      continue;
    }
    results.add({
      'relations': [
        for (final relation in held)
          {'id': relation.id, ...resolver.resolveJson(relation)},
      ],
      'linked_from': [
        for (final linked in resolver.linkedFrom(held))
          {
            'sender': linked.sender,
            'id': linked.id,
            'from': [
              for (final f in linked.from)
                {'sender': f.sender, 'id': f.id, 'relation': f.relation},
            ],
          },
      ],
    });
  }
  return {'steps': results};
}

extension on RelationResolver {
  Map<String, Object?> resolveJson(HeldRelation relation) {
    final resolution = resolve(relation);
    return {'sender': resolution.sender, 'resolved': resolution.resolved};
  }
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

DeleteWithLocalChanges _removalPolicy(Object? value) => switch (value) {
  'delete' => DeleteWithLocalChanges.delete,
  'keep' => DeleteWithLocalChanges.keep,
  final other => throw _BadRequest('no policy $other'),
};

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
    deleteWithLocalChanges: _removalPolicy(value['delete_with_local_changes']),
    withdrawWithLocalChanges: value['withdraw_with_local_changes'] == null
        ? null
        : _removalPolicy(value['withdraw_with_local_changes']),
  );
}

Map<String, Object?> _step(Applied applied) => {
  'outcome': applied.outcome.code,
  'receiver_version': applied.held.version,
  'kept_fields': applied.keptFields,
  'state': applied.held.state.code,
  'value': _json(applied.value),
};

/// Whether [value] is an extension in the JSON form of the vectors.
bool _isExtension(Object? value) =>
    value is Map<String, Object?> &&
    value.length == 2 &&
    value['name'] is String &&
    value['data'] is String;

/// [value] with the data of its extensions as bytes.
Object? _extensionBytes(Object? value) => switch (value) {
  final Map<String, Object?> e when _isExtension(e) => {
    'name': e['name'],
    'data': _unhex(e['data']! as String),
  },
  Map<String, Object?>() => {
    for (final entry in value.entries) entry.key: _extensionBytes(entry.value),
  },
  List<Object?>() => [for (final v in value) _extensionBytes(v)],
  _ => value,
};

/// The record as the sender sends it to one receiver (shares.md, section
/// 19.1); relations and extensions are found by their shape, as the input
/// has no schema.
Future<Map<String, Object?>> _sharedValue(Map<String, Object?> input) async {
  final value = _object(input, 'value');
  if (input['own_user'] == true || input['links'] == true) {
    return _accept({'value': value});
  }
  final shared = _strings(input['shared']).toSet();
  final ownKeys = _strings(input['own_keys']).toSet();
  Object? walk(Object? value) => switch (value) {
    final List<Object?> list
        when list.isNotEmpty &&
            list.every((e) => _elementKeyOf(e) == ElementKey.id) =>
      sharedRelations(list, shared: shared, ownKeys: ownKeys),
    final List<Object?> list when list.isNotEmpty && list.every(_isExtension) =>
      const <Object?>[],
    Map<String, Object?>() => {
      for (final MapEntry(:key, value: v) in value.entries) key: walk(v),
    },
    List<Object?>() => [for (final v in value) walk(v)],
    _ => value,
  };
  return _accept({'value': walk(value)});
}

/// The key of [element] when it is an element of a list merged per
/// element: a relation or an extension.
ElementKey? _elementKeyOf(Object? element) => switch (element) {
  {'id': String(), 'target': Map()} => ElementKey.id,
  {'name': String(), 'data': Uint8List()} when (element as Map).length == 2 =>
    ElementKey.name,
  _ => null,
};

/// The lists of [values] merged per element: those that hold relations or
/// extensions.
Map<String, ElementKey> _elementLists(List<Map<String, Object?>?> values) => {
  for (final value in values)
    if (value != null)
      for (final MapEntry(:key, value: field) in value.entries)
        if (field is List<Object?>)
          for (final element in field)
            if (_elementKeyOf(element) case final ElementKey k) key: k,
};

/// One receiver and the records of one sender, starting empty (records.md,
/// sections 5 to 7); its user's changes are kept as the current values.
Future<Map<String, Object?>> _apply(Map<String, Object?> input) async {
  final policy = _policy(input['policy']);
  final events = input['events'];
  if (events is! List<Object?>) throw const _BadRequest('events is no list');
  final held = <String, HeldRecord>{};
  final current = <String, Map<String, Object?>?>{};
  final steps = <Object?>[];
  final extensions = [
    for (final text in _strings(input['extensions'] ?? <Object?>[]))
      parseTypeSchema(text),
  ];
  for (final event in events) {
    if (event is! Map<String, Object?>) {
      throw const _BadRequest('an event is no object');
    }
    final message = event['message'];
    final change = event['local_change'];
    final delete = event['local_delete'];
    final take = event['local_take'];
    if (take is Map<String, Object?>) {
      final key = recordKey(_string(take, 'id'));
      final kept = held[key];
      final applied = kept == null ? null : takeKeptRemoval(kept);
      if (applied == null) throw const _BadRequest('nothing kept to take');
      held[key] = applied.held;
      current[key] = null;
      steps.add(_step(applied));
    } else if (change is Map<String, Object?>) {
      final key = recordKey(_string(change, 'id'));
      current[key] = {
        ...?current[key],
        _string(change, 'field'): _extensionBytes(change['value']),
      };
      steps.add(<String, Object?>{});
    } else if (delete is Map<String, Object?>) {
      final key = recordKey(_string(delete, 'id'));
      final record = held[key];
      if (record == null) throw const _BadRequest('no record to delete');
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
        final value =
            _extensionBytes(message['value']) as Map<String, Object?>?;
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
          value: value,
          elements: ElementMerge(
            lists: _elementLists([value, current[key], held[key]?.taken]),
            writers: {for (final s in extensions) s.crc64: s},
            own: {for (final s in extensions) (s as NamedSchema).fullName: s},
          ),
        );
        held[key] = applied.held;
        current[key] = applied.value;
        steps.add(_step(applied));
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
          (
            description: descriptionFromJson(t['description']),
            count: t['count']! as int,
          ),
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

int? _version(Object? value) {
  if (value == null) return null;
  if (value is! String) throw const _BadRequest('a version is no decimal text');
  return int.parse(value);
}

String? _text(int? version) => version?.toString();

const Map<Owes, String> _owesCodes = {
  Owes.data: 'DATA',
  Owes.delete: 'DELETE',
  Owes.withdraw: 'WITHDRAW',
  Owes.nothing: 'nothing',
  Owes.newWithdrawal: 'new_withdrawal',
};

const Map<Then, String> _thenCodes = {
  Then.nothing: 'nothing',
  Then.newWithdrawal: 'new_withdrawal',
  Then.sendState: 'send_state',
  Then.wait: 'wait',
};

RecordKind _recordKind(Object? value) => switch (value) {
  'DATA' => RecordKind.data,
  'DELETE' => RecordKind.delete,
  'WITHDRAW' => RecordKind.withdraw,
  final other => throw _BadRequest('no record kind $other'),
};

Outcome? _outcome(Object? value) =>
    value == null ? null : Outcome.values.firstWhere((o) => o.code == value);

Future<Map<String, Object?>> _takeVersion(Map<String, Object?> input) async {
  final result = takeVersion(
    shareAgain: input['occasion'] == 'share_again',
    highestGiven: _version(input['highest_given'])!,
    stateStamp: _version(input['state_stamp'])!,
  );
  return _accept({
    'version': _text(result.version),
    'state_stamp': _text(result.stateStamp),
  });
}

Future<Map<String, Object?>> _owed(Map<String, Object?> input) async {
  final last = input['last'];
  final result = owed(
    shared: input['shared'] == true,
    deleted: input['deleted'] == true,
    version: _version(input['version'])!,
    withdrawal: _version(input['withdrawal']),
    last: last is Map<String, Object?>
        ? (kind: _recordKind(last['kind']), version: _version(last['version'])!)
        : null,
  );
  return _accept({
    'owes': _owesCodes[result.owes],
    'version': _text(result.version),
  });
}

Future<Map<String, Object?>> _acked(Map<String, Object?> input) async {
  final result = acked(
    sent: _recordKind(input['sent']),
    held: _outcome(input['held']),
    outcome: _outcome(input['outcome'])!,
    receiverVersion: _version(input['receiver_version'])!,
    shared: input['shared'] == true,
    withdrawal: _version(input['withdrawal']),
    stateStamp: _version(input['state_stamp'])!,
    siblingStamp: _version(input['sibling_stamp']),
    sibling: input['sibling'] == true,
  );
  return _accept({
    'outcome': result.outcome.code,
    'then': _thenCodes[result.then],
    'to_pass': _text(result.toPass),
  });
}

Future<Map<String, Object?>> _passWithdrawal(Map<String, Object?> input) async {
  final result = passWithdrawal(
    shared: input['shared'] == true,
    withdrawal: _version(input['withdrawal']),
    toPass: _version(input['to_pass'])!,
    stateStamp: _version(input['state_stamp'])!,
  );
  return _accept({
    'then': _thenCodes[result.then],
    'to_pass': _text(result.toPass),
  });
}

Future<Map<String, Object?>> _joinReceivers(Map<String, Object?> input) async {
  final receivers = input['receivers'];
  if (receivers is! List<Object?>) {
    throw const _BadRequest('receivers is no list');
  }
  final result = joinReceivers([
    for (final r in receivers.cast<Map<String, Object?>>())
      (shared: r['shared'] == true, withdrawal: _version(r['withdrawal'])),
  ]);
  return _accept({
    'shared': result.shared,
    'withdrawal': _text(result.withdrawal),
    'new_state_stamp': result.newStateStamp,
  });
}

Future<Map<String, Object?>> _offerTypes(Map<String, Object?> input) async {
  final records = input['records'];
  if (records is! List<Object?>) throw const _BadRequest('records is no list');
  final owesByCode = {for (final e in _owesCodes.entries) e.value: e.key};
  return _accept({
    'types': [
      for (final t in offerTypes([
        for (final r in records.cast<Map<String, Object?>>())
          (
            type: _string(r, 'type'),
            owes: owesByCode[r['owes']] ?? Owes.nothing,
            delivered: r['delivered'] == true,
          ),
      ]))
        {'type': t.type, 'count': t.count},
    ],
  });
}

List<String> _strings(Object? value) {
  if (value is! List<Object?> || value.any((v) => v is! String)) {
    throw const _BadRequest('not a list of strings');
  }
  return value.cast<String>();
}

/// One installation of the owner of shared records (shares.md, 12 to 18).
Future<Map<String, Object?>> _owner(Map<String, Object?> input) async {
  final device = _object(input, 'device');
  final receivers = [
    for (final r
        in (device['receivers'] as List<Object?>? ?? [])
            .cast<Map<String, Object?>>())
      ProposalReceiver(
        _string(r, 'name'),
        current: _keys(r['current']),
        removed: _keys(r['removed']),
        ownUser: r['own_user'] == true,
      ),
  ];
  final records = [
    for (final r
        in (device['records'] as List<Object?>? ?? [])
            .cast<Map<String, Object?>>())
      OwnRecord(
        id: _string(r, 'id'),
        type: _string(r, 'type'),
        version: _version(r['version'])!,
        deleted: r['state'] == 'deleted',
        value: (r['value'] as Map<String, Object?>?) ?? {},
        shared: _strings(r['shared'] ?? <String>[]).toSet(),
      ),
  ];
  final readers = device['readers'];
  final owner = await ProposalOwner.start(
    seed: _bytes(device['seed']),
    siblings: _keys(device['siblings'] ?? <String>[]),
    proposals: _strings(device['proposals'] ?? <String>[]).toSet(),
    schemas: _strings(device['schemas'] ?? <String>[]),
    receivers: receivers,
    records: records,
    readers: readers == null ? null : _schemaTexts(readers),
    open: [
      for (final o
          in (device['open'] as List<Object?>? ?? [])
              .cast<Map<String, Object?>>())
        OpenProposal(
          receiver: _string(o, 'receiver'),
          proposalId: _string(o, 'proposal_id'),
          id: _string(o, 'id'),
          version: 0,
          valueBytes: (o['value_bytes'] as int?) ?? 0,
        ),
    ],
    answers: [
      for (final a
          in (device['answers'] as List<Object?>? ?? [])
              .cast<Map<String, Object?>>())
        ProposalAnswer(
          _string(a, 'receiver'),
          _string(a, 'proposal_id'),
          _string(a, 'answer'),
          _string(a, 'id'),
          a['version']! as int,
        ),
    ],
    stops: [
      for (final st
          in (device['stopped'] as List<Object?>? ?? [])
              .cast<Map<String, Object?>>())
        (
          receiver: _string(st, 'receiver'),
          id: st['id'] as String?,
          type: st['type'] as String?,
        ),
    ],
  );
  final steps = input['steps'];
  if (steps is! List<Object?>) throw const _BadRequest('steps is no list');
  final out = <Object?>[];
  for (final step in steps.cast<Map<String, Object?>>()) {
    if (step.containsKey('receive')) {
      final r = await owner.receive(_bytes(step['receive']));
      out.add({
        'result': r.result,
        'replies': [for (final m in r.replies) _hex(m)],
      });
    } else if (step.containsKey('answer')) {
      final a = _object(step, 'answer');
      final r = await owner.answer(
        _string(a, 'receiver'),
        _string(a, 'proposal_id'),
        _string(a, 'answer'),
      );
      final update = r.update;
      out.add({
        'made': r.made,
        'replies': [for (final m in r.replies) _hex(m)],
        'update': update == null
            ? null
            : {'version': '${update.version}', 'value': update.value},
      });
    } else if (step.containsKey('answered')) {
      final a = _object(step, 'answered');
      owner.answered(
        _string(a, 'receiver'),
        _string(a, 'proposal_id'),
        _string(a, 'answer'),
        _string(a, 'id'),
        a['version']! as int,
      );
      out.add(<String, Object?>{});
    } else if (step.containsKey('stop')) {
      final st = _object(step, 'stop');
      owner.stop((
        receiver: _string(st, 'receiver'),
        id: st['id'] as String?,
        type: st['type'] as String?,
      ));
      out.add(<String, Object?>{});
    } else if (step.containsKey('change')) {
      final c = _object(step, 'change');
      owner.change(
        _string(c, 'id'),
        _string(c, 'action'),
        c['receiver'] as String?,
      );
      out.add(<String, Object?>{});
    } else if (step.containsKey('manifest')) {
      owner.proposals = _strings(step['manifest']).toSet();
      out.add(<String, Object?>{});
    } else if (step.containsKey('query')) {
      int byKey(Object? a, Object? b) {
        final x = a! as Map<String, Object?>;
        final y = b! as Map<String, Object?>;
        final first = (x['receiver']! as String).compareTo(
          y['receiver']! as String,
        );
        return first != 0
            ? first
            : (x['proposal_id']! as String).compareTo(
                y['proposal_id']! as String,
              );
      }

      out.add({
        'open': [
          for (final p in owner.open)
            {
              'receiver': p.receiver,
              'proposal_id': p.proposalId,
              'id': p.id,
              'message_hash': p.message == null
                  ? null
                  : _hex(sha256.convert(p.message!).bytes),
            },
        ]..sort(byKey),
        'answers': [
          for (final a in owner.answers)
            {
              'receiver': a.receiver,
              'proposal_id': a.proposalId,
              'answer': a.answer,
              'id': a.id,
              'version': a.version,
            },
        ]..sort(byKey),
        'records': [
          for (final r in [
            ...owner.records,
          ]..sort((a, b) => a.id.compareTo(b.id)))
            {
              'id': r.id,
              'version': '${r.version}',
              'state': r.deleted ? 'deleted' : 'there',
              'value': r.value,
            },
        ],
      });
    } else {
      throw const _BadRequest('a step of no known form');
    }
  }
  return {'steps': out};
}

Map<String, Uint8List>? _valueBytes(Object? value) {
  if (value == null) return null;
  if (value is! Map<String, Object?>) {
    throw const _BadRequest('values is no object');
  }
  return {for (final e in value.entries) e.key: _bytes(e.value)};
}

/// One installation of a receiver that proposes changes (shares.md, 13 to 16).
Future<Map<String, Object?>> _proposer(Map<String, Object?> input) async {
  final device = _object(input, 'device');
  final manifests = <String, ({int revision, Set<String> proposals})>{
    for (final e
        in ((device['manifests'] as Map<String, Object?>?) ?? {}).entries)
      e.key: (
        revision: (e.value! as Map)['revision'] as int,
        proposals: _strings((e.value! as Map)['proposals']).toSet(),
      ),
  };
  final proposer = await ProposalProposer.start(
    seed: _bytes(device['seed']),
    owner: _strings(device['owner']),
    manifests: manifests,
    records: [
      for (final r
          in (device['records'] as List<Object?>? ?? [])
              .cast<Map<String, Object?>>())
        HeldOwnerRecord(
          id: _string(r, 'id'),
          type: _string(r, 'type'),
          version: _version(r['version'])!,
          last: _string(r, 'last'),
          schema: _string(r, 'schema'),
          values: _valueBytes(r['values']) ?? {},
          deleted: r['deleted'] == true,
        ),
    ],
    proposalIds: _strings(device['proposal_ids'] ?? <String>[]),
  );
  final steps = input['steps'];
  if (steps is! List<Object?>) throw const _BadRequest('steps is no list');
  final out = <Object?>[];
  for (final step in steps.cast<Map<String, Object?>>()) {
    if (step.containsKey('propose')) {
      final p = _object(step, 'propose');
      final values = p['values'];
      if (values is! Map<String, Object?>) {
        throw const _BadRequest('values is no object');
      }
      final message = await proposer.propose(
        _string(p, 'id'),
        _string(p, 'to'),
        {
          for (final e in values.entries)
            e.key: e.value == null ? null : _bytes(e.value),
        },
        relay: p['relay'] == true,
      );
      out.add({'message': message == null ? null : _hex(message)});
    } else if (step.containsKey('receive')) {
      final r = await proposer.receive(_bytes(step['receive']));
      out.add({
        'result': r.result,
        'replies': [for (final m in r.replies) _hex(m)],
      });
    } else if (step.containsKey('record')) {
      final r = _object(step, 'record');
      proposer.record(
        _string(r, 'id'),
        _string(r, 'kind'),
        _version(r['version'])!,
        _valueBytes(r['values']),
      );
      out.add(<String, Object?>{});
    } else if (step.containsKey('manifest')) {
      final m = _object(step, 'manifest');
      proposer.manifest(
        _string(m, 'key'),
        m['revision']! as int,
        _strings(m['proposals']).toSet(),
      );
      out.add(<String, Object?>{});
    } else if (step.containsKey('remove')) {
      out.add({
        'messages': [
          for (final m in await proposer.remove(_string(step, 'remove')))
            _hex(m),
        ],
      });
    } else if (step.containsKey('connect')) {
      out.add({
        'messages': [
          for (final m in proposer.connect(_string(step, 'connect'))) _hex(m),
        ],
      });
    } else if (step.containsKey('days')) {
      out.add({
        'messages': [
          for (final m in proposer.days(step['days']! as int)) _hex(m),
        ],
      });
    } else if (step.containsKey('query')) {
      final q = proposer.query(_string(step, 'query'));
      out.add({'status': q?.status, 'resend': q?.resend ?? false});
    } else {
      throw const _BadRequest('a step of no known form');
    }
  }
  return {'steps': out};
}
