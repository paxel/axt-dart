/// One app in one live connection with another app: manifests, offers,
/// answers, record messages, acknowledgements and errors (AXT
/// `spec/protocol.md`, sections 3 to 9 and 14).
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:avro/avro.dart';
import 'package:crypto/crypto.dart' as crypto;

import 'device_sets.dart';
import 'ed25519.dart' as ed25519;
import 'bricks.dart' show Description;
import 'envelope.dart';
import 'errors.dart';
import 'manifest.dart';
import 'record_decoder.dart';
import 'records.dart';
import 'signing.dart';
import 'type_description.dart';

String _hex(List<int> bytes) =>
    [for (final b in bytes) b.toRadixString(16).padLeft(2, '0')].join();

bool _same(List<int> a, List<int> b) => _hex(a) == _hex(b);

/// The answer of a `receive` step.
final class Received {
  Received({this.outcome, this.close = false, List<Uint8List>? replies})
    : replies = replies ?? [];

  /// The outcome of a record message processed to one, or null.
  final Outcome? outcome;

  /// Whether the app closes the connection.
  final bool close;

  /// The messages the app sends in reply.
  final List<Uint8List> replies;
}

/// An entry of an `ACK`.
typedef AckEntry = ({
  String id,
  int version,
  Outcome outcome,
  int receiverVersion,
  List<String> keptFields,
});

final class _PeerOffer {
  _PeerOffer(this.id, this.answers);

  final String id;

  /// The answer per type: `ACCEPT` or a reason of a `DECLINE`.
  final Map<String, String> answers;
}

final class _Current {
  _Current(
    this.offerId,
    this.type,
    this.schema,
    this.text, {
    required this.accepted,
  });

  final String offerId;
  final String type;
  final Schema schema;
  final String text;
  final bool accepted;
}

final class _Rejected implements Exception {
  _Rejected(this.code, {this.fingerprint, this.field});

  final ErrorCode code;
  final Uint8List? fingerprint;
  final String? field;
}

final class _Ignored implements Exception {
  const _Ignored();
}

/// One app in live connections with one other app, whose key its user has
/// accepted.
final class LiveApp {
  LiveApp._(
    this._seed,
    this.key,
    this._manifest,
    this._readers,
    this._userTakes,
    this.peer,
  ) : _receiver = DeviceSetReceiver(
        senders: [
          KnownSender('peer', current: {_hex(peer)}),
        ],
      );

  /// An app with the signing key [seed] and the body of its own `MANIFEST`,
  /// in a live connection whose `HELLO` proved [peer].
  static Future<LiveApp> open({
    required Uint8List seed,
    required Uint8List manifestBody,
    required List<int> formats,
    required Map<String, String> readers,
    required Set<String> userTakes,
    required Uint8List peer,
  }) async => LiveApp._(
    seed,
    await ed25519.publicKeyOf(seed),
    decodeBody(Kind.manifest, manifestBody)! as Map<String, Object?>,
    readers,
    userTakes,
    peer,
  );

  final Uint8List _seed;

  /// The app's own key.
  final Uint8List key;

  final Map<String, Object?> _manifest;
  final Map<String, String> _readers;
  final Set<String> _userTakes;

  /// The other app's key, the connection key.
  final Uint8List peer;

  final DeviceSetReceiver _receiver;

  // State of the connection.
  bool _signedManifest = false;
  Map<String, Object?>? _peerManifest;
  final Map<String, _PeerOffer> _peerOffers = {};
  final Map<String, _Current> _current = {};
  final List<Uint8List> _heldErrors = [];

  // State across connections.
  final Map<String, HeldRecord> _held = {};
  final Map<String, Map<String, Object?>?> _values = {};
  final List<AckEntry> _owedAcks = [];
  final Map<String, ({String offerId, Map<String, String> answers})>
  _ownOffers = {};
  final Map<String, Outcome> _outcomes = {};
  final List<String> _errors = [];

  Future<Uint8List> _send(
    String schema,
    Kind kind,
    Map<String, Object?> value,
  ) async {
    final body = AvroCodec(writer: axtRawSchema(schema))
        .encodeSingleObject(value);
    final unsigned = encodeMessage(
      Envelope(
        kind: kind,
        sender: key,
        record: null,
        body: body,
        signature: Uint8List(64),
      ),
    );
    final signature = await ed25519.sign(
      _seed,
      signedBytesOfLiveMessage(unsigned),
    );
    return unsigned..setAll(unsigned.length - 64, signature);
  }

  Future<Uint8List> _error(
    Uint8List message,
    ErrorCode code, {
    RecordRef? record,
    Uint8List? fingerprint,
    String? field,
  }) => _send('axt.Error', Kind.error, {
    'to': peer,
    'code': code.code,
    'message_hash': Uint8List.fromList(crypto.sha256.convert(message).bytes),
    'record': record == null || utf8.encode(record.id).length > 64
        ? null
        : {'id': record.id, 'version': record.version},
    'fingerprint': fingerprint,
    'field': field,
    'detail': '',
  });

  /// The connection ends; offers end with it (section 4.3).
  void closeConnection() {
    _signedManifest = false;
    _peerManifest = null;
    _peerOffers.clear();
    _current.clear();
    _heldErrors.clear();
  }

  /// Processes one live message of the other app.
  Future<Received> receive(Uint8List message) async {
    final Envelope envelope;
    try {
      envelope = decodeMessage(message);
    } on AxtException catch (e) {
      if (!_signedManifest) return Received();
      return Received(
        replies: [
          await _error(
            message,
            e.code,
            fingerprint: e.code == ErrorCode.formatUnsupported
                ? Uint8List.sublistView(message, 2, 10)
                : null,
          ),
        ],
      );
    }
    final kind = envelope.kind;
    final isChain = kind == Kind.deviceAdd || kind == Kind.deviceRemove;
    if (!await verifyLiveMessage(message, envelope.sender)) {
      if (!_signedManifest) return Received();
      return Received(
        replies: [await _error(message, ErrorCode.signatureInvalid)],
      );
    }
    if (isChain) return _chain(message);
    if (kind == Kind.deviceJoin) return Received();
    final sender = _hex(envelope.sender);
    final state = _receiver.stateOf(sender);
    if (state == KeyState.removed || !_same(envelope.sender, peer)) {
      return Received();
    }
    if ((envelope.record != null) != _carriesRecord(kind)) {
      if (!_signedManifest) return Received();
      return Received(
        replies: [
          await _error(
            message,
            ErrorCode.invalidMessage,
            record: envelope.record,
          ),
        ],
      );
    }
    if (kind == Kind.manifest) return _onManifest(message, envelope);
    // Nothing but a MANIFEST is processed before a valid one (3.1).
    if (_peerManifest == null) return Received();
    try {
      return await _process(message, envelope);
    } on _Ignored {
      return Received();
    } on _Rejected catch (e) {
      return Received(
        replies: [
          await _error(
            message,
            e.code,
            record: envelope.record,
            fingerprint: e.fingerprint,
            field: e.field,
          ),
        ],
      );
    }
  }

  /// Whether a message of [kind] carries a `record` (section 2).
  static bool _carriesRecord(Kind kind) => const {
    Kind.data,
    Kind.delete,
    Kind.withdraw,
    Kind.change,
    Kind.resync,
    Kind.forward,
    Kind.proposal,
    Kind.proposalReply,
  }.contains(kind);

  Future<Received> _chain(Uint8List message) async {
    final outcome = await _receiver.receiveChain([message]);
    final result = outcome.results.single;
    final replies = <Uint8List>[];
    if (result == ChangeResult.deviceRejected) {
      final error = await _error(message, ErrorCode.deviceRejected);
      if (_signedManifest) {
        replies.add(error);
      } else {
        _heldErrors.add(error);
      }
    }
    final close = _receiver.stateOf(_hex(peer)) == KeyState.removed;
    if (close) {
      // The offers made to the removed key and by it end (section 4.3).
      _ownOffers.clear();
      _current.clear();
    }
    return Received(replies: replies, close: close);
  }

  Future<Received> _onManifest(Uint8List message, Envelope envelope) async {
    _signedManifest = true;
    final replies = [..._heldErrors];
    _heldErrors.clear();
    try {
      _peerManifest = await checkManifest(envelope.body, envelope.format);
    } on AxtException catch (e) {
      replies.add(await _error(message, e.code));
    }
    return Received(replies: replies);
  }

  Map<String, Object?> _body(Envelope envelope) {
    try {
      return decodeBody(envelope.kind, envelope.body)! as Map<String, Object?>;
    } on AxtException {
      throw _Rejected(ErrorCode.invalidMessage);
    }
  }

  void _checkTo(Map<String, Object?> body) {
    if (!_same(body['to']! as Uint8List, key)) throw const _Ignored();
  }

  Future<Received> _process(Uint8List message, Envelope envelope) async {
    final kind = envelope.kind;
    switch (kind) {
      case Kind.offer:
        return _onOffer(message, envelope);
      case Kind.accept || Kind.decline:
        return _onAnswer(envelope);
      case Kind.ack:
        return _onAck(envelope);
      case Kind.error:
        _onError(envelope);
        return Received();
      case Kind.data || Kind.delete || Kind.withdraw:
        return _onRecord(envelope);
      case Kind.change || Kind.resync || Kind.forward:
        // Only between the devices of one set (sync.md, section 7.1).
        throw _Rejected(ErrorCode.invalidMessage);
      default:
        return Received();
    }
  }

  Future<Received> _onOffer(Uint8List message, Envelope envelope) async {
    final body = _body(envelope);
    _checkTo(body);
    final offerId = body['offer_id']! as String;
    final repeat = _peerOffers[offerId];
    if (repeat != null) {
      return Received(replies: await _answer(offerId, repeat.answers));
    }
    final types = body['types']! as List<Object?>;
    try {
      recordKey(offerId);
    } on AxtException {
      throw _Rejected(ErrorCode.offerInvalid);
    }
    if (types.isEmpty || types.length > 256) {
      throw _Rejected(ErrorCode.offerInvalid);
    }
    // A description that is not valid is declined, not the offer (4.2).
    final parsed = <({String name, TypeDescription? type})>[];
    for (final entry in types.cast<Map<String, Object?>>()) {
      if ((entry['count']! as int) < 0) throw _Rejected(ErrorCode.offerInvalid);
      final description = entry['description']! as Description;
      final kind = description['kind']! as Branch;
      if (kind.name != 'axt.ObjectField') {
        throw _Rejected(ErrorCode.offerInvalid);
      }
      final name = (kind.value! as Map<String, Object?>)['name']! as String;
      TypeDescription? type;
      try {
        type = TypeDescription.of(description);
      } on AxtException {
        type = null;
      }
      // The full name is in the Parsing Canonical Form, so two types of
      // one fingerprint have one name as well.
      if (parsed.any((p) => p.name == name)) {
        throw _Rejected(ErrorCode.offerInvalid);
      }
      parsed.add((name: name, type: type));
    }
    final answers = <String, String>{};
    for (final (:name, :type) in parsed) {
      String answer;
      if (type == null) {
        answer = 'DESCRIPTION_INVALID';
      } else if (!fit(_manifest, type.schemaText, const []).fits) {
        answer = 'DOES_NOT_FIT';
      } else {
        try {
          checkAxtNames(type.schema);
          final reader = _readers[name];
          if (reader != null) {
            // The reader is the one of the offered full name, so only the
            // resolution itself can fail here.
            AvroCodec(writer: type.schema, reader: parseTypeSchema(reader));
          }
          answer = _userTakes.contains(name) ? 'ACCEPT' : 'NOT_WANTED';
        } on AxtException {
          answer = 'DOES_NOT_RESOLVE';
        } on ResolutionException {
          answer = 'DOES_NOT_RESOLVE';
        }
      }
      answers[name] = answer;
      if (type != null) {
        _current[name] = _Current(
          offerId,
          name,
          type.schema,
          type.schemaText,
          accepted: answer == 'ACCEPT',
        );
      } else {
        _current.remove(name);
      }
    }
    _peerOffers[offerId] = _PeerOffer(offerId, answers);
    return Received(replies: await _answer(offerId, answers));
  }

  Future<List<Uint8List>> _answer(
    String offerId,
    Map<String, String> answers,
  ) async {
    final accepted = [
      for (final e in answers.entries)
        if (e.value == 'ACCEPT') e.key,
    ];
    final declined = [
      for (final e in answers.entries)
        if (e.value != 'ACCEPT') {'type': e.key, 'reason': e.value},
    ];
    return [
      if (accepted.isNotEmpty)
        await _send('axt.Accept', Kind.accept, {
          'to': peer,
          'offer_id': offerId,
          'types': accepted,
        }),
      if (declined.isNotEmpty)
        await _send('axt.Decline', Kind.decline, {
          'to': peer,
          'offer_id': offerId,
          'types': declined,
        }),
    ];
  }

  Future<Received> _onAnswer(Envelope envelope) async {
    final body = _body(envelope);
    _checkTo(body);
    final offerId = body['offer_id']! as String;
    final names = [
      for (final t in body['types']! as List<Object?>)
        envelope.kind == Kind.accept
            ? t! as String
            : (t! as Map)['type'] as String,
    ];
    final offered = [
      for (final e in _ownOffers.entries)
        if (e.value.offerId == offerId) e.key,
    ];
    final made = _madeOffers.contains(offerId);
    if (!made) return Received();
    if (names.toSet().length != names.length ||
        names.any((n) => !(_offerTypes[offerId] ?? const {}).contains(n))) {
      throw _Rejected(ErrorCode.invalidMessage);
    }
    for (var i = 0; i < names.length; i++) {
      final name = names[i];
      if (!offered.contains(name)) continue;
      final own = _ownOffers[name]!;
      if (own.answers.containsKey(name)) continue;
      own.answers[name] = envelope.kind == Kind.accept
          ? 'ACCEPT'
          : ((body['types']! as List<Object?>)[i]! as Map)['reason'] as String;
    }
    return Received();
  }

  final Set<String> _madeOffers = {};
  final Map<String, Set<String>> _offerTypes = {};

  Future<Received> _onAck(Envelope envelope) async {
    final body = _body(envelope);
    _checkTo(body);
    final records = (body['records']! as List<Object?>)
        .cast<Map<String, Object?>>();
    final seen = <String>{};
    for (final entry in records) {
      final String id;
      try {
        id = recordKey(entry['id']! as String);
      } on AxtException {
        throw _Rejected(ErrorCode.invalidMessage);
      }
      final version = entry['version']! as int;
      final outcome = entry['outcome']! as String;
      final receiverVersion = entry['receiver_version']! as int;
      final kept = (entry['kept_fields']! as List<Object?>).cast<String>();
      if (version < 1 ||
          !seen.add('$id/$version') ||
          (outcome == 'STALE'
              ? receiverVersion <= version
              : receiverVersion != version) ||
          (outcome == 'MERGED') == kept.isEmpty ||
          kept.toSet().length != kept.length) {
        throw _Rejected(ErrorCode.invalidMessage);
      }
    }
    if (records.isEmpty || records.length > 4096) {
      throw _Rejected(ErrorCode.invalidMessage);
    }
    for (final entry in records) {
      final slot = '${recordKey(entry['id']! as String)}/${entry['version']}';
      final outcome = Outcome.values.firstWhere(
        (o) => o.code == entry['outcome'],
      );
      final had = _outcomes[slot];
      if (had == null ||
          had == Outcome.duplicate ||
          (outcome == Outcome.applied &&
              (had == Outcome.kept || had == Outcome.merged)) ||
          (outcome == Outcome.withdrawn && had == Outcome.kept)) {
        _outcomes[slot] = outcome;
      }
    }
    return Received();
  }

  void _onError(Envelope envelope) {
    final Map<String, Object?> body;
    try {
      body = decodeBody(Kind.error, envelope.body)! as Map<String, Object?>;
    } on AxtException {
      return;
    }
    if (!_same(body['to']! as Uint8List, key)) return;
    final record = body['record'] as Map<String, Object?>?;
    if (record != null) {
      try {
        if (_outcomes.containsKey(
          '${recordKey(record['id']! as String)}/${record['version']}',
        )) {
          return;
        }
      } on AxtException {
        // An id that is no UUID has no outcome.
      }
    }
    _errors.add(body['code']! as String);
  }

  bool _acceptedAny() => _current.values.any((c) => c.accepted);

  Future<Received> _onRecord(Envelope envelope) async {
    final ref = envelope.record!;
    final kind = envelope.kind;
    if (kind == Kind.delete && envelope.body.isNotEmpty) {
      throw _Rejected(ErrorCode.invalidMessage);
    }
    if (kind == Kind.withdraw) _checkTo(_body(envelope));
    final String id;
    try {
      id = recordKey(ref.id);
    } on AxtException catch (e) {
      throw _Rejected(e.code);
    }
    if (ref.version < 1) throw _Rejected(ErrorCode.versionInvalid);
    final held = _held[id];
    String? type;
    Schema? writer;
    switch (kind) {
      case Kind.data:
        final SingleObjectHeader header;
        try {
          header = SingleObjectHeader.parse(envelope.body);
        } on DecodeException {
          throw _Rejected(ErrorCode.invalidMessage);
        }
        final current = _current.values
            .where((c) => c.schema.crc64 == header.fingerprint)
            .firstOrNull;
        if (current == null) {
          throw _Rejected(
            ErrorCode.schemaUnknown,
            fingerprint: Uint8List.sublistView(envelope.body, 2, 10),
          );
        }
        if (!current.accepted || !fit(_manifest, current.text, const []).fits) {
          throw _Rejected(ErrorCode.notAccepted);
        }
        type = current.type;
        writer = current.schema;
        if (held?.type != null && held!.type != type) {
          throw _Rejected(ErrorCode.typeChanged);
        }
      case Kind.delete:
        final kept = held?.type;
        final ok = kept == null
            ? _acceptedAny()
            : (_current[kept]?.accepted ?? false);
        if (!ok) throw _Rejected(ErrorCode.notAccepted);
      default:
        if (held == null && !_acceptedAny()) {
          throw _Rejected(ErrorCode.notAccepted);
        }
    }
    Map<String, Object?>? value;
    if (held == null || ref.version > held.version) {
      if (kind == Kind.data) {
        final readerText = _readers[type];
        try {
          value =
              decodeRecord(
                    writer!,
                    readerText == null ? null : parseTypeSchema(readerText),
                    envelope.body,
                  )!
                  as Map<String, Object?>;
        } on AxtException catch (e) {
          throw _Rejected(e.code, field: e.field);
        }
      }
    }
    final applied = applyRecordMessage(
      held: held,
      current: _values[id],
      kind: switch (kind) {
        Kind.data => RecordKind.data,
        Kind.delete => RecordKind.delete,
        _ => RecordKind.withdraw,
      },
      version: ref.version,
      policy: const RecordPolicy(),
      type: type,
      value: value,
    );
    _held[id] = applied.held;
    _values[id] = applied.value;
    _owedAcks.add((
      id: ref.id,
      version: ref.version,
      outcome: applied.outcome,
      receiverVersion: applied.held.version,
      keptFields: applied.keptFields,
    ));
    return Received(outcome: applied.outcome);
  }

  /// Sends the acknowledgements it owes: the entries, and the `ACK`.
  Future<(List<AckEntry>, List<Uint8List>)> flushAcks() async {
    final entries = List.of(_owedAcks);
    _owedAcks.clear();
    if (entries.isEmpty) return (entries, <Uint8List>[]);
    final ack = await _send('axt.Ack', Kind.ack, {
      'to': peer,
      'records': [
        for (final e in entries)
          {
            'id': e.id,
            'version': e.version,
            'outcome': e.outcome.code,
            'receiver_version': e.receiverVersion,
            'kept_fields': e.keptFields,
          },
      ],
    });
    return (entries, [ack]);
  }

  /// Offers the types of [descriptions] with their counts under [offerId],
  /// the descriptions as given.
  Future<Uint8List> offer(
    String offerId,
    List<({Description description, int count})> types,
  ) async {
    _madeOffers.add(offerId);
    final names = <String>{};
    for (final type in types) {
      final root =
          (type.description['kind']! as Branch).value! as Map<String, Object?>;
      final name = root['name']! as String;
      names.add(name);
      _ownOffers[name] = (offerId: offerId, answers: {});
    }
    _offerTypes[offerId] = names;
    return _send('axt.Offer', Kind.offer, {
      'to': peer,
      'offer_id': offerId,
      'types': [
        for (final type in types)
          {'description': type.description, 'count': type.count},
      ],
    });
  }

  /// Whether it has an accepted offer of [type].
  bool accepted(String type) => _ownOffers[type]?.answers[type] == 'ACCEPT';

  /// The outcome it holds for its record message [id] and [version].
  Outcome? outcomeOf(String id, int version) {
    try {
      return _outcomes['${recordKey(id)}/$version'];
    } on AxtException {
      return null;
    }
  }

  /// What it holds of the other app's record [id].
  HeldRecord? record(String id) {
    try {
      return _held[recordKey(id)];
    } on AxtException {
      return null;
    }
  }

  /// The codes of the `ERROR` messages about its own messages it has taken.
  List<String> get errors => List.unmodifiable(_errors);
}
