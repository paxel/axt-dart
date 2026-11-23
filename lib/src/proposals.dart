/// Proposals: a receiver proposes a change of a record to its owner, and the
/// owner's user answers (AXT `spec/shares.md`, sections 12 to 18).
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:avro/avro.dart';
import 'package:crypto/crypto.dart' as crypto;

import 'ed25519.dart' as ed25519;
import 'envelope.dart';
import 'errors.dart';
import 'element_parts.dart';
import 'record_decoder.dart';
import 'records.dart' show ElementKey, elementListsOf, recordKey, sameValue;
import 'signing.dart';

String _hex(List<int> bytes) =>
    [for (final b in bytes) b.toRadixString(16).padLeft(2, '0')].join();

/// The largest value bytes of one `PROPOSAL`.
const int maxProposalValueBytes = 65536;

/// The largest value bytes of the open proposals of one proposer.
const int maxOpenValueBytes = 1048576;

/// The most open proposals of one proposer for one record, and in all.
const int maxOpenPerRecord = 16;
const int maxOpenInAll = 256;

Future<Uint8List> _signed(
  Uint8List seed,
  Uint8List key,
  Kind kind,
  RecordRef? record,
  String schema,
  Map<String, Object?> value,
) async {
  final body = AvroCodec(writer: axtRawSchema(schema))
      .encodeSingleObject(value);
  final unsigned = encodeMessage(
    Envelope(
      kind: kind,
      sender: key,
      record: record,
      body: body,
      signature: Uint8List(64),
    ),
  );
  final signature = await ed25519.sign(
    seed,
    signedBytesOfLiveMessage(unsigned),
  );
  return unsigned..setAll(unsigned.length - 64, signature);
}

/// A decoded Avro value in the JSON form of the conformance vectors.
Object? jsonValue(Object? value) => switch (value) {
  Uint8List() => _hex(value),
  Map<String, Object?>() => {
    for (final e in value.entries) e.key: jsonValue(e.value),
  },
  List<Object?>() => [for (final v in value) jsonValue(v)],
  _ => value,
};

/// A receiver of the owner's records, as the owner's device knows it.
final class ProposalReceiver {
  ProposalReceiver(
    this.name, {
    required this.current,
    required this.removed,
    this.ownUser = false,
    this.links = false,
  });

  final String name;
  final Set<String> current;
  final Set<String> removed;
  final bool ownUser;

  /// Whether its shares let the links of its records go along (section
  /// 19.1).
  final bool links;

  /// Whether it gets every record whole, its links included.
  bool get getsLinks => ownUser || links;
}

/// A record of the owner's own set.
final class OwnRecord {
  OwnRecord({
    required this.id,
    required this.type,
    required this.version,
    required this.deleted,
    required this.value,
    required this.shared,
  });

  final String id;
  final String type;
  int version;
  bool deleted;
  Map<String, Object?> value;
  final Set<String> shared;
}

/// An open proposal at the owner.
final class OpenProposal {
  OpenProposal({
    required this.receiver,
    required this.proposalId,
    required this.id,
    required this.version,
    required this.valueBytes,
    this.message,
    this.signer,
    this.fields = const [],
  });

  final String receiver;
  final String proposalId;
  final String id;
  final int version;
  final int valueBytes;
  Uint8List? message;
  Uint8List? signer;
  List<Map<String, Object?>> fields;
}

/// An answer the owner's app holds.
final class ProposalAnswer {
  ProposalAnswer(
    this.receiver,
    this.proposalId,
    this.answer,
    this.id,
    this.version,
  );

  final String receiver;
  final String proposalId;
  String answer;
  final String id;
  final int version;
}

/// A stop of a receiver's proposals, for one record, one type, or all.
typedef Stop = ({String receiver, String? id, String? type});

/// The owner's result of a received `PROPOSAL`.
typedef OwnerReceived = ({String result, List<Uint8List> replies});

/// One installation of the owner of shared records, which counts its versions
/// and takes proposals of its receivers.
final class ProposalOwner {
  ProposalOwner._(
    this._seed,
    this.key,
    this.siblings,
    this.proposals,
    this._schemas,
    this.receivers,
    this.records,
    this._readers,
    this.open,
    this.answers,
    this.stops,
  );

  static Future<ProposalOwner> start({
    required Uint8List seed,
    required Set<String> siblings,
    required Set<String> proposals,
    required List<String> schemas,
    required List<ProposalReceiver> receivers,
    required List<OwnRecord> records,
    required Map<String, String>? readers,
    required List<OpenProposal> open,
    required List<ProposalAnswer> answers,
    required List<Stop> stops,
  }) async => ProposalOwner._(
    seed,
    await ed25519.publicKeyOf(seed),
    siblings,
    proposals,
    {
      for (final text in schemas)
        parseTypeSchema(text).crc64: (
          schema: parseTypeSchema(text),
          text: text,
        ),
    },
    receivers,
    records,
    readers,
    open,
    answers,
    stops,
  );

  final Uint8List _seed;
  final Uint8List key;
  final Set<String> siblings;
  Set<String> proposals;
  final Map<int, ({Schema schema, String text})> _schemas;
  final List<ProposalReceiver> receivers;
  final List<OwnRecord> records;
  final Map<String, String>? _readers;
  final List<OpenProposal> open;
  final List<ProposalAnswer> answers;
  final List<Stop> stops;

  ProposalReceiver? _receiverOf(String key) {
    for (final r in receivers) {
      if (r.current.contains(key) || r.removed.contains(key)) return r;
    }
    return null;
  }

  OwnRecord? _record(String id) {
    for (final r in records) {
      if (r.id.toLowerCase() == id.toLowerCase()) return r;
    }
    return null;
  }

  bool _stopped(String receiver, OwnRecord record) => stops.any(
    (s) =>
        s.receiver == receiver &&
        (s.id == null || s.id!.toLowerCase() == record.id.toLowerCase()) &&
        (s.type == null || s.type == record.type),
  );

  /// The schema of the record's type that the device holds, or null.
  RecordSchema? _typeSchema(OwnRecord record) => _schemas.values
      .map((e) => e.schema)
      .whereType<RecordSchema>()
      .where((s) => s.fullName == record.type)
      .firstOrNull;

  /// The ids of the records shared with [receiver], and the keys of the own
  /// set, which decide what goes along without the links.
  ({Set<String> shared, Set<String> ownKeys}) _linksOf(
    ProposalReceiver receiver,
  ) => (
    shared: {
      for (final r in records)
        if (!r.deleted && r.shared.contains(receiver.name)) r.id,
    },
    ownKeys: {_hex(key), ...siblings},
  );

  /// Whether an entry of [fields] is a part of an element that [record]
  /// holds and the shares of [receiver] left out (section 20.2).
  bool _leftOutPart(
    OwnRecord record,
    ProposalReceiver receiver,
    List<Map<String, Object?>> fields,
  ) {
    final schema = _typeSchema(record);
    if (receiver.getsLinks || schema == null) return false;
    final lists = elementListsOf(schema);
    final links = _linksOf(receiver);
    for (final field in fields) {
      final PartName? part;
      try {
        part = partName(field['name']! as String);
      } on AxtException {
        continue;
      }
      final kind = part == null ? null : lists[part.list];
      final list = part == null ? null : record.value[part.list];
      if (kind == null || list is! List<Object?>) continue;
      final element = elementOf(kind, list, part!.key);
      if (element != null &&
          !goesWithoutLinks(
            kind,
            element,
            shared: links.shared,
            ownKeys: links.ownKeys,
          )) {
        return true;
      }
    }
    return false;
  }

  /// [proposed], a list proposed whole, with every element of [held] that
  /// the shares of [receiver] left out kept after it, unless the proposal
  /// holds its key (section 19.3).
  List<Object?> _keepLeftOut(
    ElementKey kind,
    List<Object?> proposed,
    List<Object?> held,
    ProposalReceiver receiver,
  ) {
    final links = _linksOf(receiver);
    final keys = {
      for (final e in proposed.cast<Map<String, Object?>>()) keyText(kind, e),
    };
    return [
      ...proposed,
      for (final e in held.cast<Map<String, Object?>>())
        if (!keys.contains(keyText(kind, e)) &&
            !goesWithoutLinks(
              kind,
              e,
              shared: links.shared,
              ownKeys: links.ownKeys,
            ))
          e,
    ];
  }

  Future<Uint8List> _error(
    Uint8List message,
    Uint8List to,
    ErrorCode code, {
    RecordRef? record,
    Uint8List? fingerprint,
    String? field,
  }) => _signed(_seed, key, Kind.error, null, 'axt.Error', {
    'to': to,
    'code': code.code,
    'message_hash': Uint8List.fromList(crypto.sha256.convert(message).bytes),
    'record': record == null || utf8.encode(record.id).length > 64
        ? null
        : {'id': record.id, 'version': record.version},
    'fingerprint': fingerprint,
    'field': field,
    'detail': '',
  });

  Future<Uint8List> _reply(
    Uint8List to,
    String id,
    int version,
    String proposalId,
    String answer,
  ) => _signed(
    _seed,
    key,
    Kind.proposalReply,
    RecordRef(id, version),
    'axt.ProposalReply',
    {'to': to, 'proposal_id': proposalId, 'answer': answer},
  );

  /// Processes a `PROPOSAL` of a key of a receiver, a sibling or its own
  /// (sections 13.3 and 13.4).
  Future<OwnerReceived> receive(Uint8List message) async {
    final Envelope envelope;
    try {
      envelope = decodeMessage(message);
    } on AxtException {
      // No sender can be told, so it is rejected without a report.
      return (result: 'rejected', replies: <Uint8List>[]);
    }
    final signer = envelope.sender;
    final signerHex = _hex(signer);
    if (signerHex == _hex(key)) {
      return (result: 'ignored', replies: <Uint8List>[]);
    }
    final receiver = _receiverOf(signerHex);
    final known = receiver != null || siblings.contains(signerHex);
    if (!known) return (result: 'ignored', replies: <Uint8List>[]);
    if (!await verifyLiveMessage(message, signer)) {
      return (
        result: 'rejected',
        replies: [await _error(message, signer, ErrorCode.signatureInvalid)],
      );
    }
    if (receiver != null && receiver.removed.contains(signerHex)) {
      return (result: 'ignored', replies: <Uint8List>[]);
    }
    Future<OwnerReceived> reject(
      ErrorCode code, {
      Uint8List? fingerprint,
      String? field,
    }) async => (
      result: 'rejected',
      replies: [
        await _error(
          message,
          signer,
          code,
          record: envelope.record,
          fingerprint: fingerprint,
          field: field,
        ),
      ],
    );
    if (envelope.kind != Kind.proposal) return reject(ErrorCode.invalidMessage);
    final ref = envelope.record;
    if (ref == null) return reject(ErrorCode.invalidMessage);
    final Map<String, Object?> body;
    try {
      body = decodeBody(Kind.proposal, envelope.body)! as Map<String, Object?>;
    } on AxtException {
      return reject(ErrorCode.invalidMessage);
    }
    if (_hex(body['to']! as Uint8List) != _hex(key)) {
      return (result: 'ignored', replies: <Uint8List>[]);
    }
    try {
      recordKey(ref.id);
    } on AxtException {
      return reject(ErrorCode.recordIdInvalid);
    }
    if (ref.version < 1) return reject(ErrorCode.versionInvalid);
    final proposalId = body['proposal_id']! as String;
    final fields = (body['fields']! as List<Object?>)
        .cast<Map<String, Object?>>();
    final names = <String>{};
    var validId = true;
    try {
      recordKey(proposalId);
    } on AxtException {
      validId = false;
    }
    if (!validId ||
        fields.isEmpty ||
        fields.length > 4096 ||
        fields.any((f) {
          final name = f['name']! as String;
          final length = utf8.encode(name).length;
          return length < 1 || length > 512 || !names.add(name);
        })) {
      return reject(ErrorCode.invalidMessage);
    }
    final name = receiver?.name;
    // A repeat of an answered proposal gets its reply again (13.4).
    for (final answer in answers) {
      if (answer.receiver == name && answer.proposalId == proposalId) {
        return (
          result: 'repeat',
          replies: [
            await _reply(
              signer,
              answer.id,
              answer.version,
              proposalId,
              answer.answer,
            ),
          ],
        );
      }
    }
    final record = _record(ref.id);
    final valueBytes = fields.fold<int>(
      0,
      (n, f) => n + (f['value']! as Uint8List).length,
    );
    final held = open
        .where((p) => p.receiver == name && p.proposalId == proposalId)
        .firstOrNull;
    if (held != null) {
      final heldHash = held.message == null
          ? null
          : crypto.sha256.convert(held.message!).bytes;
      final hash = crypto.sha256.convert(message).bytes;
      if (heldHash != null && _hex(hash).compareTo(_hex(heldHash)) > 0) {
        held
          ..message = message
          ..signer = signer
          ..fields = fields;
        return (result: 'replaced', replies: <Uint8List>[]);
      }
      return (result: 'repeat', replies: <Uint8List>[]);
    }
    final ofProposer = open.where((p) => p.receiver == name).toList();
    if (receiver == null ||
        record == null ||
        record.deleted ||
        !(record.shared.contains(name) || receiver.ownUser) ||
        !proposals.contains(record.type) ||
        _stopped(name!, record) ||
        valueBytes > maxProposalValueBytes ||
        ofProposer.fold<int>(0, (n, p) => n + p.valueBytes) + valueBytes >
            maxOpenValueBytes ||
        ofProposer
                .where((p) => p.id.toLowerCase() == record.id.toLowerCase())
                .length >=
            maxOpenPerRecord ||
        ofProposer.length >= maxOpenInAll ||
        _leftOutPart(record, receiver, fields)) {
      return reject(ErrorCode.proposalsNotTaken);
    }
    for (final field in fields) {
      final fingerprint = crc64FromBytes(field['schema']! as Uint8List);
      if (!_schemas.containsKey(fingerprint)) {
        return reject(
          ErrorCode.schemaUnknown,
          fingerprint: field['schema']! as Uint8List,
        );
      }
    }
    for (final field in fields) {
      final schema =
          _schemas[crc64FromBytes(field['schema']! as Uint8List)]!.schema;
      final fieldName = field['name']! as String;
      final PartName? part;
      try {
        part = partName(fieldName);
      } on AxtException catch (e) {
        return reject(e.code);
      }
      if (part != null) {
        if (names.contains(part.list)) return reject(ErrorCode.invalidMessage);
        final code = part.field == null
            ? _checkElementPart(record, schema, part, field)
            : _checkExtensionPart(record, schema, part, field);
        if (code != null) return reject(code.code, field: code.field);
        continue;
      }
      final match = schema is RecordSchema && schema.fullName == record.type
          ? schema.fields.where((f) => f.name == fieldName).firstOrNull
          : null;
      if (match == null) return reject(ErrorCode.invalidMessage);
      final Object? value;
      try {
        value = AvroCodec(writer: match.schema)
            .decode(field['value']! as Uint8List);
      } on AvroException {
        return reject(ErrorCode.undecodable);
      }
      try {
        checkValue(match.schema, value, fieldName, depthOffset: 1);
      } on AxtException catch (e) {
        return reject(e.code, field: e.field);
      }
    }
    open.add(
      OpenProposal(
        receiver: name,
        proposalId: proposalId,
        id: ref.id,
        version: ref.version,
        valueBytes: valueBytes,
        message: message,
        signer: signer,
        fields: fields,
      ),
    );
    return (result: 'taken', replies: <Uint8List>[]);
  }

  /// The list field [part] of [schema] when it is a schema of the record's
  /// type in which the list is merged per element.
  ({ElementKey kind, Schema items})? _elementList(
    OwnRecord record,
    Schema schema,
    PartName part,
  ) {
    if (schema is! RecordSchema || schema.fullName != record.type) return null;
    final kind = elementListsOf(schema)[part.list];
    if (kind == null) return null;
    final items =
        (schema.fields.firstWhere((f) => f.name == part.list).schema
                as ArraySchema)
            .items;
    return (kind: kind, items: items);
  }

  /// Steps 7 to 9 for an element part (section 20.1): the error, or null.
  ({ErrorCode code, String? field})? _checkElementPart(
    OwnRecord record,
    Schema schema,
    PartName part,
    Map<String, Object?> field,
  ) {
    final list = _elementList(record, schema, part);
    if (list == null || (list.kind == ElementKey.id && !_isKeyText(part.key))) {
      return (code: ErrorCode.invalidMessage, field: null);
    }
    final Object? element;
    try {
      element = decodeElementPart(list.items, field['value']! as Uint8List);
    } on AxtException catch (e) {
      return (code: e.code, field: null);
    }
    if (element == null) return null;
    final problem = elementProblem(
      list.kind,
      field['name']! as String,
      part.key,
      element as Map<String, Object?>,
    );
    return problem == null
        ? null
        : (code: ErrorCode.valueInvalid, field: problem);
  }

  static bool _isKeyText(String key) {
    try {
      return recordKey(key) == key;
    } on AxtException {
      return false;
    }
  }

  /// The field of a part within an extension in the entry's [schema], when
  /// the device holds a schema of the record's type with the list as a list
  /// of extensions.
  Field? _extensionField(OwnRecord record, Schema schema, PartName part) {
    final holds = _schemas.values.any(
      (e) =>
          e.schema is RecordSchema &&
          (e.schema as RecordSchema).fullName == record.type &&
          elementListsOf(e.schema)[part.list] == ElementKey.name,
    );
    if (!holds || schema is! RecordSchema || schema.fullName != part.key) {
      return null;
    }
    return schema.fields.where((f) => f.name == part.field).firstOrNull;
  }

  /// Steps 7 to 9 for a part within an extension: the error, or null.
  ({ErrorCode code, String? field})? _checkExtensionPart(
    OwnRecord record,
    Schema schema,
    PartName part,
    Map<String, Object?> field,
  ) {
    final match = _extensionField(record, schema, part);
    if (match == null) return (code: ErrorCode.invalidMessage, field: null);
    final name = field['name']! as String;
    try {
      final value = AvroCodec(writer: match.schema)
          .decode(field['value']! as Uint8List);
      checkValue(match.schema, value, name, depthOffset: 1);
    } on AvroException {
      return (code: ErrorCode.undecodable, field: null);
    } on AxtException catch (e) {
      return (code: e.code, field: e.field);
    }
    return null;
  }

  /// The decoded value of [field] of an open proposal, read with its entry's
  /// schema and resolved against the reader schema, or null when the device
  /// cannot show it.
  ({Object? value})? _show(OwnRecord record, Map<String, Object?> field) {
    final entry = _schemas[crc64FromBytes(field['schema']! as Uint8List)];
    if (entry == null) return null;
    final schema = entry.schema as RecordSchema;
    final name = field['name']! as String;
    final part = partName(name);
    if (part != null) {
      final bytes = field['value']! as Uint8List;
      if (part.field == null) {
        final list = _elementList(record, schema, part)!;
        return (value: decodeElementPart(list.items, bytes));
      }
      final match = _extensionField(record, schema, part)!;
      return (value: AvroCodec(writer: match.schema).decode(bytes));
    }
    final match = schema.fields.where((f) => f.name == name).firstOrNull;
    if (match == null) return null;
    final readerText = _readers?[record.type];
    Schema? reader;
    if (readerText != null) {
      final full = parseTypeSchema(readerText) as RecordSchema;
      final readerField = full.fields.where((f) => f.name == name).firstOrNull;
      if (readerField == null) return null;
      reader = readerField.schema;
    }
    try {
      final value = AvroCodec(
        writer: match.schema,
        reader: reader,
      ).decode(field['value']! as Uint8List);
      checkValue(match.schema, value, name, depthOffset: 1);
      return (value: value);
    } on AvroException {
      return null;
    } on AxtException {
      return null;
    }
  }

  /// Its user answers an open proposal (sections 15.1 and 15.2).
  Future<
    ({
      bool made,
      List<Uint8List> replies,
      ({int version, Map<String, Object?> value})? update,
    })
  >
  answer(String receiver, String proposalId, String answer) async {
    final proposal = open
        .where((p) => p.receiver == receiver && p.proposalId == proposalId)
        .firstOrNull;
    final record = proposal == null ? null : _record(proposal.id);
    if (proposal == null || record == null || record.deleted) {
      return (made: false, replies: <Uint8List>[], update: null);
    }
    final shown = <String, Object?>{};
    if (answer == 'ACCEPTED') {
      if (proposal.message == null) {
        return (made: false, replies: <Uint8List>[], update: null);
      }
      for (final field in proposal.fields) {
        final value = _show(record, field);
        if (value == null) {
          return (made: false, replies: <Uint8List>[], update: null);
        }
        shown[field['name']! as String] = value.value;
      }
    }
    open.remove(proposal);
    answers.add(
      ProposalAnswer(
        receiver,
        proposalId,
        answer,
        proposal.id,
        proposal.version,
      ),
    );
    final signer = proposal.signer;
    final owner = receivers.where((r) => r.name == receiver).firstOrNull;
    final replies = <Uint8List>[
      if (signer != null && !(owner?.removed.contains(_hex(signer)) ?? false))
        await _reply(signer, proposal.id, proposal.version, proposalId, answer),
    ];
    if (answer != 'ACCEPTED') {
      return (made: true, replies: replies, update: null);
    }
    final value = {...record.value};
    final lists = switch (_typeSchema(record)) {
      final RecordSchema schema => elementListsOf(schema),
      null => const <String, ElementKey>{},
    };
    final proposer = owner!;
    for (final field in proposal.fields) {
      final name = field['name']! as String;
      final proposed = jsonValue(shown[name]);
      final part = partName(name);
      final kind = lists[part?.list ?? name];
      if (part == null) {
        value[name] = kind == null || proposer.getsLinks
            ? proposed
            : _keepLeftOut(
                kind,
                proposed! as List<Object?>,
                value[name] as List<Object?>? ?? const [],
                proposer,
              );
      } else if (part.field == null) {
        final list = [...?value[part.list] as List<Object?>?];
        final at = list.indexWhere(
          (e) => keyText(kind!, e! as Map<String, Object?>) == part.key,
        );
        if (proposed == null) {
          if (at >= 0) list.removeAt(at);
        } else if (at >= 0) {
          list[at] = proposed;
        } else {
          list.add(proposed);
        }
        value[part.list] = list;
      } else {
        value[part.list] = _setWithin(value[part.list], part, field);
      }
    }
    record
      ..version = record.version + 1
      ..value = value;
    return (
      made: true,
      replies: replies,
      update: (version: record.version, value: record.value),
    );
  }

  /// The list of extensions [list] with the field of [part] set within its
  /// extension, encoded again with the device's own schema of the type
  /// (section 20.3); as it is where it does not hold the extension.
  Object? _setWithin(Object? list, PartName part, Map<String, Object?> field) {
    if (list is! List<Object?>) return list;
    final entry = _schemas[crc64FromBytes(field['schema']! as Uint8List)]!;
    final own = _schemas.values
        .map((e) => e.schema)
        .whereType<RecordSchema>()
        .firstWhere((s) => s.fullName == part.key);
    return [
      for (final e in list.cast<Map<String, Object?>>())
        if (e['name'] != part.key)
          e
        else
          () {
            final data = _unhex(e['data']! as String);
            final header = SingleObjectHeader.parse(data);
            final writer = _schemas[header.fingerprint]?.schema ?? own;
            final decoded =
                AvroCodec(writer: writer, reader: own).decode(header.payload)!
                    as Map<String, Object?>;
            final ownField = own.fields.firstWhere((f) => f.name == part.field);
            final entryField = (entry.schema as RecordSchema).fields.firstWhere(
              (f) => f.name == part.field,
            );
            decoded[part.field!] = AvroCodec(
              writer: entryField.schema,
              reader: ownField.schema,
            ).decode(field['value']! as Uint8List);
            return {
              'name': part.key,
              'data': _hex(AvroCodec(writer: own).encodeSingleObject(decoded)),
            };
          }(),
    ];
  }

  /// An answer of a sibling comes into the app's records; `ACCEPTED` stands.
  void answered(
    String receiver,
    String proposalId,
    String answer,
    String id,
    int version,
  ) {
    open.removeWhere(
      (p) => p.receiver == receiver && p.proposalId == proposalId,
    );
    final held = answers
        .where((a) => a.receiver == receiver && a.proposalId == proposalId)
        .firstOrNull;
    if (held == null) {
      answers.add(ProposalAnswer(receiver, proposalId, answer, id, version));
    } else if (answer == 'ACCEPTED') {
      held.answer = 'ACCEPTED';
    }
  }

  /// Its user stops the proposals of a receiver (section 18.4).
  void stop(Stop stop) {
    stops.add(stop);
    open.removeWhere((p) {
      final record = _record(p.id);
      return p.receiver == stop.receiver &&
          record != null &&
          _stopped(stop.receiver, record);
    });
  }

  /// The record is deleted, no longer shared with a receiver, or shared again
  /// (section 15.4).
  void change(String id, String action, String? receiver) {
    final record = _record(id);
    if (record == null) return;
    switch (action) {
      case 'delete':
        record.deleted = true;
        open.removeWhere((p) => p.id.toLowerCase() == id.toLowerCase());
      case 'unshare':
        record.shared.remove(receiver);
        open.removeWhere(
          (p) =>
              p.receiver == receiver && p.id.toLowerCase() == id.toLowerCase(),
        );
      default:
        record.shared.add(receiver!);
    }
  }
}

/// A record of the owner that a proposer holds.
final class HeldOwnerRecord {
  HeldOwnerRecord({
    required this.id,
    required this.type,
    required this.version,
    required this.last,
    required this.schema,
    required this.values,
    required this.deleted,
  });

  final String id;
  final String type;
  int version;
  String last;
  final String schema;
  Map<String, Uint8List> values;
  final bool deleted;
}

/// A proposal that a proposer sent.
final class SentProposal {
  SentProposal(
    this.id,
    this.proposalId,
    this.to,
    this.message,
    this.fields, {
    required this.relay,
  });

  final String id;
  final String proposalId;
  String to;
  Uint8List message;
  final List<Map<String, Object?>> fields;
  final bool relay;
  String? status;
  bool settled = false;
  int daysSinceSent = 0;
}

/// One installation of a receiver that proposes changes of the records of
/// one owner (sections 13.1, 14.2 and 16).
final class ProposalProposer {
  ProposalProposer._(
    this._seed,
    this.key,
    this.owner,
    this.manifests,
    this.records,
    this._ids,
    this._extensions,
  );

  /// A proposer with the signing key [seed], and [schemas], the writer
  /// schemas of the extension types it holds.
  static Future<ProposalProposer> start({
    required Uint8List seed,
    required List<String> owner,
    required Map<String, ({int revision, Set<String> proposals})> manifests,
    required List<HeldOwnerRecord> records,
    required List<String> proposalIds,
    List<String> schemas = const [],
  }) async => ProposalProposer._(
    seed,
    await ed25519.publicKeyOf(seed),
    [...owner],
    manifests,
    records,
    [...proposalIds],
    {
      for (final text in schemas)
        if (parseTypeSchema(text) case final RecordSchema schema)
          schema.crc64: schema,
    },
  );

  final Uint8List _seed;
  final Uint8List key;
  final List<String> owner;
  final Map<String, ({int revision, Set<String> proposals})> manifests;
  final List<HeldOwnerRecord> records;
  final List<String> _ids;
  final Map<int, RecordSchema> _extensions;
  final List<SentProposal> sent = [];

  /// Blocks of new proposals per record, after an error (section 16.3).
  final Map<
    String,
    ({
      String code,
      int version,
      Map<String, int> revisions,
      String? field,
      Uint8List? value,
    })
  >
  _blocks = {};

  HeldOwnerRecord? _record(String id) =>
      records.where((r) => r.id.toLowerCase() == id.toLowerCase()).firstOrNull;

  bool _takes(String key, String type) =>
      owner.contains(key) &&
      (manifests[key]?.proposals.contains(type) ?? false);

  Future<Uint8List> _proposal(
    String to,
    HeldOwnerRecord record,
    String proposalId,
    List<Map<String, Object?>> fields,
  ) => _signed(
    _seed,
    key,
    Kind.proposal,
    RecordRef(record.id, record.version),
    'axt.Proposal',
    {'to': _unhex(to), 'proposal_id': proposalId, 'fields': fields},
  );

  /// Its user proposes [values] for the record [id] to the key [to].
  Future<Uint8List?> propose(
    String id,
    String to,
    Map<String, Uint8List?> values, {
    bool relay = false,
  }) async {
    final record = _record(id);
    if (record == null ||
        record.deleted ||
        record.last != 'DATA' ||
        !_takes(to, record.type)) {
      return null;
    }
    final block = _blocks[record.id.toLowerCase()];
    final schema = parseTypeSchema(record.schema) as RecordSchema;
    final fields = <Map<String, Object?>>[];
    for (final MapEntry(key: name, :value) in values.entries) {
      if (value == null) continue;
      final PartName? part;
      try {
        part = partName(name);
      } on AxtException {
        continue;
      }
      if (part != null) {
        final entry = _partEntry(record, schema, name, part, value);
        if (entry != null) fields.add(entry);
        continue;
      }
      final kept = record.values[name];
      final match = schema.fields.where((f) => f.name == name).firstOrNull;
      if (match == null) continue;
      final codec = AvroCodec(writer: match.schema);
      Object? decode(Uint8List bytes) {
        try {
          return codec.decode(bytes);
        } on AvroException {
          return bytes;
        }
      }

      if (kept != null && sameValue(decode(kept), decode(value))) continue;
      fields.add({
        'name': name,
        'schema': crc64ToBytes(schema.crc64),
        'value': value,
      });
    }
    if (fields.isEmpty) return null;
    if (block != null) {
      if (block.code == 'VALUE_INVALID') {
        final top = block.field!.split(RegExp(r'[.\[]')).first;
        final proposed = values[top];
        if (proposed != null &&
            block.value != null &&
            _hex(proposed) == _hex(block.value!)) {
          return null;
        }
      } else {
        return null;
      }
    }
    final proposalId = _ids.removeAt(0);
    final message = await _proposal(to, record, proposalId, fields);
    sent.add(
      SentProposal(record.id, proposalId, to, message, fields, relay: relay),
    );
    return message;
  }

  /// The entry of the part [name] with [value], or null where its value is
  /// that of the kept `DATA` or it names nothing the proposer can propose
  /// (section 20.1).
  Map<String, Object?>? _partEntry(
    HeldOwnerRecord record,
    RecordSchema schema,
    String name,
    PartName part,
    Uint8List value,
  ) {
    final kind = elementListsOf(schema)[part.list];
    if (kind == null) return null;
    final listSchema =
        schema.fields.firstWhere((f) => f.name == part.list).schema
            as ArraySchema;
    final bytes = record.values[part.list];
    final kept = bytes == null
        ? const <Object?>[]
        : AvroCodec(writer: listSchema).decode(bytes)! as List<Object?>;
    final element = elementOf(kind, kept, part.key);
    if (part.field == null) {
      final before = encodeElementPart(listSchema.items, element);
      if (_hex(before) == _hex(value)) return null;
      return {
        'name': name,
        'schema': crc64ToBytes(schema.crc64),
        'value': value,
      };
    }
    if (element == null) return null;
    final header = SingleObjectHeader.parse(element['data']! as Uint8List);
    final writer = _extensions[header.fingerprint];
    final field = writer?.fields.where((f) => f.name == part.field).firstOrNull;
    if (field == null) return null;
    final decoded =
        AvroCodec(writer: writer!).decode(header.payload)!
            as Map<String, Object?>;
    final before = AvroCodec(writer: field.schema).encode(decoded[field.name]);
    if (_hex(before) == _hex(value)) return null;
    return {'name': name, 'schema': crc64ToBytes(writer.crc64), 'value': value};
  }

  /// Processes a `PROPOSAL_REPLY` or an `ERROR` (sections 14.2 and 16.3).
  Future<({String result, List<Uint8List> replies})> receive(
    Uint8List message,
  ) async {
    final Envelope envelope;
    try {
      envelope = decodeMessage(message);
    } on AxtException {
      return (result: 'ignored', replies: <Uint8List>[]);
    }
    Future<({String result, List<Uint8List> replies})> reject(
      ErrorCode code, {
      bool withRecord = true,
    }) async => (
      result: 'rejected',
      replies: [
        await _signed(_seed, key, Kind.error, null, 'axt.Error', {
          'to': envelope.sender,
          'code': code.code,
          'message_hash': Uint8List.fromList(
            crypto.sha256.convert(message).bytes,
          ),
          'record':
              !withRecord ||
                  envelope.record == null ||
                  utf8.encode(envelope.record!.id).length > 64
              ? null
              : {
                  'id': envelope.record!.id,
                  'version': envelope.record!.version,
                },
          'fingerprint': null,
          'field': null,
          'detail': '',
        }),
      ],
    );
    if (!await verifyLiveMessage(message, envelope.sender)) {
      return reject(ErrorCode.signatureInvalid, withRecord: false);
    }
    final senderHex = _hex(envelope.sender);
    if (envelope.kind == Kind.error) {
      final Map<String, Object?> body;
      try {
        body = decodeBody(Kind.error, envelope.body)! as Map<String, Object?>;
      } on AxtException {
        return (result: 'ignored', replies: <Uint8List>[]);
      }
      if (_hex(body['to']! as Uint8List) != _hex(key)) {
        return (result: 'ignored', replies: <Uint8List>[]);
      }
      final hash = _hex(body['message_hash']! as Uint8List);
      final proposal = sent
          .where(
            (p) =>
                p.to == senderHex &&
                _hex(crypto.sha256.convert(p.message).bytes) == hash,
          )
          .firstOrNull;
      if (proposal == null || proposal.status != null || proposal.settled) {
        return (result: 'ignored', replies: <Uint8List>[]);
      }
      final code = body['code']! as String;
      if (code == 'FORMAT_UNSUPPORTED') {
        return (result: 'taken', replies: <Uint8List>[]);
      }
      proposal
        ..settled = true
        ..status = code;
      final record = _record(proposal.id);
      if (code == 'PROPOSALS_NOT_TAKEN' ||
          code == 'SCHEMA_UNKNOWN' ||
          code == 'VALUE_INVALID') {
        final field = body['field'] as String?;
        _blocks[proposal.id.toLowerCase()] = (
          code: code,
          version: record?.version ?? 0,
          revisions: {
            for (final e in manifests.entries) e.key: e.value.revision,
          },
          field: field,
          value: field == null
              ? null
              : proposal.fields
                    .where(
                      (f) => f['name'] == field.split(RegExp(r'[.\[]')).first,
                    )
                    .map((f) => f['value']! as Uint8List)
                    .firstOrNull,
        );
      }
      return (result: 'taken', replies: <Uint8List>[]);
    }
    if (envelope.kind != Kind.proposalReply) {
      return (result: 'ignored', replies: <Uint8List>[]);
    }
    final ref = envelope.record;
    if (ref == null) return reject(ErrorCode.invalidMessage);
    final Map<String, Object?> body;
    try {
      body =
          decodeBody(Kind.proposalReply, envelope.body)!
              as Map<String, Object?>;
    } on AxtException {
      return reject(ErrorCode.invalidMessage);
    }
    if (_hex(body['to']! as Uint8List) != _hex(key)) {
      return (result: 'ignored', replies: <Uint8List>[]);
    }
    final proposalId = body['proposal_id']! as String;
    final proposal = owner.contains(senderHex)
        ? sent.where((p) => p.proposalId == proposalId).firstOrNull
        : null;
    if (proposal == null) return (result: 'ignored', replies: <Uint8List>[]);
    final record = _record(proposal.id)!;
    if (ref.id != proposal.id || ref.version != _versionOf(proposal)) {
      return reject(ErrorCode.invalidMessage);
    }
    final answer = body['answer']! as String;
    // Any reply to its own proposals ends a block of new proposals (16.3).
    _blocks.removeWhere((_, b) => b.code == 'PROPOSALS_NOT_TAKEN');
    if (proposal.status == 'DECLINED' && answer == 'ACCEPTED') {
      proposal.status = 'ACCEPTED';
      return (result: 'taken', replies: <Uint8List>[]);
    }
    if (proposal.status == 'ACCEPTED' || proposal.status == 'DECLINED') {
      return (result: 'ignored', replies: <Uint8List>[]);
    }
    proposal
      ..status = answer
      ..settled = true;
    record.version = record.version;
    return (result: 'taken', replies: <Uint8List>[]);
  }

  int _versionOf(SentProposal proposal) =>
      decodeMessage(proposal.message).record!.version;

  /// A record message of the owner reaches it and is applied.
  void record(
    String id,
    String kind,
    int version,
    Map<String, Uint8List>? values,
  ) {
    final record = _record(id);
    if (record == null) return;
    if (version > record.version) {
      record
        ..version = version
        ..last = kind;
      if (values != null) record.values = values;
      _blocks.remove(record.id.toLowerCase());
    }
  }

  /// A manifest of a key of the owner reaches it.
  void manifest(String key, int revision, Set<String> proposals) {
    final had = manifests[key];
    manifests[key] = (revision: revision, proposals: proposals);
    if (had == null || revision > had.revision) {
      _blocks.removeWhere(
        (_, b) => b.code == 'PROPOSALS_NOT_TAKEN' || b.code == 'SCHEMA_UNKNOWN',
      );
    }
  }

  /// Whether [p] has neither a reply nor an error, for a record whose last
  /// message from the owner is a `DATA`.
  bool _unsettled(SentProposal p) {
    final record = _record(p.id);
    return !p.settled &&
        p.status == null &&
        record != null &&
        record.last == 'DATA';
  }

  /// Whether [p] is sent again: unsettled, to a current key of the owner.
  bool _pending(SentProposal p) => _unsettled(p) && owner.contains(p.to);

  /// The key [removed] is removed from the owner: the proposals to it go to
  /// another current key whose manifest takes proposals for the type.
  Future<List<Uint8List>> remove(String removed) async {
    owner.remove(removed);
    final messages = <Uint8List>[];
    for (final p in sent.where((p) => p.to == removed && _unsettled(p))) {
      final record = _record(p.id)!;
      final keys = [
        for (final k in owner)
          if (_takes(k, record.type)) k,
      ];
      if (keys.isEmpty) continue;
      p
        ..to = keys.first
        ..message = await _proposal(keys.first, record, p.proposalId, p.fields);
      messages.add(p.message);
    }
    return messages;
  }

  /// A live connection with the device of [key] begins.
  List<Uint8List> connect(String key) => [
    for (final p in sent)
      if (p.to == key && _pending(p)) p.message,
  ];

  /// [days] days pass: proposals sent through the relay go again after 14.
  List<Uint8List> days(int days) {
    final messages = <Uint8List>[];
    for (final p in sent.where((p) => p.relay && _pending(p))) {
      p.daysSinceSent += days;
      if (p.daysSinceSent >= 14) {
        p.daysSinceSent = 0;
        messages.add(p.message);
      }
    }
    return messages;
  }

  /// The status of a proposal, and whether it is sent again.
  ({String status, bool resend})? query(String proposalId) {
    final p = sent.where((p) => p.proposalId == proposalId).firstOrNull;
    if (p == null) return null;
    return (status: p.status ?? 'open', resend: _pending(p));
  }
}

Uint8List _unhex(String text) => Uint8List.fromList([
  for (var i = 0; i < text.length; i += 2)
    int.parse(text.substring(i, i + 2), radix: 16),
]);
