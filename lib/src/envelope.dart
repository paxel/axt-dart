/// The AXT envelope of format 1 and the bodies of its kinds (AXT
/// `spec/envelope.md`, sections 2, 3 and 5).
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:avro/avro.dart';

import 'errors.dart';
import 'schemas.g.dart';

/// What a message is, and so which schema its body has (section 2.2).
///
/// The order is that of the symbols of `axt.Kind`, so [Kind.index] is the
/// value in the binary encoding.
enum Kind {
  manifest('MANIFEST', 'axt.Manifest'),
  offer('OFFER', 'axt.Offer'),
  accept('ACCEPT', 'axt.Accept'),
  decline('DECLINE', 'axt.Decline'),
  data('DATA', null),
  delete('DELETE', null),
  ack('ACK', 'axt.Ack'),
  error('ERROR', 'axt.Error'),
  deviceJoin('DEVICE_JOIN', 'axt.DeviceJoin'),
  deviceAdd('DEVICE_ADD', 'axt.DeviceAdd'),
  deviceRemove('DEVICE_REMOVE', 'axt.DeviceRemove'),
  change('CHANGE', 'axt.Change'),
  resync('RESYNC', 'axt.Resync'),
  forward('FORWARD', 'axt.Forward'),
  withdraw('WITHDRAW', 'axt.Withdraw'),
  proposal('PROPOSAL', 'axt.Proposal'),
  proposalReply('PROPOSAL_REPLY', 'axt.ProposalReply');

  const Kind(this.symbol, this.bodySchema);

  /// The symbol of `axt.Kind`, such as `DEVICE_ADD`.
  final String symbol;

  /// The full name of the body's schema of format 1; null for `DATA`, whose
  /// body has the record type's offered schema, and for `DELETE`, whose body
  /// is empty.
  final String? bodySchema;

  /// The kind of [symbol]; throws [AxtException] `INVALID_MESSAGE` for a
  /// symbol that format 1 does not have.
  static Kind ofSymbol(String symbol) {
    for (final kind in values) {
      if (kind.symbol == symbol) return kind;
    }
    throw AxtException(ErrorCode.invalidMessage, 'no kind $symbol');
  }
}

/// The record a message is about: its id and version.
final class RecordRef {
  const RecordRef(this.id, this.version);

  /// The record's id, as received: a UUID text, not checked here.
  final String id;

  /// The record's version.
  final int version;
}

/// One AXT message of envelope format 1.
final class Envelope {
  const Envelope({
    required this.kind,
    required this.sender,
    required this.record,
    required this.body,
    required this.signature,
    this.format = 1,
  });

  /// The envelope format; always 1 here.
  final int format;

  /// What the message is.
  final Kind kind;

  /// The Ed25519 public key of the sending device, 32 bytes.
  final Uint8List sender;

  /// The record the message is about, or null.
  final RecordRef? record;

  /// Empty, or one datum in single-object encoding.
  final Uint8List body;

  /// The sender's Ed25519 signature, 64 bytes.
  final Uint8List signature;
}

/// The largest live message, 16 MiB (`spec/transports.md`, section 4.4).
const int maxMessageBytes = 16 * 1024 * 1024;

/// The AXT schemas, parsed once, by full name.
final Map<String, Schema> _schemas = {
  for (final entry in axtSchemaTexts.entries)
    entry.key: Schema.parse(entry.value),
};

/// The same schemas without their logical types, which decode to the values
/// of the underlying types: a record id stays the text it was received as.
final Map<String, Schema> _rawSchemas = {
  for (final entry in axtSchemaTexts.entries)
    entry.key: Schema.parse(
      jsonEncode(withoutLogicalTypes(jsonDecode(entry.value))),
    ),
};

/// [schemaJson] without the `logicalType` attributes, which leaves its
/// Parsing Canonical Form and so its fingerprint as it is.
Object? withoutLogicalTypes(Object? schemaJson) => switch (schemaJson) {
  Map<String, Object?>() => {
    for (final entry in schemaJson.entries)
      if (entry.key != 'logicalType')
        entry.key: withoutLogicalTypes(entry.value),
  },
  List<Object?>() => [for (final item in schemaJson) withoutLogicalTypes(item)],
  _ => schemaJson,
};

/// The JSON text of the AXT schema of [fullName], as the release publishes it.
String axtSchemaText(String fullName) =>
    axtSchemaTexts[fullName] ??
    (throw ArgumentError.value(fullName, 'fullName'));

/// The AXT schema of [fullName] without its logical types, for writing
/// bodies whose ids are kept as given.
Schema axtRawSchema(String fullName) =>
    _rawSchemas[fullName] ?? (throw ArgumentError.value(fullName, 'fullName'));

/// The parsed AXT schema of [fullName], such as `axt.Envelope`.
Schema axtSchema(String fullName) =>
    _schemas[fullName] ?? (throw ArgumentError.value(fullName, 'fullName'));

final AvroCodec _envelopeCodec = AvroCodec(
  writer: _rawSchemas['axt.Envelope']!,
);

/// The CRC-64-AVRO fingerprint of the envelope schema of format 1.
final int envelopeFingerprint = _envelopeCodec.writer.crc64;

/// Decodes a live message: the marker, the envelope fingerprint and the
/// envelope (sections 2 and 3). Checks only the envelope, not the signature
/// and not the body.
///
/// Throws [AxtException] with `TOO_LARGE` above [maxMessageBytes],
/// `FORMAT_UNSUPPORTED` for an envelope fingerprint of no format this library
/// reads, and `INVALID_MESSAGE` for anything else that is not an envelope of
/// format 1 with no bytes left over.
Envelope decodeMessage(Uint8List message) {
  if (message.length > maxMessageBytes) {
    throw AxtException(
      ErrorCode.tooLarge,
      '${message.length} bytes, the limit is $maxMessageBytes',
    );
  }
  final SingleObjectHeader header;
  try {
    header = SingleObjectHeader.parse(message);
  } on DecodeException catch (e) {
    throw AxtException(ErrorCode.invalidMessage, e.message);
  }
  if (header.fingerprint != envelopeFingerprint) {
    throw const AxtException(
      ErrorCode.formatUnsupported,
      'the envelope fingerprint is of no format this library reads',
    );
  }
  final Object? value;
  try {
    value = _envelopeCodec.decode(header.payload);
  } on AvroException catch (e) {
    throw AxtException(ErrorCode.invalidMessage, e.message);
  }
  final fields = value! as Map<String, Object?>;
  if (fields['format'] != 1) {
    throw AxtException(
      ErrorCode.invalidMessage,
      'format ${fields['format']} under the fingerprint of format 1',
    );
  }
  final record = fields['record'] as Map<String, Object?>?;
  return Envelope(
    kind: Kind.ofSymbol(fields['kind']! as String),
    sender: fields['sender']! as Uint8List,
    record: record == null
        ? null
        : RecordRef(record['id']! as String, record['version']! as int),
    body: fields['body']! as Uint8List,
    signature: fields['signature']! as Uint8List,
  );
}

/// Encodes [envelope] as a live message (section 3).
Uint8List encodeMessage(Envelope envelope) {
  final record = envelope.record;
  return _envelopeCodec.encodeSingleObject({
    'format': envelope.format,
    'kind': envelope.kind.symbol,
    'sender': envelope.sender,
    'record': record == null
        ? null
        : {'id': record.id, 'version': record.version},
    'body': envelope.body,
    'signature': envelope.signature,
  });
}

final Map<String, AvroCodec> _bodyCodecs = {};

/// Decodes the body of a message of [kind] with its kind's schema of format 1,
/// to values of the underlying types (section 2.3).
///
/// Throws [AxtException] `INVALID_MESSAGE` for a body that is not a complete
/// single-object encoding of that schema, and [ArgumentError] for `DATA` and
/// `DELETE`, which have no schema of the specification.
Object? decodeBody(Kind kind, Uint8List body) {
  final name = kind.bodySchema;
  if (name == null) {
    throw ArgumentError.value(kind, 'kind', 'has no body schema');
  }
  final codec = _bodyCodecs[name] ??= AvroCodec(writer: _rawSchemas[name]!);
  try {
    return codec.decodeSingleObject(body);
  } on AvroException catch (e) {
    throw AxtException(ErrorCode.invalidMessage, e.message);
  }
}
