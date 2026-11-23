/// Reading an AXT file: the whole file is checked before any record of it is
/// applied (AXT `spec/transports.md`, section 2.2; `spec/keys.md`, section
/// 2.5; `spec/envelope.md`, section 4).
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:avro/avro.dart';
import 'package:crypto/crypto.dart' as crypto;

import 'container.dart';
import 'device_sets.dart';
import 'ed25519.dart';
import 'envelope.dart';
import 'errors.dart';
import 'manifest.dart';
import 'record_decoder.dart';
import 'records.dart';
import 'signing.dart';
import 'type_description.dart';

AxtException _rejected(String why) => AxtException(ErrorCode.fileRejected, why);

final List<int> _headerPrefix = [...ascii.encode('AXT-v1 file header'), 0];

final RegExp _lowerHex = RegExp(r'^[0-9a-f]*$');

String _hex(List<int> bytes) =>
    [for (final b in bytes) b.toRadixString(16).padLeft(2, '0')].join();

Uint8List _unhexMeta(Uint8List? value, int length, String key) {
  if (value == null) throw _rejected('the file has no $key');
  final text = ascii.decode(value, allowInvalid: true);
  if (text.length != 2 * length || !_lowerHex.hasMatch(text)) {
    throw _rejected('$key is not $length bytes in lower-case hexadecimal');
  }
  return Uint8List.fromList([
    for (var i = 0; i < text.length; i += 2)
      int.parse(text.substring(i, i + 2), radix: 16),
  ]);
}

/// The bytes the header signature of a file covers.
Uint8List fileHeaderSignedBytes(List<int> sender, List<int>? schemas) =>
    Uint8List.fromList([
      ..._headerPrefix,
      ...sender,
      ...crypto.sha256.convert(schemas ?? const []).bytes,
    ]);

/// One message of a file, checked.
final class FileMessage {
  const FileMessage(this.envelope, this.bytes);

  final Envelope envelope;

  /// The datum as stored in the file.
  final Uint8List bytes;
}

/// A file that passed every check of the whole: its sender, the writer
/// schemas of its header, and its messages in their order.
final class CheckedFile {
  const CheckedFile({
    required this.sender,
    required this.schemas,
    required this.chain,
    required this.manifest,
    required this.records,
  });

  /// The key in `axt.sender`.
  final Uint8List sender;

  /// The types of `axt.schemas`, by the fingerprint of their derived schema.
  final Map<int, TypeDescription> schemas;

  /// The `DEVICE_ADD` and `DEVICE_REMOVE` messages at its start, as live
  /// messages.
  final List<Uint8List> chain;

  /// The body of its `MANIFEST`, or null.
  final Uint8List? manifest;

  /// Its record messages, `DATA`, `DELETE` and `WITHDRAW`.
  final List<FileMessage> records;
}

Uint8List _asLiveMessage(Uint8List datum) => Uint8List.fromList([
  0xc3,
  0x01,
  ...crc64ToBytes(envelopeFingerprint),
  ...datum,
]);

const Set<Kind> _recordKinds = {Kind.data, Kind.delete, Kind.withdraw};

/// Checks [file] as a whole (transports.md, section 2.2, the rows that
/// reject the whole file).
///
/// Throws [AxtException] `FILE_REJECTED` for a file rejected as a whole.
Future<CheckedFile> checkFile(Uint8List file) async {
  final container = Container.read(file, envelopeLength);
  final avroSchema = container.metadata['avro.schema'];
  if (avroSchema == null) throw _rejected('the file has no avro.schema');
  try {
    final schema = Schema.parse(utf8.decode(avroSchema));
    if (schema.canonicalForm != axtSchema('axt.Envelope').canonicalForm) {
      throw _rejected('avro.schema is not the envelope of format 1');
    }
  } on FormatException {
    throw _rejected('avro.schema is no UTF-8');
  } on AvroException {
    throw _rejected('avro.schema is no schema');
  }
  final sender = _unhexMeta(container.metadata['axt.sender'], 32, 'axt.sender');
  final signature = _unhexMeta(
    container.metadata['axt.signature'],
    64,
    'axt.signature',
  );
  final schemasValue = container.metadata['axt.schemas'];
  if (!await verifyStrict(
    sender,
    fileHeaderSignedBytes(sender, schemasValue),
    signature,
  )) {
    throw _rejected('the header signature does not verify');
  }
  final schemas = <int, TypeDescription>{};
  if (schemasValue != null) {
    final Object? list;
    try {
      list = jsonDecode(utf8.decode(schemasValue));
    } on FormatException {
      throw _rejected('axt.schemas is no JSON');
    }
    if (list is! List<Object?>) throw _rejected('axt.schemas is no JSON array');
    for (final item in list) {
      if (item is! Map<String, Object?> ||
          !item.containsKey('description') ||
          !item.containsKey('schema')) {
        throw _rejected('axt.schemas holds an entry without its members');
      }
      final TypeDescription type;
      final Schema schema;
      try {
        type = TypeDescription.fromJson(item['description']);
        schema = parseTypeSchema(jsonEncode(item['schema']));
      } on AxtException {
        throw _rejected(
          'axt.schemas holds a description that is not valid, or no schema',
        );
      }
      if (schema.canonicalForm != type.schema.canonicalForm) {
        throw _rejected('a schema in axt.schemas is not its derived schema');
      }
      if (schemas.containsKey(type.fingerprint)) {
        throw _rejected('two schemas in axt.schemas have one fingerprint');
      }
      schemas[type.fingerprint] = type;
    }
  }
  final chain = <Uint8List>[];
  Uint8List? manifest;
  final records = <FileMessage>[];
  for (final datum in container.datums) {
    final message = _asLiveMessage(datum);
    final Envelope envelope;
    try {
      envelope = decodeMessage(message);
    } on AxtException catch (e) {
      throw _rejected('a datum is no valid message: ${e.message}');
    }
    final kind = envelope.kind;
    final isDevice = kind == Kind.deviceAdd || kind == Kind.deviceRemove;
    if (!isDevice && kind != Kind.manifest && !_recordKinds.contains(kind)) {
      throw _rejected('a file holds no ${kind.symbol}');
    }
    if (isDevice && (manifest != null || records.isNotEmpty)) {
      throw _rejected('a ${kind.symbol} after another kind of message');
    }
    if (kind == Kind.manifest && (manifest != null || records.isNotEmpty)) {
      throw _rejected('a second MANIFEST, or one after a record message');
    }
    if ((envelope.record != null) != _recordKinds.contains(kind)) {
      throw _rejected(
        'a ${kind.symbol} with a record where none belongs, or none',
      );
    }
    if (kind == Kind.delete && envelope.body.isNotEmpty) {
      throw _rejected('a DELETE with a body');
    }
    if (kind == Kind.data) {
      final SingleObjectHeader header;
      try {
        header = SingleObjectHeader.parse(envelope.body);
      } on DecodeException {
        throw _rejected('a DATA whose body is no single-object encoding');
      }
      if (!schemas.containsKey(header.fingerprint)) {
        throw _rejected('a DATA whose fingerprint is not in axt.schemas');
      }
    } else if (kind.bodySchema != null) {
      try {
        decodeBody(kind, envelope.body);
      } on AxtException {
        throw _rejected('a ${kind.symbol} whose body is not its kind\'s');
      }
    }
    if (!await verifyLiveMessage(message, envelope.sender)) {
      throw _rejected('a message whose signature does not verify');
    }
    if (isDevice) {
      if (!await DeviceChange.decode(message).deviceVerifies()) {
        throw _rejected(
          'a ${kind.symbol} fails step 2 of keys.md, section 5.5',
        );
      }
      chain.add(message);
      continue;
    }
    if (_hex(envelope.sender) != _hex(sender)) {
      throw _rejected('a message of another sender than axt.sender');
    }
    if (kind == Kind.manifest) {
      manifest = envelope.body;
    } else {
      records.add(FileMessage(envelope, message));
    }
  }
  return CheckedFile(
    sender: sender,
    schemas: schemas,
    chain: chain,
    manifest: manifest,
    records: records,
  );
}

/// The reader of a file: its own manifest, its reader schemas, and the keys
/// of its own set, by which it takes a `WITHDRAW`.
final class FileReader {
  const FileReader({
    required this.manifest,
    required this.readers,
    this.current = const {},
    this.removed = const {},
  });

  /// The reader's own manifest, decoded.
  final Map<String, Object?> manifest;

  /// Its reader schemas by full name, as texts.
  final Map<String, String> readers;

  /// The current and removed keys of its own set, by hexadecimal text.
  final Set<String> current;

  final Set<String> removed;
}

/// What a reader did with one record message of a file.
final class FileRecordResult {
  const FileRecordResult(this.id, this.version, this.result, {this.applied});

  final String id;

  final int version;

  /// The outcome, or why it was not applied.
  final String result;

  /// For an applied message, what the receiver holds now.
  final Applied? applied;
}

/// Reads the records of [file] as [reader], with what it holds of the
/// sender's records in [held] by id and its user's values in [current].
/// Applies each record message by the version rule, and leaves the rest
/// unapplied with the reason (transports.md, section 2.2).
Future<List<FileRecordResult>> readFileRecords(
  CheckedFile file,
  FileReader reader, {
  required Map<String, HeldRecord> held,
  required Map<String, Map<String, Object?>?> current,
  RecordPolicy policy = const RecordPolicy(),
}) async {
  final results = <FileRecordResult>[];
  for (final message in file.records) {
    final envelope = message.envelope;
    final ref = envelope.record!;
    FileRecordResult result(String code) =>
        FileRecordResult(ref.id, ref.version, code);
    final String key;
    try {
      key = recordKey(ref.id);
      if (ref.version < 1) {
        throw AxtException(ErrorCode.versionInvalid, 'version ${ref.version}');
      }
    } on AxtException catch (e) {
      results.add(result(e.code.code));
      continue;
    }
    String? type;
    Map<String, Object?>? value;
    var elements = const ElementMerge();
    RecordKind kind;
    switch (envelope.kind) {
      case Kind.withdraw:
        final to = _hex(
          (decodeBody(Kind.withdraw, envelope.body)! as Map)['to'] as Uint8List,
        );
        if (!reader.current.contains(to) && !reader.removed.contains(to)) {
          results.add(result('IGNORED'));
          continue;
        }
        kind = RecordKind.withdraw;
      case Kind.delete:
        kind = RecordKind.delete;
      default:
        kind = RecordKind.data;
        final writer =
            file.schemas[SingleObjectHeader.parse(envelope.body).fingerprint]!;
        type = writer.name;
        final kept = held[key];
        if (kept?.type != null && kept!.type != type) {
          results.add(result(ErrorCode.typeChanged.code));
          continue;
        }
        if (!fit(reader.manifest, writer.schemaText, const []).fits) {
          results.add(result('DOES_NOT_FIT'));
          continue;
        }
        final readerText = reader.readers[type];
        try {
          final readerSchema = readerText == null
              ? null
              : parseTypeSchema(readerText);
          value =
              decodeRecord(writer.schema, readerSchema, envelope.body)!
                  as Map<String, Object?>;
          elements = elementMergeOf(
            readerSchema ?? writer.schema,
            writers: [for (final t in file.schemas.values) t.schema],
            readers: {
              for (final MapEntry(:key, :value) in reader.readers.entries)
                key: parseTypeSchema(value),
            },
          );
        } on AxtException catch (e) {
          results.add(result(e.code.code));
          continue;
        }
    }
    final applied = applyRecordMessage(
      held: held[key],
      current: current[key],
      kind: kind,
      version: ref.version,
      policy: policy,
      type: type,
      value: value,
      elements: elements,
    );
    held[key] = applied.held;
    current[key] = applied.value;
    results.add(
      FileRecordResult(
        ref.id,
        ref.version,
        applied.outcome.code,
        applied: applied,
      ),
    );
  }
  return results;
}
