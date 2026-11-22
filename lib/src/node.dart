/// The public face of the library: one installation of an app that speaks
/// AXT through files, keeping its AXT state in the app's store
/// (`docs/adr/0001-the-public-api.md`).
library;

import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:avro/avro.dart';
import 'package:crypto/crypto.dart' as crypto;

import 'container.dart';
import 'device_sets.dart';
import 'ed25519.dart' as ed25519;
import 'envelope.dart';
import 'errors.dart';
import 'file_reader.dart';
import 'links.dart' show withoutLinks;
import 'manifest.dart';
import 'record_decoder.dart' show parseTypeSchema;
import 'records.dart';
import 'relation_index.dart';
import 'signing.dart';
import 'type_description.dart';

/// The key-value storage of bytes that the app implements for the library.
///
/// The library runs every received file and every written file in one
/// [transaction]; the app runs it on the same connection as its own data, so
/// that both are written together or not at all.
abstract interface class AxtStore {
  /// The value of [key], or null.
  Future<Uint8List?> read(String key);

  /// Sets [key] to [value].
  Future<void> write(String key, Uint8List value);

  /// Removes [key].
  Future<void> delete(String key);

  /// The keys that begin with [prefix], in any order.
  Future<List<String>> list(String prefix);

  /// Runs [body] as one transaction.
  Future<T> transaction<T>(Future<T> Function() body);
}

/// What the app gets for one received record that changed what it holds.
final class RecordChange {
  const RecordChange({
    required this.sender,
    required this.id,
    required this.type,
    required this.value,
    required this.outcome,
  });

  /// The sender, by the key it was first accepted with.
  final String sender;

  /// The record's id, as its sender wrote it.
  final String id;

  /// The record's type, or null for a tombstone of a record never seen.
  final String? type;

  /// The record as the app now holds it, merged with its user's changes;
  /// null when the record is deleted or withdrawn.
  final Map<String, Object?>? value;

  /// `APPLIED`, `MERGED` or `WITHDRAWN`.
  final Outcome outcome;
}

/// A record of the app's own, as it hands it to the library to send.
final class OutgoingRecord {
  /// A record that is there, with its type and its value; [withLinks] when a
  /// share for the receiver that names it lets its links go along
  /// (`spec/shares.md`, section 19.1).
  const OutgoingRecord(
    this.id,
    this.type,
    Map<String, Object?> this.value, {
    this.withLinks = false,
  });

  /// A record its user deleted.
  const OutgoingRecord.deleted(this.id)
    : type = null,
      value = null,
      withLinks = false;

  /// The record's id, a UUID the app keeps beside its entity.
  final String id;

  /// The record's type, whose derived schema is the writer schema; null for
  /// a deleted record.
  final TypeDescription? type;

  /// The value; null for a deleted record.
  final Map<String, Object?>? value;

  /// Whether its links go along: its relations to records not shared in the
  /// same file and to things outside AXT, and its extensions.
  final bool withLinks;
}

/// What [AxtNode.inspect] found in a file, before anything is applied.
final class FilePreview {
  const FilePreview._({
    required this.file,
    required this.sender,
    required this.shortFingerprint,
    required this.appName,
    required this.firstContact,
    required this.senderRemoved,
    required this.fitting,
  });

  final CheckedFile file;

  /// The key in `axt.sender`, as hexadecimal text.
  final String sender;

  /// Its short fingerprint, for the user to compare.
  final String shortFingerprint;

  /// The app name of a valid `MANIFEST` in the file, or null.
  final String? appName;

  /// Whether the sender is no known sender, even after the chain.
  final bool firstContact;

  /// Whether the sender is a removed key, so that nothing is applied.
  final bool senderRemoved;

  /// The record messages by type that fit the app's manifest.
  final Map<String, int> fitting;
}

/// What [AxtNode.apply] did with a file.
final class FileResult {
  const FileResult(this.accepted, this.records);

  /// Whether the sender was known or accepted, so that records were applied.
  final bool accepted;

  /// One entry for each record message of the file, in its order.
  final List<FileRecordResult> records;
}

/// A record of a sender, or of the app itself, by the sender's name as
/// [RecordChange.sender] gives it, or the app's own key as hexadecimal text,
/// and the record's id.
final class RecordAddress {
  const RecordAddress(this.sender, this.id);

  final String sender;

  /// The id, in lower case.
  final String id;

  @override
  bool operator ==(Object other) =>
      other is RecordAddress && other.sender == sender && other.id == id;

  @override
  int get hashCode => Object.hash(sender, id);

  @override
  String toString() => '$sender/$id';
}

/// A relation that points at a record: the record that holds it, and the
/// relation's id.
typedef Link = ({RecordAddress holder, String relation});

final Random _random = Random.secure();

/// A new record id: a UUID of version 7 (RFC 9562).
String newRecordId({DateTime? now}) {
  final ms = (now ?? DateTime.now()).millisecondsSinceEpoch;
  final bytes = Uint8List(16);
  for (var i = 0; i < 6; i++) {
    bytes[i] = (ms >> (8 * (5 - i))) & 0xff;
  }
  for (var i = 6; i < 16; i++) {
    bytes[i] = _random.nextInt(256);
  }
  bytes[6] = 0x70 | (bytes[6] & 0x0f);
  bytes[8] = 0x80 | (bytes[8] & 0x3f);
  final hex = [for (final b in bytes) b.toRadixString(16).padLeft(2, '0')]
      .join();
  return '${hex.substring(0, 8)}-${hex.substring(8, 12)}-'
      '${hex.substring(12, 16)}-${hex.substring(16, 20)}-${hex.substring(20)}';
}

/// The next state stamp after [highest] (`spec/sync.md`, section 2.2).
int nextStamp(int highest, {required int nowMs, required int random}) {
  final clock = BigInt.from(nowMs) * BigInt.from(65536);
  final base = clock > BigInt.from(highest) + BigInt.one
      ? clock
      : BigInt.from(highest) + BigInt.one;
  final next = base + BigInt.from(random);
  if (base + BigInt.from(32767) > BigInt.parse('9223372036854775807')) {
    throw StateError('no stamp is left');
  }
  return next.toInt();
}

String _hex(List<int> bytes) =>
    [for (final b in bytes) b.toRadixString(16).padLeft(2, '0')].join();

Uint8List _unhex(String text) => Uint8List.fromList([
  for (var i = 0; i < text.length; i += 2)
    int.parse(text.substring(i, i + 2), radix: 16),
]);

/// A generic value as JSON, bytes tagged so that they come back as bytes.
Object? _toJson(Object? value) => switch (value) {
  Uint8List() => {r'$bytes': _hex(value)},
  Map<String, Object?>() => {
    for (final e in value.entries) e.key: _toJson(e.value),
  },
  List<Object?>() => [for (final v in value) _toJson(v)],
  _ => value,
};

Object? _fromJson(Object? value) => switch (value) {
  {r'$bytes': final String hex} => _unhex(hex),
  Map<String, Object?>() => {
    for (final e in value.entries) e.key: _fromJson(e.value),
  },
  List<Object?>() => [for (final v in value) _fromJson(v)],
  _ => value,
};

Uint8List _encode(Object? json) => utf8.encode(jsonEncode(_toJson(json)));

Object? _decode(Uint8List bytes) => _fromJson(jsonDecode(utf8.decode(bytes)));

/// One installation of an app that speaks AXT.
final class AxtNode {
  AxtNode._(
    this._store,
    this._seed,
    this.publicKey,
    this._manifest,
    this._readers,
    this._policy,
    this._clock,
  );

  /// Opens the library on the app's [store], with the seed of the app's
  /// Ed25519 signing key, its own [manifest] content (without `revision`),
  /// the [readers], its own types by which it reads the records of others,
  /// and its [policy] for its user's changes.
  ///
  /// The library raises the manifest's revision whenever its content changes.
  static Future<AxtNode> open({
    required AxtStore store,
    required Uint8List signingSeed,
    required Map<String, Object?> manifest,
    List<TypeDescription> readers = const [],
    RecordPolicy policy = const RecordPolicy(),
    DateTime Function()? clock,
  }) async {
    final publicKey = await ed25519.publicKeyOf(signingSeed);
    return AxtNode._(
      store,
      Uint8List.fromList(signingSeed),
      publicKey,
      manifest,
      {for (final type in readers) type.name: type.schemaText},
      policy,
      clock ?? DateTime.now,
    );
  }

  final AxtStore _store;
  final Uint8List _seed;

  /// The app's own Ed25519 public key.
  final Uint8List publicKey;

  final Map<String, Object?> _manifest;
  final Map<String, String> _readers;
  final RecordPolicy _policy;
  final DateTime Function() _clock;

  /// The short fingerprint of the app's own key, for its settings.
  String get shortFingerprintOfOwnKey => shortFingerprint(publicKey);

  Future<DeviceSetReceiver> _receiver() async {
    final senders = <KnownSender>[];
    for (final key in await _store.list('sender/')) {
      final json = _decode((await _store.read(key))!)! as Map<String, Object?>;
      senders.add(
        KnownSender(
          json['name']! as String,
          current: {...(json['current']! as List<Object?>).cast<String>()},
          removed: {...(json['removed']! as List<Object?>).cast<String>()},
        ),
      );
    }
    final receiver = DeviceSetReceiver(senders: senders);
    final joined = await _store.read('joined');
    if (joined != null) {
      receiver.joinedInto.addAll(
        (_decode(joined)! as Map<String, Object?>).cast<String, String>(),
      );
    }
    return receiver;
  }

  Future<void> _saveSenders(DeviceSetReceiver receiver) async {
    await _store.write('joined', _encode(receiver.joinedInto));
    for (final key in await _store.list('sender/')) {
      await _store.delete(key);
    }
    for (final sender in receiver.senders) {
      await _store.write(
        'sender/${sender.name}',
        _encode({
          'name': sender.name,
          'current': sender.current.toList(),
          'removed': sender.removed.toList(),
        }),
      );
    }
  }

  Map<String, Object?> get _manifestValue => {'revision': 1, ..._manifest};

  /// The app's manifest with its revision, raised when the content changed
  /// since the revision it last sent (manifest.md, section 3.8).
  Future<Map<String, Object?>> _revisedManifest() async {
    final digest = _hex(crypto.sha256.convert(_encode(_manifest)).bytes);
    final stored = await _store.read('manifest');
    final json = stored == null
        ? null
        : _decode(stored)! as Map<String, Object?>;
    var revision = (json?['revision'] as int?) ?? 1;
    if (json != null && json['digest'] != digest) revision++;
    await _store.write(
      'manifest',
      _encode({'revision': revision, 'digest': digest}),
    );
    return {..._manifest, 'revision': revision};
  }

  /// Checks [file] as a whole and tells what it holds, applying nothing.
  ///
  /// Throws [AxtException] `FILE_REJECTED` for a file rejected as a whole.
  Future<FilePreview> inspect(Uint8List file) async {
    final checked = await checkFile(file);
    final sender = _hex(checked.sender);
    final receiver = await _receiver();
    await receiver.receiveChain(checked.chain);
    String? appName;
    final body = checked.manifest;
    if (body != null) {
      try {
        appName = (await checkManifest(body, 1))['app_name']! as String;
      } on AxtException {
        appName = null;
      }
    }
    final fitting = <String, int>{};
    final manifest = _manifestValue;
    for (final message in checked.records) {
      if (message.envelope.kind != Kind.data) continue;
      final writer =
          checked.schemas[SingleObjectHeader.parse(message.envelope.body)
              .fingerprint]!;
      if (fit(manifest, writer.schemaText, const []).fits) {
        fitting[writer.name] = (fitting[writer.name] ?? 0) + 1;
      }
    }
    final state = receiver.stateOf(sender);
    return FilePreview._(
      file: checked,
      sender: sender,
      shortFingerprint: shortFingerprint(checked.sender),
      appName: appName,
      firstContact: state == KeyState.unknown,
      senderRemoved: state == KeyState.removed,
      fitting: fitting,
    );
  }

  /// Applies the file of [preview], in one transaction of the store.
  ///
  /// A first contact is applied only with [acceptSender]. [onRecord] gets
  /// each record that changes what the app holds; [currentValue] gives the
  /// app's current value of a received record, or null for one its user
  /// deleted.
  Future<FileResult> apply(
    FilePreview preview, {
    required bool acceptSender,
    required Future<void> Function(RecordChange change) onRecord,
    required Future<Map<String, Object?>?> Function(String sender, String id)
    currentValue,
  }) => _store.transaction(() async {
    final file = preview.file;
    final receiver = await _receiver();
    await receiver.receiveChain(file.chain);
    final key = preview.sender;
    if (receiver.stateOf(key) == KeyState.unknown) {
      if (!acceptSender) return const FileResult(false, []);
      receiver.senders.add(KnownSender(key, current: {key}));
    }
    await _saveSenders(receiver);
    if (receiver.stateOf(key) != KeyState.current) {
      return FileResult(true, [
        for (final message in file.records)
          FileRecordResult(
            message.envelope.record!.id,
            message.envelope.record!.version,
            'SENDER_REMOVED',
          ),
      ]);
    }
    final sender = receiver.currentSenderOf(key)!.name;
    final held = <String, HeldRecord>{};
    final current = <String, Map<String, Object?>?>{};
    final ids = <String, String>{};
    for (final message in file.records) {
      final String id;
      try {
        id = recordKey(message.envelope.record!.id);
      } on AxtException {
        continue;
      }
      ids[id] = message.envelope.record!.id;
      if (held.containsKey(id)) continue;
      final stored = await _store.read('record/$sender/$id');
      if (stored == null) continue;
      final json = _decode(stored)! as Map<String, Object?>;
      final record = HeldRecord(
        version: json['version']! as int,
        state: HeldState.values.byName(json['state']! as String),
        type: json['type'] as String?,
        taken: json['taken'] as Map<String, Object?>?,
      );
      held[id] = record;
      current[id] = record.state == HeldState.there
          ? await currentValue(sender, id)
          : null;
    }
    final reader = FileReader(
      manifest: _manifestValue,
      readers: _readers,
      current: {_hex(publicKey)},
    );
    final results = await readFileRecords(
      file,
      reader,
      held: held,
      current: current,
      policy: _policy,
    );
    for (final result in results) {
      final applied = result.applied;
      if (applied == null) continue;
      final id = recordKey(result.id);
      await _store.write(
        'record/$sender/$id',
        _encode({
          'version': applied.held.version,
          'state': applied.held.state.name,
          'type': applied.held.type,
          'taken': applied.held.taken,
        }),
      );
      await _index(sender, id, applied.value, _decodedSchema(file, applied));
      if (applied.outcome == Outcome.applied ||
          applied.outcome == Outcome.merged ||
          applied.outcome == Outcome.withdrawn) {
        await onRecord(
          RecordChange(
            sender: sender,
            id: ids[id]!,
            type: applied.held.type,
            value: applied.value,
            outcome: applied.outcome,
          ),
        );
      }
    }
    return FileResult(true, results);
  });

  /// The schema a received record was decoded with: the reader's, or the
  /// writer's.
  Schema? _decodedSchema(CheckedFile file, Applied applied) {
    final type = applied.held.type;
    final reader = type == null ? null : _readers[type];
    if (reader != null) return parseTypeSchema(reader);
    for (final writer in file.schemas.values) {
      if (writer.name == type) return writer.schema;
    }
    return null;
  }

  /// Keeps the relations with a record target of the record [id] of
  /// [sender], whose [value] has [schema]; none for a record that is gone.
  Future<void> _index(
    String sender,
    String id,
    Map<String, Object?>? value,
    Schema? schema,
  ) async {
    final key = 'relations/$sender/$id';
    final relations = value == null || schema == null
        ? const <Map<String, Object?>>[]
        : recordTargets(schema, value);
    if (relations.isEmpty) {
      await _store.delete(key);
    } else {
      await _store.write(key, _encode(relations));
    }
  }

  Future<(RelationResolver, List<HeldRelation>)> _resolver() async {
    final receiver = await _receiver();
    final ownName = _hex(publicKey);
    final own = KnownSender(ownName, current: {ownName});
    final emptyBody = _hex(crypto.sha256.convert(const <int>[]).bytes);
    for (final key in await _store.list('own/')) {
      final json = _decode((await _store.read(key))!)! as Map<String, Object?>;
      own.records[key.substring(4)] = KeptRecord(
        json['version']! as int,
        json['digest'] == emptyBody ? RecordState.tombstone : RecordState.there,
      );
    }
    for (final key in await _store.list('record/')) {
      final cut = key.lastIndexOf('/');
      final name = receiver.senderNamed(key.substring(7, cut));
      final sender = receiver.senders.where((s) => s.name == name).firstOrNull;
      if (sender == null) continue;
      final json = _decode((await _store.read(key))!)! as Map<String, Object?>;
      final kept = KeptRecord(
        json['version']! as int,
        json['state'] == HeldState.there.name
            ? RecordState.there
            : RecordState.tombstone,
      );
      final id = key.substring(cut + 1);
      if ((sender.records[id]?.version ?? 0) < kept.version) {
        sender.records[id] = kept;
      }
    }
    final held = <HeldRelation>[];
    for (final key in await _store.list('relations/')) {
      final cut = key.lastIndexOf('/');
      final holder = key.substring(10, cut);
      for (final r
          in (_decode((await _store.read(key))!)! as List<Object?>)
              .cast<Map<String, Object?>>()) {
        held.add((
          id: r['id']! as String,
          holderSender: holder,
          holderId: key.substring(cut + 1),
          targetSender: r['sender'] as String?,
          targetId: r['target']! as String,
        ));
      }
    }
    return (RelationResolver(receiver, own), held);
  }

  /// The record that a relation of the record of [holderSender] points at,
  /// with [target] the relation's `target` as the record's value holds it;
  /// null while it does not resolve (`spec/records.md`, section 10.2).
  Future<RecordAddress?> resolve(
    String holderSender,
    Map<String, Object?> target,
  ) async {
    final id = target['id'];
    if (id is! String) return null;
    final sender = target['sender'];
    final (resolver, _) = await _resolver();
    final resolution = resolver.resolve((
      id: '',
      holderSender: holderSender,
      holderId: '',
      targetSender: sender is Uint8List ? _hex(sender) : null,
      targetId: id,
    ));
    return resolution.resolved
        ? RecordAddress(resolution.sender!, recordKey(id))
        : null;
  }

  /// The relations of the records the app holds, of every sender and its
  /// own, that resolve to the record [id] of [sender] (section 10.1).
  Future<List<Link>> linkedFrom(String sender, String id) async {
    final (resolver, held) = await _resolver();
    final key = recordKey(id);
    final name = resolver.receiver.senderNamed(sender);
    return [
      for (final linked in resolver.linkedFrom(held))
        if (linked.sender == name && linked.id == key)
          for (final f in linked.from)
            (holder: RecordAddress(f.sender, f.id), relation: f.relation),
    ];
  }

  Future<int> _stamp() async {
    final stored = await _store.read('stamp');
    final highest = stored == null ? 0 : _decode(stored)! as int;
    final stamp = nextStamp(
      highest,
      nowMs: _clock().millisecondsSinceEpoch,
      random: _random.nextInt(32768),
    );
    await _store.write('stamp', _encode(stamp));
    return stamp;
  }

  Future<Uint8List> _sign(Kind kind, RecordRef? record, Uint8List body) async {
    final unsigned = encodeMessage(
      Envelope(
        kind: kind,
        sender: publicKey,
        record: record,
        body: body,
        signature: Uint8List(64),
      ),
    );
    final signature = await ed25519.sign(
      _seed,
      signedBytesOfLiveMessage(unsigned),
    );
    return Uint8List.sublistView(
      unsigned..setAll(unsigned.length - 64, signature),
      10,
    );
  }

  /// The version of the app's own record [id] with the content [digest]: the
  /// version it has, or a new state stamp when the content changed.
  Future<int> _versionOf(String id, String digest) async {
    final stored = await _store.read('own/$id');
    final json = stored == null
        ? null
        : _decode(stored)! as Map<String, Object?>;
    if (json != null && json['digest'] == digest) {
      return json['version']! as int;
    }
    final version = await _stamp();
    await _store.write(
      'own/$id',
      _encode({'version': version, 'digest': digest}),
    );
    return version;
  }

  /// Writes an AXT file of [shared], the app's records shared with
  /// [receiver] now, the key of an app of another user; or, with [receiver]
  /// null, an export of the records its user chose.
  ///
  /// For a receiver, the file also holds the `WITHDRAW` of every record that
  /// was sent to it before and is no longer shared with it
  /// (`spec/shares.md`, sections 5.3 and 8.2).
  ///
  /// A record goes without its links (`spec/shares.md`, section 19.1) unless
  /// it is [OutgoingRecord.withLinks], or [ownUser] says that the receiver
  /// is an app of the app's own user, which gets every record whole.
  Future<Uint8List> writeFile(
    List<OutgoingRecord> shared, {
    Uint8List? receiver,
    bool ownUser = false,
  }) => _store.transaction(() async {
    final sharedIds = {
      for (final record in shared)
        if (record.value != null) record.id,
    };
    final datums = <Uint8List>[];
    final schemas = <int, TypeDescription>{};
    final manifest = AvroCodec(writer: axtSchema('axt.Manifest'))
        .encodeSingleObject(await _revisedManifest());
    datums.add(await _sign(Kind.manifest, null, manifest));
    final to = receiver == null ? null : _hex(receiver);
    final ids = <String>{};
    for (final record in shared) {
      final id = recordKey(record.id);
      ids.add(id);
      final value = record.value;
      final Kind kind;
      final Uint8List body;
      Uint8List whole;
      if (value == null) {
        kind = Kind.delete;
        body = whole = Uint8List(0);
      } else {
        kind = Kind.data;
        final type = record.type!;
        schemas[type.fingerprint] = type;
        final codec = AvroCodec(writer: type.schema);
        // The version follows the record whole, whatever goes along.
        whole = codec.encodeSingleObject(value);
        body = record.withLinks || ownUser
            ? whole
            : codec.encodeSingleObject(
                withoutLinks(
                  type.schema,
                  value,
                  shared: sharedIds,
                  ownKeys: {_hex(publicKey)},
                ),
              );
      }
      await _index(_hex(publicKey), id, value, record.type?.schema);
      final digest = _hex(crypto.sha256.convert(whole).bytes);
      var version = await _versionOf(id, digest);
      final withdrawal = to == null
          ? null
          : await _store.read('withdrawal/$to/$id');
      if (withdrawal != null && (_decode(withdrawal)! as int) >= version) {
        // Shared again: a version above the withdrawal (shares.md, 6.2).
        version = await _stamp();
        await _store.write(
          'own/$id',
          _encode({'version': version, 'digest': digest}),
        );
      }
      datums.add(await _sign(kind, RecordRef(record.id, version), body));
      if (to != null) {
        // Sending the record again supersedes its last withdrawal.
        await _store.delete('withdrawal/$to/$id');
        await _store.write(
          'sent/$to/$id',
          _encode({'kind': kind.symbol, 'id': record.id}),
        );
      }
    }
    if (to != null) {
      for (final key in await _store.list('sent/$to/')) {
        final id = key.substring('sent/$to/'.length);
        if (ids.contains(id)) continue;
        final sent =
            _decode((await _store.read(key))!)! as Map<String, Object?>;
        final withdrawal = await _store.read('withdrawal/$to/$id');
        final int version;
        if (sent['kind'] == 'DATA') {
          version = await _stamp();
          await _store.write('withdrawal/$to/$id', _encode(version));
        } else if (withdrawal != null) {
          version = _decode(withdrawal)! as int;
        } else {
          continue;
        }
        final body = AvroCodec(writer: axtSchema('axt.Withdraw'))
            .encodeSingleObject({'to': receiver});
        datums.add(
          await _sign(
            Kind.withdraw,
            RecordRef(sent['id']! as String, version),
            body,
          ),
        );
        await _store.write(
          key,
          _encode({'kind': 'WITHDRAW', 'id': sent['id']}),
        );
      }
    }
    final schemasText = schemas.isEmpty
        ? null
        : utf8.encode(
            jsonEncode([for (final t in schemas.values) t.fileEntry]),
          );
    final signature = await ed25519.sign(
      _seed,
      fileHeaderSignedBytes(publicKey, schemasText),
    );
    return writeContainer(
      {
        'avro.schema': utf8.encode(axtSchemaText('axt.Envelope')),
        'axt.schemas': ?schemasText,
        'axt.sender': ascii.encode(_hex(publicKey)),
        'axt.signature': ascii.encode(_hex(signature)),
      },
      datums,
      syncMarker: Uint8List.fromList([
        for (var i = 0; i < 16; i++) _random.nextInt(256),
      ]),
    );
  });
}
