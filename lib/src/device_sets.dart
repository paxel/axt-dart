/// Device sets: adding and removing devices, and a receiver that follows the
/// devices of its known senders (AXT `spec/keys.md`, section 5).
library;

import 'dart:typed_data';

import 'ed25519.dart';
import 'envelope.dart';
import 'errors.dart';
import 'signing.dart';

/// A `DEVICE_ADD` or `DEVICE_REMOVE`, decoded.
final class DeviceChange {
  DeviceChange._(this.message, this.kind, this.signer, this.device, this.proof);

  /// Decodes [message], a live message of the kind `DEVICE_ADD` or
  /// `DEVICE_REMOVE`; throws [AxtException] `INVALID_MESSAGE` otherwise.
  factory DeviceChange.decode(Uint8List message) {
    final envelope = decodeMessage(message);
    if (envelope.kind != Kind.deviceAdd && envelope.kind != Kind.deviceRemove) {
      throw AxtException(
        ErrorCode.invalidMessage,
        '${envelope.kind.symbol} is no addition or removal',
      );
    }
    final body =
        decodeBody(envelope.kind, envelope.body)! as Map<String, Object?>;
    return DeviceChange._(
      message,
      envelope.kind,
      envelope.sender,
      body['device']! as Uint8List,
      body['proof'] as Uint8List?,
    );
  }

  /// The message as received.
  final Uint8List message;

  /// `DEVICE_ADD` or `DEVICE_REMOVE`.
  final Kind kind;

  /// The message's `sender`.
  final Uint8List signer;

  /// The body's `device`.
  final Uint8List device;

  /// The proof of a `DEVICE_ADD`; null for a `DEVICE_REMOVE`.
  final Uint8List? proof;

  bool get isAdd => kind == Kind.deviceAdd;

  /// Step 1: whether the message's signature verifies with the signer's key.
  Future<bool> signatureVerifies() => verifyLiveMessage(message, signer);

  /// Step 2: whether the device's key and the proof of an addition verify,
  /// and a removal does not remove its own signer.
  Future<bool> deviceVerifies() async {
    if (!isAdd) return !_same(device, signer);
    if (!isPointOfOrderL(device)) return false;
    return verifyStrict(device, deviceAddProofBytes(signer, device), proof!);
  }
}

bool _same(List<int> a, List<int> b) {
  if (a.length != b.length) return false;
  for (var i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}

String _hex(List<int> bytes) =>
    [for (final b in bytes) b.toRadixString(16).padLeft(2, '0')].join();

/// The result of a `DEVICE_ADD` or `DEVICE_REMOVE` at a receiver.
enum ChangeResult {
  applied('APPLIED'),
  ignored('IGNORED'),
  deviceRejected('DEVICE_REJECTED'),
  signatureInvalid('SIGNATURE_INVALID'),
  refused('REFUSED'),
  notPlaced('NOT_PLACED');

  const ChangeResult(this.code);

  /// The result as the conformance vectors write it.
  final String code;
}

/// The state of a record a receiver keeps.
enum RecordState { there, tombstone }

/// What a receiver keeps of one record: its version and its state.
final class KeptRecord {
  const KeptRecord(this.version, this.state);

  final int version;

  final RecordState state;
}

/// A sender a receiver knows: its keys, by hexadecimal text, and its records.
final class KnownSender {
  KnownSender(
    this.name, {
    Set<String>? current,
    Set<String>? removed,
    Map<String, KeptRecord>? records,
  }) : current = current ?? {},
       removed = removed ?? {},
       records = records ?? {};

  /// The name by which the receiver shows the sender.
  final String name;

  final Set<String> current;

  final Set<String> removed;

  final Map<String, KeptRecord> records;

  /// Whether the sender has only one key, current and not removed.
  bool get hasOneKey => current.length == 1 && removed.isEmpty;
}

/// What the key that sent a chain is to the receiver after it.
enum KeyState { current, removed, refused, unknown }

/// The outcome of one chain at a [DeviceSetReceiver].
final class ChainOutcome {
  const ChainOutcome(this.results);

  /// One result for each message of the chain, the last try of a kept one.
  final List<ChangeResult> results;
}

/// The outcome of a message tried by the table: one of the results, or kept.
enum _Try { applied, ignored, rejected, refused, notPlaced, keptRemoval }

/// A receiver that follows the devices of its known senders (section 5.5).
final class DeviceSetReceiver {
  DeviceSetReceiver({List<KnownSender>? senders, Set<String>? refused})
    : senders = senders ?? [],
      refused = refused ?? {};

  /// The senders the receiver knows.
  final List<KnownSender> senders;

  /// The receiver's refused keys (section 3.4).
  final Set<String> refused;

  KnownSender? _senderOf(String key) {
    for (final sender in senders) {
      if (sender.current.contains(key) || sender.removed.contains(key)) {
        return sender;
      }
    }
    return null;
  }

  /// What [key] is to the receiver.
  KeyState stateOf(String key) {
    if (refused.contains(key)) return KeyState.refused;
    final sender = _senderOf(key);
    if (sender == null) return KeyState.unknown;
    return sender.current.contains(key) ? KeyState.current : KeyState.removed;
  }

  /// The sender of which [key] is a current key, or null.
  KnownSender? currentSenderOf(String key) {
    final sender = _senderOf(key);
    return sender != null && sender.current.contains(key) ? sender : null;
  }

  /// Takes the messages of one chain in their order (section 5.5).
  Future<ChainOutcome> receiveChain(List<Uint8List> chain) async {
    final results = List<ChangeResult>.filled(
      chain.length,
      ChangeResult.ignored,
    );
    final changes = <DeviceChange?>[];
    final kept = <int>[];
    void record(int index, _Try outcome) {
      results[index] = switch (outcome) {
        _Try.applied => ChangeResult.applied,
        _Try.ignored || _Try.keptRemoval => ChangeResult.ignored,
        _Try.rejected => ChangeResult.deviceRejected,
        _Try.refused => ChangeResult.refused,
        _Try.notPlaced => ChangeResult.notPlaced,
      };
    }

    void retryKept() {
      var applied = true;
      while (applied) {
        applied = false;
        for (final index in List.of(kept)) {
          final outcome = _table(changes[index]!);
          record(index, outcome);
          if (outcome == _Try.applied) {
            kept.remove(index);
            applied = true;
            break;
          }
        }
      }
    }

    for (var i = 0; i < chain.length; i++) {
      final DeviceChange change;
      try {
        change = DeviceChange.decode(chain[i]);
      } on AxtException {
        changes.add(null);
        results[i] = ChangeResult.deviceRejected;
        continue;
      }
      changes.add(change);
      if (!await change.signatureVerifies()) {
        results[i] = ChangeResult.signatureInvalid;
        continue;
      }
      if (!await change.deviceVerifies()) {
        results[i] = ChangeResult.deviceRejected;
        continue;
      }
      final outcome = _table(change);
      record(i, outcome);
      if (outcome == _Try.notPlaced || outcome == _Try.keptRemoval) {
        kept.add(i);
      } else if (outcome == _Try.applied && change.isAdd) {
        retryKept();
      }
    }
    retryKept();
    return ChainOutcome(results);
  }

  /// Steps 3 and 4 for a message whose signature and device verified.
  _Try _table(DeviceChange change) {
    final signer = _hex(change.signer);
    final device = _hex(change.device);
    if (refused.contains(signer)) return _Try.refused;
    final own = _senderOf(signer);
    if (own == null) {
      final vouching = change.isAdd ? currentSenderOf(device) : null;
      if (vouching == null) return _Try.notPlaced;
      vouching.current.add(signer);
      return _Try.applied;
    }
    final signerCurrent = own.current.contains(signer);
    if (own.current.contains(device)) {
      if (change.isAdd) return _Try.ignored;
      if (!signerCurrent) return _Try.rejected;
      own.current.remove(device);
      own.removed.add(device);
      return _Try.applied;
    }
    if (own.removed.contains(device)) return _Try.ignored;
    if (!change.isAdd) return signerCurrent ? _Try.keptRemoval : _Try.rejected;
    if (!signerCurrent) return _Try.rejected;
    final other = _senderOf(device);
    if (refused.contains(device)) return _Try.rejected;
    if (other == null) {
      own.current.add(device);
      return _Try.applied;
    }
    if (!other.current.contains(device)) return _Try.rejected;
    if (other.hasOneKey) {
      _join(stays: own, joins: other);
      return _Try.applied;
    }
    if (own.hasOneKey) {
      _join(stays: other, joins: own);
      return _Try.applied;
    }
    return _Try.rejected;
  }

  /// Joins the sender [joins] into [stays] (section 5.5, joining two senders).
  void _join({required KnownSender stays, required KnownSender joins}) {
    stays.current.addAll(joins.current);
    stays.removed.addAll(joins.removed);
    for (final entry in joins.records.entries) {
      final kept = stays.records[entry.key];
      if (kept == null || entry.value.version > kept.version) {
        stays.records[entry.key] = entry.value;
      }
    }
    senders.remove(joins);
  }
}

/// What a member does with a `DEVICE_JOIN` (section 5.2).
enum JoinAction { ask, sendChain, ignore }

/// The member's answer to the `DEVICE_JOIN` [message], when its own key is
/// [member], its set's other keys are [current] and [removed], and [first] is
/// the sender of the first `DEVICE_JOIN` for this join code, or null.
///
/// Throws [AxtException] `SIGNATURE_INVALID` for a message whose signature
/// does not verify, and `DEVICE_REJECTED` for a proof that does not verify
/// or a removed key of the set.
Future<JoinAction> answerDeviceJoin(
  Uint8List message, {
  required Uint8List member,
  required Set<String> current,
  required Set<String> removed,
  required Uint8List? first,
}) async {
  final envelope = decodeMessage(message);
  if (envelope.kind != Kind.deviceJoin) {
    throw AxtException(
      ErrorCode.invalidMessage,
      '${envelope.kind.symbol} is no DEVICE_JOIN',
    );
  }
  if (!await verifyLiveMessage(message, envelope.sender)) {
    throw const AxtException(
      ErrorCode.signatureInvalid,
      'the DEVICE_JOIN does not verify',
    );
  }
  final body =
      decodeBody(Kind.deviceJoin, envelope.body)! as Map<String, Object?>;
  if (!_same(body['to']! as Uint8List, member)) return JoinAction.ignore;
  if (first != null && !_same(first, envelope.sender)) return JoinAction.ignore;
  final proofVerifies = await verifyStrict(
    envelope.sender,
    deviceAddProofBytes(member, envelope.sender),
    body['proof']! as Uint8List,
  );
  final key = _hex(envelope.sender);
  if (!proofVerifies || removed.contains(key)) {
    throw const AxtException(
      ErrorCode.deviceRejected,
      'the proof does not verify or the key was removed',
    );
  }
  if (key == _hex(member) || current.contains(key)) return JoinAction.sendChain;
  return JoinAction.ask;
}

/// Whether a new device with the key [device] takes [chain], the answer to
/// its `DEVICE_JOIN` to [member] (section 5.2, step 5).
Future<bool> takesJoinChain(
  List<Uint8List> chain, {
  required Uint8List member,
  required Uint8List device,
}) async {
  var added = false;
  for (final message in chain) {
    final DeviceChange change;
    try {
      change = DeviceChange.decode(message);
    } on AxtException {
      return false;
    }
    if (!await change.signatureVerifies()) return false;
    if (!_same(change.device, device)) continue;
    if (!change.isAdd) return false;
    if (_same(change.signer, member) &&
        await verifyStrict(
          device,
          deviceAddProofBytes(member, device),
          change.proof!,
        )) {
      added = true;
    }
  }
  return added;
}
