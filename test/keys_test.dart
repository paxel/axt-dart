import 'dart:convert';
import 'dart:typed_data';

import 'package:axt_protocol/src/device_sets.dart';
import 'package:axt_protocol/src/ed25519.dart';
import 'package:axt_protocol/src/envelope.dart';
import 'package:axt_protocol/src/errors.dart';
import 'package:axt_protocol/src/sealing.dart';
import 'package:axt_protocol/src/signing.dart';
import 'package:crypto/crypto.dart' as crypto;
import 'package:cryptography/cryptography.dart' as c;
import 'package:test/test.dart';

import 'envelope_test.dart' show deleteHex, unhex;
import 'key_fixtures.dart';

Matcher rejectedWith(ErrorCode code) =>
    throwsA(isA<AxtException>().having((e) => e.code, 'code', code));

void main() {
  group('Ed25519', () {
    // RFC 8032, section 7.1, TEST 1.
    final seed = unhex(
      '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60',
    );
    const publicHex =
        'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a';
    const signatureHex =
        'e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155'
        '5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b';

    test('signs and verifies the test of RFC 8032', () async {
      expect(toHex(await publicKeyOf(seed)), publicHex);
      expect(toHex(await sign(seed, [])), signatureHex);
      expect(
        await verifyStrict(unhex(publicHex), [], unhex(signatureHex)),
        isTrue,
      );
      expect(
        await verifyStrict(unhex(publicHex), [1], unhex(signatureHex)),
        isFalse,
      );
    });

    test('rejects S of L or above, bad lengths and bad points', () async {
      final big = unhex(signatureHex)..setAll(32, List.filled(32, 0xff));
      expect(await verifyStrict(unhex(publicHex), [], big), isFalse);
      expect(await verifyStrict(unhex(publicHex), [], Uint8List(63)), isFalse);
      expect(
        await verifyStrict(Uint8List(31), [], unhex(signatureHex)),
        isFalse,
      );
      final neutralR = unhex(signatureHex)
        ..setAll(0, [1, ...List.filled(31, 0)]);
      expect(await verifyStrict(unhex(publicHex), [], neutralR), isFalse);
    });

    test('a point of order L, and the ones that are not', () {
      expect(isPointOfOrderL(unhex(publicHex)), isTrue);
      for (final small in [
        '0100000000000000000000000000000000000000000000000000000000000000',
        '0000000000000000000000000000000000000000000000000000000000000080',
        'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
        'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a',
        'edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
      ]) {
        expect(isPointOfOrderL(unhex(small)), isFalse, reason: small);
      }
      expect(isPointOfOrderL(Uint8List(31)), isFalse);
      // Some y have no x at all; some need the square root of -1.
      final outcomes = {
        for (var y = 2; y < 40; y++)
          isPointOfOrderL([y, ...List.filled(31, 0)]),
      };
      expect(outcomes, contains(false));
    });
  });

  test('the short fingerprint of the test key of keys.md', () async {
    final seed = crypto.sha256
        .convert(
          utf8.encode(
            'AXT test key, not for use: cat-a-log, old phone, Ed25519',
          ),
        )
        .bytes;
    final key = await publicKeyOf(seed);
    expect(shortFingerprint(key), matches(RegExp(r'^\d{5}( \d{5}){4}$')));
  });

  group('sealing', () {
    test('pads to P(n)', () {
      expect(paddedLength(0), 1024);
      expect(paddedLength(210), 1024);
      expect(paddedLength(1023), 1024);
      expect(paddedLength(1024), 1088);
      expect(paddedLength(4000), 4096);
      expect(paddedLength(100000), 100352);
      expect(paddedLength(16777216), 17301504);
    });

    Future<(Uint8List, Uint8List)> x25519Pair() async {
      final pair = await c.X25519().newKeyPair();
      return (
        Uint8List.fromList(await pair.extractPrivateKeyBytes()),
        Uint8List.fromList((await pair.extractPublicKey()).bytes),
      );
    }

    test('seals and opens, with the right key among others', () async {
      final (private, public) = await x25519Pair();
      final (other, _) = await x25519Pair();
      final message = unhex(deleteHex);
      final sealed = await seal(message, public);
      expect(sealed.length, 1 + 32 + 1024 + 16);
      expect(sealed[0], 1);
      expect(await open(sealed, [other, private]), message);
      expect(() => open(sealed, [other]), rejectedWith(ErrorCode.notOpened));
      expect(
        () => open(Uint8List.fromList(sealed)..[0] = 2, [private]),
        rejectedWith(ErrorCode.notOpened),
      );
      expect(
        () => open([1, 2, 3], [private]),
        rejectedWith(ErrorCode.notOpened),
      );
      expect(
        () => open(sealed, [Uint8List(32)]),
        rejectedWith(ErrorCode.notOpened),
      );
    });

    test('rejects a plaintext without its padding', () async {
      final (private, public) = await x25519Pair();
      for (final plaintext in [
        Uint8List(1024),
        Uint8List.fromList([1, 2, 3]),
      ]) {
        final sealed = await sealPlaintext(plaintext, public);
        expect(
          () => open(sealed, [private]),
          rejectedWith(ErrorCode.paddingInvalid),
        );
      }
    });

    test('rejects encryption keys of small order', () async {
      final (_, public) = await x25519Pair();
      expect(await isSmallOrderEncryptionKey(public), isFalse);
      expect(await isSmallOrderEncryptionKey(Uint8List(32)), isTrue);
      expect(await isSmallOrderEncryptionKey(Uint8List(31)), isTrue);
      expect(
        () => seal([1], Uint8List(32)),
        rejectedWith(ErrorCode.encryptionKeyInvalid),
      );
    });
  });

  group('device sets', () {
    late TestKey a, b, c2, d, e;
    setUpAll(() async {
      a = await TestKey.named('a');
      b = await TestKey.named('b');
      c2 = await TestKey.named('c');
      d = await TestKey.named('d');
      e = await TestKey.named('e');
    });

    DeviceSetReceiver receiverOf(
      Map<String, List<TestKey>> current, {
      Map<String, List<TestKey>> removed = const {},
      Set<String> refused = const {},
    }) => DeviceSetReceiver(
      senders: [
        for (final entry in current.entries)
          KnownSender(
            entry.key,
            current: {for (final k in entry.value) k.hex},
            removed: {for (final k in removed[entry.key] ?? <TestKey>[]) k.hex},
          ),
      ],
      refused: Set.of(refused),
    );

    Future<List<String>> codes(
      DeviceSetReceiver receiver,
      List<Future<Uint8List>> chain,
    ) async => [
      for (final r in (await receiver.receiveChain(
        await Future.wait(chain),
      )).results)
        r.code,
    ];

    test(
      'adds, repeats, removes, and rejects what a removed key signs',
      () async {
        final receiver = receiverOf({
          's': [a],
        });
        expect(
          await codes(receiver, [
            deviceAdd(a, b),
            deviceAdd(a, b),
            deviceRemove(a, b),
            deviceAdd(a, b),
            deviceRemove(b, a),
            deviceRemove(b, b),
            deviceRemove(a, b),
            deviceAdd(b, c2),
          ]),
          [
            'APPLIED',
            'IGNORED',
            'APPLIED',
            'IGNORED',
            'DEVICE_REJECTED',
            'DEVICE_REJECTED',
            'IGNORED',
            'DEVICE_REJECTED',
          ],
        );
        expect(receiver.stateOf(b.hex), KeyState.removed);
        expect(receiver.stateOf(a.hex), KeyState.current);
        expect(receiver.currentSenderOf(a.hex)?.name, 's');
        expect(receiver.currentSenderOf(b.hex), isNull);
        expect(receiver.stateOf(e.hex), KeyState.unknown);
      },
    );

    test('a removal by a removed key of a key it does not have', () async {
      final receiver = receiverOf(
        {
          's': [a],
        },
        removed: {
          's': [b],
        },
      );
      expect(await codes(receiver, [deviceRemove(b, c2)]), ['DEVICE_REJECTED']);
    });

    test(
      'joins a sender of one key into the signer, keeping records',
      () async {
        final receiver = receiverOf({
          's': [a],
          't': [c2],
        });
        receiver.senders[0].records['r1'] = const KeptRecord(
          2,
          RecordState.there,
        );
        receiver.senders[1].records
          ..['r1'] = const KeptRecord(3, RecordState.tombstone)
          ..['r2'] = const KeptRecord(1, RecordState.there);
        expect(await codes(receiver, [deviceAdd(a, c2)]), ['APPLIED']);
        expect(receiver.senders.single.name, 's');
        expect(receiver.senders.single.records['r1']?.version, 3);
        expect(receiver.senders.single.records['r2']?.version, 1);
      },
    );

    test(
      'joins the signer of one key into a device with further keys',
      () async {
        final receiver = receiverOf({
          's': [a, b],
          't': [c2],
        });
        expect(await codes(receiver, [deviceAdd(c2, a)]), ['APPLIED']);
        expect(receiver.senders.single.name, 's');
        expect(receiver.senders.single.current, hasLength(3));
      },
    );

    test('rejects joining two senders that each have more keys', () async {
      final receiver = receiverOf({
        's': [a, b],
        't': [c2, d],
      });
      expect(await codes(receiver, [deviceAdd(a, c2)]), ['DEVICE_REJECTED']);
      final removed = receiverOf(
        {
          's': [a],
          't': [d],
        },
        removed: {
          't': [c2],
        },
      );
      expect(await codes(removed, [deviceAdd(a, c2)]), ['DEVICE_REJECTED']);
    });

    test('refused signers and devices', () async {
      final receiver = receiverOf(
        {
          's': [a],
        },
        refused: {b.hex, c2.hex},
      );
      expect(await codes(receiver, [deviceAdd(b, d), deviceAdd(a, c2)]), [
        'REFUSED',
        'DEVICE_REJECTED',
      ]);
      expect(receiver.stateOf(b.hex), KeyState.refused);
    });

    test('an unknown signer added by the device it vouches for', () async {
      final receiver = receiverOf({
        's': [a],
      });
      expect(await codes(receiver, [deviceAdd(b, a)]), ['APPLIED']);
      expect(receiver.currentSenderOf(b.hex)?.name, 's');
    });

    test('keeps what it cannot place and tries it again', () async {
      final receiver = receiverOf({
        's': [a],
      });
      expect(
        await codes(receiver, [
          deviceAdd(b, c2),
          deviceRemove(a, d),
          deviceRemove(e, d),
          deviceAdd(a, b),
          deviceAdd(a, d),
        ]),
        ['APPLIED', 'APPLIED', 'NOT_PLACED', 'APPLIED', 'APPLIED'],
      );
      expect(receiver.stateOf(c2.hex), KeyState.current);
      expect(receiver.stateOf(d.hex), KeyState.removed);
      final later = receiverOf({
        's': [a],
      });
      expect(await codes(later, [deviceRemove(a, e)]), ['IGNORED']);
    });

    test('bad signatures, bad proofs, bad keys and other kinds', () async {
      final receiver = receiverOf({
        's': [a],
      });
      expect(
        await codes(receiver, [
          deviceAdd(a, b).then(tampered),
          deviceAdd(a, b, proof: Uint8List(64)),
          deviceAdd(a, b, deviceKey: Uint8List(32)),
          Future.value(unhex(deleteHex)),
        ]),
        [
          'SIGNATURE_INVALID',
          'DEVICE_REJECTED',
          'DEVICE_REJECTED',
          'DEVICE_REJECTED',
        ],
      );
    });

    test('a member answers a DEVICE_JOIN', () async {
      Future<JoinAction> answer(
        Uint8List message, {
        Set<String> current = const {},
        Set<String> removed = const {},
        Uint8List? first,
      }) => answerDeviceJoin(
        message,
        member: a.public,
        current: current,
        removed: removed,
        first: first,
      );
      expect(await answer(await deviceJoin(b, a)), JoinAction.ask);
      expect(await answer(await deviceJoin(b, c2)), JoinAction.ignore);
      expect(
        await answer(await deviceJoin(b, a), first: c2.public),
        JoinAction.ignore,
      );
      expect(
        await answer(await deviceJoin(b, a), first: b.public),
        JoinAction.ask,
      );
      expect(
        await answer(await deviceJoin(b, a), current: {b.hex}),
        JoinAction.sendChain,
      );
      expect(await answer(await deviceJoin(a, a)), JoinAction.sendChain);
      expect(
        () async => answer(await deviceJoin(b, a), removed: {b.hex}),
        rejectedWith(ErrorCode.deviceRejected),
      );
      expect(
        () async => answer(await deviceJoin(b, a, proof: Uint8List(64))),
        rejectedWith(ErrorCode.deviceRejected),
      );
      expect(
        () async => answer(tampered(await deviceJoin(b, a))),
        rejectedWith(ErrorCode.signatureInvalid),
      );
      expect(
        () async => answer(await deviceAdd(a, b)),
        rejectedWith(ErrorCode.invalidMessage),
      );
    });

    test('a new device takes the chain that adds it', () async {
      Future<bool> takes(List<Uint8List> chain) =>
          takesJoinChain(chain, member: a.public, device: b.public);
      expect(
        await takes([await deviceAdd(a, c2), await deviceAdd(a, b)]),
        isTrue,
      );
      expect(await takes([await deviceAdd(c2, b)]), isFalse);
      expect(
        await takes([await deviceAdd(a, b, proof: await proofOf(b, c2))]),
        isFalse,
      );
      expect(
        await takes([await deviceAdd(a, b), await deviceRemove(c2, b)]),
        isFalse,
      );
      expect(await takes([tampered(await deviceAdd(a, b))]), isFalse);
      expect(await takes([unhex(deleteHex)]), isFalse);
      expect(await takes([]), isFalse);
    });

    test('DeviceChange decodes additions and removals only', () async {
      final change = DeviceChange.decode(await deviceRemove(a, b));
      expect(change.kind, Kind.deviceRemove);
      expect(change.proof, isNull);
      expect(
        () => DeviceChange.decode(unhex(deleteHex)),
        rejectedWith(ErrorCode.invalidMessage),
      );
    });
  });
}
