import 'dart:typed_data';

import 'package:axt_protocol/src/conformance_adapter.dart';
import 'package:axt_protocol/src/device_sets.dart';
import 'package:cryptography/cryptography.dart' as c;
import 'package:test/test.dart';

import 'envelope_test.dart' show deleteHex;
import 'key_fixtures.dart';

Future<Map<String, Object?>> run(String op, Object? input) =>
    answer({'id': 'v', 'op': op, 'input': input});

Future<Object?> output(String op, Object? input) async {
  final reply = await run(op, input);
  expect(reply, contains('output'), reason: '$reply');
  return reply['output'];
}

Future<void> fails(String op, Object? input) async {
  expect(await run(op, input), containsPair('failure', isA<String>()));
}

const accepted = {'accept': <String, Object?>{}};

Map<String, Object?> rejected(String code) => {
  'reject': {'error': code},
};

void main() {
  late TestKey a, b;
  setUpAll(() async {
    a = await TestKey.named('a');
    b = await TestKey.named('b');
  });

  test('public_key, sign, verify', () async {
    expect(await output('public_key', {'seed': toHex(a.seed)}), {
      'accept': {'public_key': a.hex},
    });
    final signed =
        (await output('sign', {'seed': toHex(a.seed), 'data': '01'}))! as Map;
    final signature = signed['accept']['signature'] as String;
    expect(
      await output('verify', {
        'public_key': a.hex,
        'data': '01',
        'signature': signature,
      }),
      accepted,
    );
    expect(
      await output('verify', {
        'public_key': a.hex,
        'data': '02',
        'signature': signature,
      }),
      rejected('SIGNATURE_INVALID'),
    );
  });

  test('check_signing_key, check_encryption_key, short_fingerprint', () async {
    expect(await output('check_signing_key', {'public_key': a.hex}), accepted);
    expect(
      await output('check_signing_key', {'public_key': '00' * 32}),
      rejected('KEY_INVALID'),
    );
    final pair = await c.X25519().newKeyPair();
    final public = toHex((await pair.extractPublicKey()).bytes);
    expect(
      await output('check_encryption_key', {'encryption_key': public}),
      accepted,
    );
    expect(
      await output('check_encryption_key', {'encryption_key': '00' * 32}),
      rejected('ENCRYPTION_KEY_INVALID'),
    );
    final fingerprint =
        ((await output('short_fingerprint', {'public_key': a.hex}))! as Map);
    expect(fingerprint['accept']['short_fingerprint'], hasLength(29));
  });

  test('verify_message', () async {
    final message = await deviceRemove(a, b);
    expect(
      await output('verify_message', {'message': toHex(message)}),
      accepted,
    );
    expect(
      await output('verify_message', {'message': toHex(tampered(message))}),
      rejected('SIGNATURE_INVALID'),
    );
  });

  test('device_add', () async {
    expect(
      await output('device_add', {'message': toHex(await deviceAdd(a, b))}),
      {
        'accept': {'member': a.hex, 'device': b.hex},
      },
    );
    expect(
      await output('device_add', {
        'message': toHex(tampered(await deviceAdd(a, b))),
      }),
      rejected('SIGNATURE_INVALID'),
    );
    expect(
      await output('device_add', {
        'message': toHex(await deviceAdd(a, b, proof: Uint8List(64))),
      }),
      rejected('DEVICE_REJECTED'),
    );
    await fails('device_add', {'message': toHex(await deviceRemove(a, b))});
    expect(await output('device_add', {'message': deleteHex}), {
      'reject': {'error': 'INVALID_MESSAGE'},
    });
  });

  test('device_join', () async {
    final join = toHex(await deviceJoin(b, a));
    Future<Object?> answerOf(
      Object? first, {
      List<String> removed = const [],
    }) => output('device_join', {
      'message': join,
      'member': {'key': a.hex, 'current': <String>[], 'removed': removed},
      'first': first,
    });
    expect(await answerOf(null), {
      'accept': {'device': b.hex, 'action': 'ask'},
    });
    expect(await answerOf(a.hex), {
      'accept': {'device': b.hex, 'action': 'ignore'},
    });
    expect(await answerOf(null, removed: [b.hex]), rejected('DEVICE_REJECTED'));
    final own = toHex(await deviceJoin(a, a));
    expect(
      await output('device_join', {
        'message': own,
        'member': {'key': a.hex, 'current': <String>[], 'removed': <String>[]},
        'first': null,
      }),
      {
        'accept': {'device': a.hex, 'action': 'send_chain'},
      },
    );
    await fails('device_join', {
      'message': join,
      'member': {'key': a.hex, 'current': 'x', 'removed': <String>[]},
      'first': null,
    });
  });

  test('join_chain', () async {
    final chain = [toHex(await deviceAdd(a, b))];
    expect(
      await output('join_chain', {
        'chain': chain,
        'member': a.hex,
        'device': b.hex,
      }),
      accepted,
    );
    expect(
      await output('join_chain', {
        'chain': <String>[],
        'member': a.hex,
        'device': b.hex,
      }),
      rejected('JOIN_INVALID'),
    );
    await fails('join_chain', {'chain': 'x', 'member': a.hex, 'device': b.hex});
  });

  test('device_sets', () async {
    final add = toHex(await deviceAdd(a, b));
    final result =
        (await output('device_sets', {
              'senders': [
                {
                  'name': 's',
                  'current': [a.hex],
                  'removed': <String>[],
                  'records': [
                    {'id': 'r2', 'version': 1, 'state': 'there'},
                    {'id': 'r1', 'version': 2, 'state': 'tombstone'},
                  ],
                },
              ],
              'refused': <String>[],
              'steps': [
                {
                  'chain': [add],
                  'key': b.hex,
                },
                {'chain': <String>[], 'key': null},
              ],
            }))!
            as Map<String, Object?>;
    final steps = result['steps']! as List<Object?>;
    expect(steps[0], {
      'results': ['APPLIED'],
      'key_state': 'current',
      'key_sender': 's',
      'senders': [
        {
          'name': 's',
          'current': ([a.hex, b.hex]..sort()),
          'removed': <String>[],
          'records': [
            {'id': 'r1', 'version': 2, 'state': 'tombstone'},
            {'id': 'r2', 'version': 1, 'state': 'there'},
          ],
        },
      ],
    });
    expect((steps[1]! as Map)['key_state'], isNull);
    for (final bad in [
      {'senders': 'x', 'refused': <String>[], 'steps': <Object?>[]},
      {
        'senders': ['x'],
        'refused': <String>[],
        'steps': <Object?>[],
      },
      {
        'senders': [
          {
            'name': 's',
            'current': <String>[],
            'removed': <String>[],
            'records': 'x',
          },
        ],
        'refused': <String>[],
        'steps': <Object?>[],
      },
      {
        'senders': <Object?>[],
        'refused': <String>[],
        'steps': ['x'],
      },
      {
        'senders': <Object?>[],
        'refused': <String>[],
        'steps': [
          {'chain': <String>[], 'key': 3},
        ],
      },
    ]) {
      await fails('device_sets', bad);
    }
  });

  test('padded_length, seal, open', () async {
    expect(await output('padded_length', {'length': 1024}), {
      'accept': {'padded_length': 1088},
    });
    await fails('padded_length', {'length': '1'});
    final pair = await c.X25519().newKeyPair();
    final private = toHex(await pair.extractPrivateKeyBytes());
    final public = toHex((await pair.extractPublicKey()).bytes);
    final sealed =
        ((await output('seal', {
                  'message': deleteHex,
                  'encryption_key': public,
                }))!
                as Map)['accept']['sealed']
            as String;
    expect(
      await output('open', {
        'sealed': sealed,
        'private_keys': [private],
      }),
      {
        'accept': {'message': deleteHex},
      },
    );
    expect(
      await output('open', {
        'sealed': '02$sealed',
        'private_keys': [private],
      }),
      rejected('NOT_OPENED'),
    );
    await fails('open', {'sealed': sealed, 'private_keys': 'x'});
  });

  test('a receiver starts with no senders', () {
    expect(DeviceSetReceiver().senders, isEmpty);
  });
}
