import 'dart:convert';
import 'dart:typed_data';

import 'package:avro/avro.dart';
import 'package:axt_protocol/src/conformance_adapter.dart';
import 'package:axt_protocol/src/envelope.dart' show axtSchema;
import 'package:axt_protocol/src/errors.dart';
import 'package:axt_protocol/src/manifest.dart';
import 'package:cryptography/cryptography.dart' as c;
import 'package:test/test.dart';

import 'key_fixtures.dart' show toHex;

Map<String, Object?> take(
  String type, {
  int min = 1,
  int? max,
  String purpose = 'A Pet becomes an animal.',
  Map<String, String> translations = const {},
}) => {
  'type': type,
  'min_version': min,
  'max_version': max,
  'purpose': purpose,
  'purpose_translations': translations,
};

Map<String, Object?> manifestOf({
  int revision = 1,
  String appName = 'cat-a-log',
  String? appUrl,
  List<int> formats = const [1],
  List<Map<String, Object?>>? takes,
  Map<String, Object?>? anyType,
  List<Map<String, Object?>>? sends,
  Uint8List? encryptionKey,
  Map<String, Object?>? relay,
}) => {
  'revision': revision,
  'app_name': appName,
  'app_url': appUrl,
  'formats': formats,
  'takes': takes ?? [take('axt.example.v1.Pet')],
  'any_type': anyType,
  'sends': sends,
  'encryption_key': encryptionKey,
  'relay': relay,
};

Uint8List bodyOf(Map<String, Object?> manifest) =>
    AvroCodec(writer: axtSchema('axt.Manifest')).encodeSingleObject(manifest);

Matcher invalid = throwsA(
  isA<AxtException>().having((e) => e.code, 'code', ErrorCode.manifestInvalid),
);

void main() {
  late Uint8List key;
  setUpAll(() async {
    final pair = await c.X25519().newKeyPair();
    key = Uint8List.fromList((await pair.extractPublicKey()).bytes);
  });

  test('a valid manifest decodes', () async {
    final manifest = await checkManifest(
      bodyOf(
        manifestOf(
          appUrl: 'https://example.org/app',
          anyType: {
            'purpose': 'Any other type becomes a Note.',
            'purpose_translations': <String, String>{},
          },
          sends: [
            {
              'type': 'axt.example.v1.Pet',
              'min_version': 1,
              'max_version': 1,
              'proposals': false,
            },
          ],
          encryptionKey: key,
          relay: {
            'url': 'https://relay.example.org/axt/',
            'mailbox': Uint8List(32),
          },
          takes: [
            take(
              'axt.example.v1.Pet',
              translations: {'de': 'Ein Tier.', 'pt-BR': 'Um animal.'},
            ),
          ],
        ),
      ),
      1,
    );
    expect(manifest['app_name'], 'cat-a-log');
  });

  test('every rule of section 4 rejects', () async {
    final cases = <Map<String, Object?>>[
      manifestOf(revision: 0),
      manifestOf(appName: ''),
      manifestOf(appName: 'two\nlines'),
      manifestOf(appName: 'sep '),
      manifestOf(appName: 'x' * 257),
      manifestOf(appUrl: 'http://example.org'),
      manifestOf(appUrl: 'https://exa mple.org'),
      manifestOf(appUrl: 'mailto:x'),
      manifestOf(formats: []),
      manifestOf(formats: [1, 1]),
      manifestOf(formats: [0, 1]),
      manifestOf(formats: [2]),
      manifestOf(takes: [take('9bad')]),
      manifestOf(takes: [take('a.B'), take('a.B')]),
      manifestOf(takes: [take('a.B', min: 0)]),
      manifestOf(takes: [take('a.B', min: 2, max: 1)]),
      manifestOf(takes: [take('a.B', purpose: '')]),
      manifestOf(
        takes: [
          take('a.B', translations: {'de_DE': 'x'}),
        ],
      ),
      manifestOf(
        takes: [
          take('a.B', translations: {'EN': 'x'}),
        ],
      ),
      manifestOf(
        takes: [
          take('a.B', translations: {'de': 'x', 'DE': 'y'}),
        ],
      ),
      manifestOf(
        takes: [
          take('a.B', translations: {'de': ''}),
        ],
      ),
      manifestOf(
        takes: [
          take('a.B', translations: {'x-old': 'x'}),
        ],
      ),
      manifestOf(
        takes: [
          take(
            'a.B',
            translations: {for (var i = 0; i < 65; i++) 'de-${1000 + i}': 'x'},
          ),
        ],
      ),
      manifestOf(takes: [for (var i = 0; i < 257; i++) take('a.B$i')]),
      manifestOf(
        anyType: {'purpose': '', 'purpose_translations': <String, String>{}},
      ),
      manifestOf(
        sends: [
          {
            'type': 'a.B',
            'min_version': 1,
            'max_version': null,
            'proposals': false,
          },
          {
            'type': 'a.B',
            'min_version': 1,
            'max_version': null,
            'proposals': false,
          },
        ],
      ),
      manifestOf(encryptionKey: key),
      manifestOf(
        encryptionKey: Uint8List(32),
        relay: {'url': 'https://r.org/', 'mailbox': Uint8List(32)},
      ),
      manifestOf(
        encryptionKey: key,
        relay: {'url': 'https://r.org/x', 'mailbox': Uint8List(32)},
      ),
      manifestOf(
        encryptionKey: key,
        relay: {'url': 'https://u@r.org/', 'mailbox': Uint8List(32)},
      ),
      manifestOf(
        encryptionKey: key,
        relay: {'url': 'https://r.org/?q', 'mailbox': Uint8List(32)},
      ),
    ];
    for (final manifest in cases) {
      expect(
        () => checkManifest(bodyOf(manifest), 1),
        invalid,
        reason: '$manifest',
      );
    }
    expect(() => checkManifest(Uint8List(maxManifestBytes + 1), 1), invalid);
    expect(
      () => checkManifest(Uint8List(3), 1),
      throwsA(
        isA<AxtException>().having(
          (e) => e.code,
          'code',
          ErrorCode.invalidMessage,
        ),
      ),
    );
  });

  test('language tags', () {
    for (final tag in [
      'de',
      'pt-BR',
      'zh-Hant-TW',
      'sl-rozaj-biske',
      'de-CH-1901',
      'en-a-bbb-x-a',
      'es-419',
    ]) {
      expect(isLanguageTag(tag), isTrue, reason: tag);
    }
    for (final tag in ['de_DE', 'x-old', 'i-klingon', '', 'de-', 'a' * 36]) {
      expect(isLanguageTag(tag), isFalse, reason: tag);
    }
  });

  test('the Lookup of RFC 4647', () {
    final tags = ['de', 'pt-BR', 'en', 'zh-Hant'];
    expect(lookup(['de-AT'], tags), 'de');
    expect(lookup(['fr-CH', 'fr'], tags), isNull);
    expect(lookup(['*', 'PT-br'], tags), 'pt-BR');
    expect(lookup(['zh-Hant-x-a'], tags), 'zh-Hant');
  });

  group('fit', () {
    final manifest = manifestOf(
      takes: [
        take(
          'axt.example.v1.Pet',
          min: 2,
          max: 3,
          translations: {'de': 'Ein Tier.'},
        ),
      ],
      anyType: {
        'purpose': 'Any other type.',
        'purpose_translations': {'fr': 'Tout autre.'},
      },
    );
    String schema(String name, Object? version) => jsonEncode({
      'type': 'record',
      'name': name,
      'namespace': 'axt.example.v1',
      'axt.version': ?version,
      'fields': <Object?>[],
    });

    test('a type in takes fits in its range', () {
      expect(fit(manifest, schema('Pet', 2), ['de-AT']), (
        fits: true,
        purpose: 'Ein Tier.',
      ));
      expect(fit(manifest, schema('Pet', 3), ['en']), (
        fits: true,
        purpose: 'A Pet becomes an animal.',
      ));
      expect(fit(manifest, schema('Pet', 4), ['de']), (
        fits: false,
        purpose: null,
      ));
      expect(fit(manifest, schema('Pet', null), ['de']), (
        fits: false,
        purpose: null,
      ));
      expect(fit(manifest, schema('Pet', 'two'), ['de']), (
        fits: false,
        purpose: null,
      ));
    });

    test('any other type fits through any_type, or not at all', () {
      expect(fit(manifest, schema('Note', 1), ['fr']), (
        fits: true,
        purpose: 'Tout autre.',
      ));
      expect(fit(manifestOf(), schema('Note', 1), ['fr']), (
        fits: false,
        purpose: null,
      ));
      expect(fit(manifest, '"string"', []), (
        fits: true,
        purpose: 'Any other type.',
      ));
    });

    test('schemaVersion', () {
      expect(schemaVersion({'axt.version': 5}), 5);
      expect(schemaVersion({'axt.version': 0}), 1);
      expect(schemaVersion({}), 1);
    });
  });

  test('the adapter checks manifests and fits', () async {
    final body = toHex(bodyOf(manifestOf()));
    final ok = await answer({
      'id': 'm',
      'op': 'check_manifest',
      'input': {'body': body, 'envelope_format': 1},
    });
    expect((ok['output']! as Map)['accept'], isA<Map<String, Object?>>());
    final bad = await answer({
      'id': 'm',
      'op': 'check_manifest',
      'input': {'body': body, 'envelope_format': 2},
    });
    expect(bad['output'], {
      'reject': {'error': 'MANIFEST_INVALID'},
    });
    expect(
      await answer({
        'id': 'm',
        'op': 'check_manifest',
        'input': {'body': body, 'envelope_format': '1'},
      }),
      containsPair('failure', isA<String>()),
    );
    final fits = await answer({
      'id': 'f',
      'op': 'fit',
      'input': {
        'manifest': body,
        'schema': '{"type":"record","name":"Pet","namespace":"axt.example.v1","fields":[]}',
        'languages': ['de'],
      },
    });
    expect(fits['output'], {
      'accept': {'fits': true, 'purpose': 'A Pet becomes an animal.'},
    });
    expect(
      await answer({
        'id': 'f',
        'op': 'fit',
        'input': {
          'manifest': body,
          'schema': '"int"',
          'languages': [1],
        },
      }),
      containsPair('failure', isA<String>()),
    );
  });
}
