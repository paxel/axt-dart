/// The manifest: its validity and limits, and which types fit it (AXT
/// `spec/manifest.md`, sections 3 to 5).
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:avro/avro.dart';

import 'envelope.dart';
import 'errors.dart';
import 'record_decoder.dart' show parseTypeSchema;
import 'sealing.dart' show isSmallOrderEncryptionKey;

/// The largest body of a `MANIFEST`, single-object header included.
const int maxManifestBytes = 1048576;

AxtException _invalid(String why) =>
    AxtException(ErrorCode.manifestInvalid, why);

int _bytes(String text) => utf8.encode(text).length;

/// Whether [text] is one line of plain text of 1 to [max] bytes.
bool isOneLine(Object? text, int max) {
  if (text is! String || text.isEmpty || _bytes(text) > max) return false;
  for (final rune in text.runes) {
    if (rune < 0x20 || (rune >= 0x7f && rune <= 0x9f)) return false;
    if (rune == 0x2028 || rune == 0x2029) return false;
  }
  return true;
}

final RegExp _fullName = RegExp(
  r'^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)*$',
);

/// Whether [name] is an Avro full name of up to 512 bytes.
bool isFullName(Object? name) =>
    name is String && _bytes(name) <= 512 && _fullName.hasMatch(name);

const String _alnum = '[A-Za-z0-9]';

/// The `langtag` form of RFC 5646, section 2.1.
final RegExp _langtag = RegExp(
  '^'
  '([A-Za-z]{2,3}(-[A-Za-z]{3}){0,3}|[A-Za-z]{4}|[A-Za-z]{5,8})'
  '(-[A-Za-z]{4})?'
  '(-([A-Za-z]{2}|[0-9]{3}))?'
  '(-($_alnum{5,8}|[0-9]$_alnum{3}))*'
  '(-[0-9A-WY-Za-wy-z](-$_alnum{2,8})+)*'
  '(-[Xx](-$_alnum{1,8})+)?'
  r'$',
);

/// Whether [tag] is a language tag of RFC 5646 in the `langtag` form, of up
/// to 35 characters.
bool isLanguageTag(String tag) => tag.length <= 35 && _langtag.hasMatch(tag);

bool _isHttpsUrl(Object? url, int max, {bool base = false}) {
  if (url is! String || _bytes(url) > max) return false;
  if (url.runes.any((r) => r <= 0x20 || (r >= 0x7f && r <= 0x9f))) {
    return false;
  }
  final uri = Uri.tryParse(url);
  if (uri == null || uri.scheme != 'https' || uri.host.isEmpty) return false;
  if (!base) return true;
  return uri.userInfo.isEmpty &&
      !uri.hasQuery &&
      !uri.hasFragment &&
      uri.path.endsWith('/');
}

void _checkPurpose(Map<String, Object?> entry, String where) {
  if (!isOneLine(entry['purpose'], 512)) {
    throw _invalid('$where.purpose is not one line of 1 to 512 bytes');
  }
  final translations = entry['purpose_translations']! as Map<String, Object?>;
  if (translations.length > 64) {
    throw _invalid('$where has more than 64 translations');
  }
  final seen = <String>{};
  for (final MapEntry(:key, :value) in translations.entries) {
    if (!isLanguageTag(key)) {
      throw _invalid("$where: '$key' is not a language tag of RFC 5646");
    }
    if (key.toLowerCase() == 'en') {
      throw _invalid("$where: the English sentence belongs in purpose");
    }
    if (!seen.add(key.toLowerCase())) {
      throw _invalid("$where: the tag '$key' appears twice");
    }
    if (!isOneLine(value, 512)) {
      throw _invalid('$where: the $key sentence is not one line');
    }
  }
}

void _checkTypes(Object? entries, String field) {
  final list = entries! as List<Object?>;
  if (list.length > 256) throw _invalid('$field has more than 256 entries');
  final names = <String>{};
  for (var i = 0; i < list.length; i++) {
    final entry = list[i]! as Map<String, Object?>;
    final where = '$field[$i]';
    final type = entry['type'];
    if (!isFullName(type)) {
      throw _invalid('$where.type is not an Avro full name');
    }
    if (!names.add(type! as String)) {
      throw _invalid('$where.type $type appears twice');
    }
    final min = entry['min_version']! as int;
    final max = entry['max_version'] as int?;
    if (min < 1) throw _invalid('$where.min_version is below 1');
    if (max != null && max < min) {
      throw _invalid('$where.max_version is below min_version');
    }
    if (field == 'takes') _checkPurpose(entry, where);
  }
}

/// Decodes the body of a `MANIFEST` carried in an envelope of
/// [envelopeFormat] and checks that it is valid (section 4).
///
/// Throws [AxtException] `INVALID_MESSAGE` for a body that is no
/// `axt.Manifest`, and `MANIFEST_INVALID` for one that is not valid.
Future<Map<String, Object?>> checkManifest(
  Uint8List body,
  int envelopeFormat,
) async {
  if (body.length > maxManifestBytes) {
    throw _invalid('body of ${body.length} bytes, above $maxManifestBytes');
  }
  final manifest = decodeBody(Kind.manifest, body)! as Map<String, Object?>;
  if ((manifest['revision']! as int) < 1) throw _invalid('revision is below 1');
  if (!isOneLine(manifest['app_name'], 256)) {
    throw _invalid('app_name is not one line of 1 to 256 bytes');
  }
  final appUrl = manifest['app_url'];
  if (appUrl != null && !_isHttpsUrl(appUrl, 2048)) {
    throw _invalid('app_url is not an absolute https URL');
  }
  final formats = (manifest['formats']! as List<Object?>).cast<int>();
  if (formats.isEmpty ||
      formats.length > 16 ||
      formats.toSet().length != formats.length ||
      formats.any((f) => f < 1)) {
    throw _invalid('formats is not 1 to 16 distinct formats of at least 1');
  }
  if (!formats.contains(envelopeFormat)) {
    throw _invalid('formats lacks the format of the envelope');
  }
  _checkTypes(manifest['takes'], 'takes');
  final anyType = manifest['any_type'] as Map<String, Object?>?;
  if (anyType != null) _checkPurpose(anyType, 'any_type');
  final sends = manifest['sends'];
  if (sends != null) _checkTypes(sends, 'sends');
  final key = manifest['encryption_key'] as Uint8List?;
  final relay = manifest['relay'] as Map<String, Object?>?;
  if ((key == null) != (relay == null)) {
    throw _invalid(
      'relay and encryption_key are not both present or both null',
    );
  }
  if (key != null && await isSmallOrderEncryptionKey(key)) {
    throw _invalid('encryption_key is an X25519 key of small order');
  }
  if (relay != null && !_isHttpsUrl(relay['url'], 256, base: true)) {
    throw _invalid('relay.url is not an absolute https base URL');
  }
  return manifest;
}

/// The version of a writer schema: its `axt.version`, or 1 without one that
/// is an integer of at least 1 (section 3.4).
int schemaVersion(Map<String, Object?> schemaJson) {
  final version = schemaJson['axt.version'];
  return version is int && version >= 1 ? version : 1;
}

/// The tag of [tags] that the Lookup of RFC 4647, section 3.4, chooses for
/// the language priority list [languages], or null.
String? lookup(List<String> languages, Iterable<String> tags) {
  final byLower = {for (final tag in tags) tag.toLowerCase(): tag};
  for (final range in languages) {
    if (range == '*') continue;
    var candidate = range.toLowerCase();
    while (candidate.isNotEmpty) {
      final found = byLower[candidate];
      if (found != null) return found;
      var cut = candidate.lastIndexOf('-');
      if (cut < 0) break;
      if (cut >= 2 && candidate[cut - 2] == '-') cut -= 2;
      candidate = candidate.substring(0, cut);
    }
  }
  return null;
}

/// Whether the type of [schemaText] fits [manifest], a valid manifest, and the
/// purpose sentence for a user with the priority list [languages] (sections
/// 3.6 and 5.2).
({bool fits, String? purpose}) fit(
  Map<String, Object?> manifest,
  String schemaText,
  List<String> languages,
) {
  final schema = parseTypeSchema(schemaText);
  final name = schema is NamedSchema ? schema.fullName : schema.type;
  final json = jsonDecode(schemaText);
  final version = json is Map<String, Object?> ? schemaVersion(json) : 1;
  Map<String, Object?>? entry;
  for (final take in manifest['takes']! as List<Object?>) {
    final candidate = take! as Map<String, Object?>;
    if (candidate['type'] == name) entry = candidate;
  }
  if (entry != null) {
    final max = entry['max_version'] as int?;
    if (version < (entry['min_version']! as int) ||
        (max != null && version > max)) {
      return (fits: false, purpose: null);
    }
  } else {
    entry = manifest['any_type'] as Map<String, Object?>?;
    if (entry == null) return (fits: false, purpose: null);
  }
  final translations = entry['purpose_translations']! as Map<String, Object?>;
  final tag = lookup(languages, [...translations.keys, 'en']);
  final purpose = tag == null || tag == 'en'
      ? entry['purpose']! as String
      : translations[tag]! as String;
  return (fits: true, purpose: purpose);
}
