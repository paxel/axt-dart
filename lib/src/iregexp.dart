/// I-Regexp (RFC 9485): a parser of its grammar, and its translation to a
/// Dart [RegExp] (AXT `spec/metadata.md`, section 6.4).
library;

import 'dart:convert';

/// The general categories of Unicode that `\p{…}` may name.
const Set<String> _categories = {
  'L', 'Lu', 'Ll', 'Lt', 'Lm', 'Lo', //
  'M', 'Mn', 'Mc', 'Me', //
  'N', 'Nd', 'Nl', 'No', //
  'P', 'Pc', 'Pd', 'Ps', 'Pe', 'Pi', 'Pf', 'Po', //
  'Z', 'Zs', 'Zl', 'Zp', //
  'S', 'Sm', 'Sc', 'Sk', 'So', //
  'C', 'Cc', 'Cf', 'Co', 'Cn', //
};

final class _Invalid implements Exception {
  const _Invalid();
}

/// Translates an I-Regexp to the expression of a Dart [RegExp] with
/// `unicode: true`, matching the whole value.
final class _Parser {
  _Parser(this.pattern, this.maxQuantifier) : runes = pattern.runes.toList();

  final String pattern;
  final int maxQuantifier;
  final List<int> runes;
  int i = 0;
  final StringBuffer out = StringBuffer();

  bool get atEnd => i >= runes.length;
  int get peek => runes[i];

  static String lit(int rune) => '\\u{${rune.toRadixString(16)}}';

  void regexp() {
    branch();
    while (!atEnd && peek == 0x7c) {
      i++;
      out.write('|');
      branch();
    }
  }

  void branch() {
    while (!atEnd && peek != 0x7c && peek != 0x29) {
      piece();
    }
  }

  void piece() {
    atom();
    if (atEnd) return;
    switch (peek) {
      case 0x2a || 0x2b || 0x3f: // * + ?
        out.writeCharCode(peek);
        i++;
      case 0x7b: // {
        i++;
        final min = number();
        int? max = min;
        var open = false;
        if (!atEnd && peek == 0x2c) {
          i++;
          open = true;
          max = atEnd || peek == 0x7d ? null : number();
        }
        if (atEnd || peek != 0x7d) throw const _Invalid();
        i++;
        if (min > maxQuantifier ||
            (max != null && (max > maxQuantifier || max < min))) {
          throw const _Invalid();
        }
        out.write(open ? '{$min,${max ?? ''}}' : '{$min}');
    }
  }

  int number() {
    final start = i;
    while (!atEnd && peek >= 0x30 && peek <= 0x39) {
      i++;
    }
    if (i == start) throw const _Invalid();
    return int.parse(String.fromCharCodes(runes.sublist(start, i)));
  }

  void atom() {
    if (atEnd) throw const _Invalid();
    final c = peek;
    switch (c) {
      case 0x28: // (
        i++;
        out.write('(?:');
        regexp();
        if (atEnd || peek != 0x29) throw const _Invalid();
        i++;
        out.write(')');
      case 0x2e: // .
        i++;
        out.write(r'[^\n\r]');
      case 0x5b: // [
        charClassExpr();
      case 0x5c: // \
        out.write(escape(inClass: false));
      default:
        if (!_normal(c)) throw const _Invalid();
        i++;
        out.write(lit(c));
    }
  }

  static bool _normal(int c) =>
      !(c == 0x28 ||
          c == 0x29 ||
          c == 0x2a ||
          c == 0x2b ||
          c == 0x2e ||
          c == 0x3f ||
          c == 0x5b ||
          c == 0x5c ||
          c == 0x5d ||
          c == 0x7b ||
          c == 0x7c ||
          c == 0x7d ||
          (c >= 0xd800 && c <= 0xdfff));

  /// A single-character escape as its code point, or a category escape.
  String escape({required bool inClass}) {
    i++; // the backslash
    if (atEnd) throw const _Invalid();
    final c = peek;
    i++;
    switch (c) {
      case 0x6e:
        return lit(0x0a);
      case 0x72:
        return lit(0x0d);
      case 0x74:
        return lit(0x09);
      case 0x70 || 0x50: // p, P
        if (atEnd || peek != 0x7b) throw const _Invalid();
        i++;
        final start = i;
        while (!atEnd && peek != 0x7d) {
          i++;
        }
        if (atEnd) throw const _Invalid();
        final name = String.fromCharCodes(runes.sublist(start, i));
        i++;
        if (!_categories.contains(name)) throw const _Invalid();
        return c == 0x70 ? '\\p{$name}' : '\\P{$name}';
    }
    final single =
        (c >= 0x28 && c <= 0x2b) ||
        c == 0x2d ||
        c == 0x2e ||
        c == 0x3f ||
        (c >= 0x5b && c <= 0x5e) ||
        (c >= 0x7b && c <= 0x7d);
    if (!single) throw const _Invalid();
    return lit(c);
  }

  int? _ccChar() {
    if (atEnd) throw const _Invalid();
    final c = peek;
    if (c == 0x5c) {
      final save = i;
      final escaped = escape(inClass: true);
      if (escaped.startsWith(r'\p') || escaped.startsWith(r'\P')) {
        i = save;
        return null;
      }
      return int.parse(escaped.substring(3, escaped.length - 1), radix: 16);
    }
    if (c == 0x2d || c == 0x5b || c == 0x5d || (c >= 0xd800 && c <= 0xdfff)) {
      throw const _Invalid();
    }
    i++;
    return c;
  }

  void charClassExpr() {
    i++; // [
    final buffer = StringBuffer('[');
    if (!atEnd && peek == 0x5e) {
      i++;
      buffer.write('^');
    }
    var first = true;
    var items = 0;
    while (true) {
      if (atEnd) throw const _Invalid();
      final c = peek;
      if (c == 0x5d) {
        if (items == 0) throw const _Invalid();
        i++;
        break;
      }
      if (c == 0x2d) {
        // A '-' is allowed first, or last before ']'.
        final last = i + 1 < runes.length && runes[i + 1] == 0x5d;
        if (!first && !last) throw const _Invalid();
        i++;
        buffer.write(lit(0x2d));
        items++;
        first = false;
        continue;
      }
      if (c == 0x5c &&
          i + 1 < runes.length &&
          (runes[i + 1] == 0x70 || runes[i + 1] == 0x50)) {
        buffer.write(escape(inClass: true));
        items++;
        first = false;
        continue;
      }
      final from = _ccChar()!;
      if (!atEnd &&
          peek == 0x2d &&
          i + 1 < runes.length &&
          runes[i + 1] != 0x5d) {
        i++;
        if (!atEnd && peek == 0x5b) throw const _Invalid(); // subtraction
        final to = _ccChar();
        if (to == null || to < from) throw const _Invalid();
        buffer.write('${lit(from)}-${lit(to)}');
      } else {
        buffer.write(lit(from));
      }
      items++;
      first = false;
    }
    buffer.write(']');
    out.write(buffer);
  }
}

/// The [RegExp] of the I-Regexp [pattern], matching a value as a whole; null
/// when [pattern] is not an I-Regexp within [maxBytes] and [maxQuantifier].
RegExp? compileIRegexp(
  String pattern, {
  required int maxBytes,
  required int maxQuantifier,
}) {
  if (utf8.encode(pattern).length > maxBytes) return null;
  final parser = _Parser(pattern, maxQuantifier);
  try {
    parser.regexp();
    if (!parser.atEnd) return null;
  } on _Invalid {
    return null;
  }
  // Every literal is written as \u{…}, so the expression is always valid.
  return RegExp('^(?:${parser.out})\$', unicode: true);
}
