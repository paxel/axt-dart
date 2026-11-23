/// I-Regexp (RFC 9485): a parser of its grammar, and a matcher that runs in
/// time linear in the value (AXT `spec/metadata.md`, sections 6.4 and 9).
///
/// Patterns come from other apps, so they are not run by Dart's [RegExp],
/// which backtracks and takes time exponential in the value for patterns
/// such as `(a*)*b`. The pattern becomes a Thompson NFA, simulated one code
/// point at a time. The NFA's size and the work of one match are bounded;
/// a match that reaches a bound takes the value as if it kept the pattern,
/// as section 9 asks.
library;

import 'dart:convert';
import 'dart:typed_data';

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

/// The most states of a pattern's NFA; a larger one, such as of nested
/// range quantifiers, is not run.
const int maxStates = 100000;

/// The most work of one match, in states visited.
const int maxSteps = 2000000;

final class _Invalid implements Exception {
  const _Invalid();
}

final class _TooLarge implements Exception {
  const _TooLarge();
}

/// Whether a code point is in a set of code points.
typedef _Test = bool Function(int rune);

sealed class _Node {}

final class _Set extends _Node {
  _Set(this.test);
  final _Test test;
}

final class _Seq extends _Node {
  _Seq(this.nodes);
  final List<_Node> nodes;
}

final class _Alt extends _Node {
  _Alt(this.branches);
  final List<_Node> branches;
}

final class _Repeat extends _Node {
  _Repeat(this.node, this.min, this.max);
  final _Node node;
  final int min;

  /// Null for no upper bound.
  final int? max;
}

final Map<String, RegExp> _categoryRegExps = {};

/// The test of the general category [name]; of its complement for [negated].
/// One code point against one category takes constant time.
_Test _category(String name, {required bool negated}) {
  final re = _categoryRegExps.putIfAbsent(
    name,
    () => RegExp('^\\p{$name}\$', unicode: true),
  );
  return negated
      ? (r) => !re.hasMatch(String.fromCharCode(r))
      : (r) => re.hasMatch(String.fromCharCode(r));
}

/// A parser of the grammar of RFC 9485, section 3, to a tree.
final class _Parser {
  _Parser(String pattern, this.maxQuantifier) : runes = pattern.runes.toList();

  final int maxQuantifier;
  final List<int> runes;
  int i = 0;

  bool get atEnd => i >= runes.length;
  int get peek => runes[i];

  _Node regexp() {
    final branches = [branch()];
    while (!atEnd && peek == 0x7c) {
      i++;
      branches.add(branch());
    }
    return branches.length == 1 ? branches.single : _Alt(branches);
  }

  _Node branch() {
    final pieces = <_Node>[];
    while (!atEnd && peek != 0x7c && peek != 0x29) {
      pieces.add(piece());
    }
    return _Seq(pieces);
  }

  _Node piece() {
    final node = atom();
    if (atEnd) return node;
    switch (peek) {
      case 0x2a: // *
        i++;
        return _Repeat(node, 0, null);
      case 0x2b: // +
        i++;
        return _Repeat(node, 1, null);
      case 0x3f: // ?
        i++;
        return _Repeat(node, 0, 1);
      case 0x7b: // {
        i++;
        final min = number();
        int? max = min;
        if (!atEnd && peek == 0x2c) {
          i++;
          max = atEnd || peek == 0x7d ? null : number();
        }
        if (atEnd || peek != 0x7d) throw const _Invalid();
        i++;
        if (min > maxQuantifier ||
            (max != null && (max > maxQuantifier || max < min))) {
          throw const _Invalid();
        }
        return _Repeat(node, min, max);
    }
    return node;
  }

  int number() {
    final start = i;
    while (!atEnd && peek >= 0x30 && peek <= 0x39) {
      i++;
    }
    if (i == start) throw const _Invalid();
    return int.parse(String.fromCharCodes(runes.sublist(start, i)));
  }

  _Node atom() {
    if (atEnd) throw const _Invalid();
    final c = peek;
    switch (c) {
      case 0x28: // (
        i++;
        final node = regexp();
        if (atEnd || peek != 0x29) throw const _Invalid();
        i++;
        return node;
      case 0x2e: // .
        i++;
        return _Set((r) => r != 0x0a && r != 0x0d);
      case 0x5b: // [
        return charClassExpr();
      case 0x5c: // \
        return _Set(escape().test);
    }
    if (!_normal(c)) throw const _Invalid();
    i++;
    return _Set((r) => r == c);
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

  /// A single-character escape as its code point, or a category escape as
  /// its test.
  ({int? rune, _Test test}) escape() {
    i++; // the backslash
    if (atEnd) throw const _Invalid();
    final c = peek;
    i++;
    switch (c) {
      case 0x6e:
        return (rune: 0x0a, test: (r) => r == 0x0a);
      case 0x72:
        return (rune: 0x0d, test: (r) => r == 0x0d);
      case 0x74:
        return (rune: 0x09, test: (r) => r == 0x09);
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
        return (rune: null, test: _category(name, negated: c == 0x50));
    }
    final single =
        (c >= 0x28 && c <= 0x2b) ||
        c == 0x2d ||
        c == 0x2e ||
        c == 0x3f ||
        (c >= 0x5b && c <= 0x5e) ||
        (c >= 0x7b && c <= 0x7d);
    if (!single) throw const _Invalid();
    return (rune: c, test: (r) => r == c);
  }

  /// A character of a class as its code point; null for a category escape,
  /// which is left unread.
  int? _ccChar() {
    if (atEnd) throw const _Invalid();
    final c = peek;
    if (c == 0x5c) {
      final save = i;
      final escaped = escape();
      if (escaped.rune == null) i = save;
      return escaped.rune;
    }
    if (c == 0x2d || c == 0x5b || c == 0x5d || (c >= 0xd800 && c <= 0xdfff)) {
      throw const _Invalid();
    }
    i++;
    return c;
  }

  _Node charClassExpr() {
    i++; // [
    var negated = false;
    if (!atEnd && peek == 0x5e) {
      i++;
      negated = true;
    }
    final tests = <_Test>[];
    while (true) {
      if (atEnd) throw const _Invalid();
      final c = peek;
      if (c == 0x5d) {
        if (tests.isEmpty) throw const _Invalid();
        i++;
        break;
      }
      if (c == 0x2d) {
        // A '-' is allowed first, or last before ']'.
        final last = i + 1 < runes.length && runes[i + 1] == 0x5d;
        if (tests.isNotEmpty && !last) throw const _Invalid();
        i++;
        tests.add((r) => r == 0x2d);
        continue;
      }
      if (c == 0x5c &&
          i + 1 < runes.length &&
          (runes[i + 1] == 0x70 || runes[i + 1] == 0x50)) {
        tests.add(escape().test);
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
        tests.add((r) => r >= from && r <= to);
      } else {
        tests.add((r) => r == from);
      }
    }
    bool any(int r) {
      for (final t in tests) {
        if (t(r)) return true;
      }
      return false;
    }

    return _Set(negated ? (r) => !any(r) : any);
  }
}

const int _char = 0, _split = 1, _match = 2;

/// A Thompson NFA, built from the end: each state is built with the state
/// it goes on to.
final class _Builder {
  final List<int> kinds = [];
  final List<int> outs = [];
  final List<int> alts = [];
  final List<_Test?> tests = [];

  int state(int kind, {int out = -1, int alt = -1, _Test? test}) {
    if (kinds.length == maxStates) throw const _TooLarge();
    kinds.add(kind);
    outs.add(out);
    alts.add(alt);
    tests.add(test);
    return kinds.length - 1;
  }

  /// The start of [node], followed by [next].
  int build(_Node node, int next) {
    switch (node) {
      case _Set(:final test):
        return state(_char, out: next, test: test);
      case _Seq(:final nodes):
        var start = next;
        for (final n in nodes.reversed) {
          start = build(n, start);
        }
        return start;
      case _Alt(:final branches):
        var start = build(branches.last, next);
        for (final b in branches.reversed.skip(1)) {
          start = state(_split, out: build(b, next), alt: start);
        }
        return start;
      case _Repeat(:final node, :final min, :final max):
        var start = next;
        if (max == null) {
          final loop = state(_split, alt: next);
          outs[loop] = build(node, loop);
          start = loop;
        } else {
          for (var k = min; k < max; k++) {
            start = state(_split, out: build(node, start), alt: next);
          }
        }
        for (var k = 0; k < min; k++) {
          start = build(node, start);
        }
        return start;
    }
  }
}

/// An I-Regexp, matching a value as a whole.
final class IRegexp {
  IRegexp._(_Node node) {
    final b = _Builder();
    try {
      _start = b.build(node, b.state(_match));
    } on _TooLarge {
      return;
    }
    _kinds = Uint8List.fromList(b.kinds);
    _outs = Int32List.fromList(b.outs);
    _alts = Int32List.fromList(b.alts);
    _tests = b.tests;
  }

  int _start = -1;
  Uint8List? _kinds;
  late final Int32List _outs, _alts;
  late final List<_Test?> _tests;

  /// Whether [value] as a whole is in the pattern's language. True as well
  /// where the pattern's NFA is above [maxStates] or the match takes more
  /// than [maxSteps].
  bool hasMatch(String value) {
    final kinds = _kinds;
    if (kinds == null) return true;
    final marks = Int32List(kinds.length)..fillRange(0, kinds.length, -1);
    final stack = <int>[];
    var current = <int>[], next = <int>[];
    var steps = 0;

    // Adds [from] and the states it reaches without a code point to [into].
    bool add(int from, List<int> into, int generation) {
      stack.add(from);
      while (stack.isNotEmpty) {
        final s = stack.removeLast();
        if (marks[s] == generation) continue;
        marks[s] = generation;
        if (++steps > maxSteps) return false;
        if (kinds[s] == _split) {
          stack
            ..add(_alts[s])
            ..add(_outs[s]);
        } else {
          into.add(s);
        }
      }
      return true;
    }

    if (!add(_start, current, 0)) return true;
    var generation = 0;
    for (final rune in value.runes) {
      generation++;
      next.clear();
      for (final s in current) {
        if (kinds[s] == _char &&
            _tests[s]!(rune) &&
            !add(_outs[s], next, generation)) {
          return true;
        }
      }
      if (next.isEmpty) return false;
      (current, next) = (next, current);
    }
    return current.any((s) => kinds[s] == _match);
  }
}

/// The I-Regexp [pattern], matching a value as a whole; null when [pattern]
/// is not an I-Regexp within [maxBytes] and [maxQuantifier].
IRegexp? compileIRegexp(
  String pattern, {
  required int maxBytes,
  required int maxQuantifier,
}) {
  if (utf8.encode(pattern).length > maxBytes) return null;
  final parser = _Parser(pattern, maxQuantifier);
  final _Node node;
  try {
    node = parser.regexp();
    if (!parser.atEnd) return null;
  } on _Invalid {
    return null;
  }
  return IRegexp._(node);
}
