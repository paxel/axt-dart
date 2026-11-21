/// Fuzz target of the conformance adapter's answers (paxel/gates `fuzz.yml`,
/// stack `dart`): `dart run fuzz/adapter_answer.dart <seconds>`.
///
/// For the given time it feeds the adapter random and mutated JSON lines and
/// checks that every answer is one JSON object with the request's id and
/// exactly one of `output`, `unsupported` and `failure`. The first input that
/// throws or breaks that rule is written to
/// `fuzz/artifacts/adapter_answer/crash-<sha256>` and the run exits with 1.
library;

import 'dart:convert';
import 'dart:io';
import 'dart:math';

import 'package:axt_protocol/src/conformance_adapter.dart';
import 'package:crypto/crypto.dart';

const List<String> _seeds = [
  '{"id": "hello", "op": "hello", "input": {"format": 1}}',
  '{"id": "hello", "op": "hello", "input": {"format": 2}}',
  '{"id": "v1", "op": "fingerprint", "input": {}}',
  '{"id": null, "op": null}',
  '[]',
  '"text"',
];

Object? _value(Random random, int depth) {
  switch (random.nextInt(depth > 3 ? 5 : 7)) {
    case 0:
      return null;
    case 1:
      return random.nextBool();
    case 2:
      return random.nextInt(1 << 32) - (1 << 31);
    case 3:
      return random.nextDouble() * 1e6;
    case 4:
      return String.fromCharCodes(
        List.generate(random.nextInt(8), (_) => random.nextInt(0x2FF)),
      );
    case 5:
      return List.generate(random.nextInt(4), (_) => _value(random, depth + 1));
    default:
      return {
        for (final key in ['id', 'op', 'input', 'format', 'x'])
          if (random.nextBool()) key: _value(random, depth + 1),
      };
  }
}

String _mutate(Random random, String line) {
  final bytes = utf8.encode(line).toList();
  for (var i = random.nextInt(4); i >= 0 && bytes.isNotEmpty; i--) {
    bytes[random.nextInt(bytes.length)] = random.nextInt(256);
  }
  return utf8.decode(bytes, allowMalformed: true);
}

String _input(Random random) {
  switch (random.nextInt(3)) {
    case 0:
      return _seeds[random.nextInt(_seeds.length)];
    case 1:
      return _mutate(random, _seeds[random.nextInt(_seeds.length)]);
    default:
      return jsonEncode(_value(random, 0));
  }
}

/// The problem with the answer to [line], or null when it keeps the protocol.
Future<String?> _check(String line) async {
  Object? request;
  try {
    request = jsonDecode(line);
  } on FormatException {
    return null;
  }
  final reply = await answer(request);
  jsonEncode(reply);
  final id = request is Map<String, Object?> ? request['id'] : null;
  if (reply['id'] != id) return 'the answer has id ${reply['id']}, not $id';
  final kinds = ['output', 'unsupported', 'failure'].where(reply.containsKey);
  if (kinds.length != 1) return 'the answer holds ${kinds.toList()}';
  return null;
}

void _crash(String line, Object problem) {
  final digest = sha256.convert(utf8.encode(line));
  final file = File('fuzz/artifacts/adapter_answer/crash-$digest')
    ..createSync(recursive: true)
    ..writeAsStringSync(line);
  stderr.writeln('${file.path}: $problem');
  exitCode = 1;
}

Future<void> main(List<String> arguments) async {
  final seconds = arguments.isEmpty ? 10 : int.parse(arguments.first);
  final random = Random.secure();
  final end = DateTime.now().add(Duration(seconds: seconds));
  var runs = 0;
  while (DateTime.now().isBefore(end)) {
    final line = _input(random);
    runs++;
    try {
      final problem = await _check(line);
      if (problem != null) return _crash(line, problem);
    } on Object catch (e) {
      return _crash(line, e);
    }
  }
  stdout.writeln('$runs inputs in $seconds s, no failure');
}
