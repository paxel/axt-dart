/// The conformance adapter of `axt_protocol` (AXT `spec/conformance.md`, section 6).
///
/// The runner of the AXT conformance suite starts it and sends one JSON request
/// per line on standard input; the adapter writes one JSON answer per line on
/// standard output and nothing else. It is a test tool, not part of the library.
library;

import 'dart:convert';
import 'dart:io';

import 'package:axt_protocol/axt_protocol.dart';

/// The categories of `spec/conformance.md`, section 2.1, that the adapter
/// answers. A category is listed only once all of its vectors pass.
const List<String> implementedCategories = [];

/// The version of the vector file format the adapter reads.
const int vectorFormat = 1;

/// Answers one request of the runner.
Map<String, Object?> answer(Object? request) {
  if (request is! Map<String, Object?>) {
    return {'id': null, 'failure': 'the request is not a JSON object'};
  }
  final id = request['id'];
  final op = request['op'];
  if (op == 'hello') {
    final input = request['input'];
    final format = input is Map<String, Object?> ? input['format'] : null;
    if (format != vectorFormat) {
      return {
        'id': id,
        'failure': 'vector format $format is not $vectorFormat',
      };
    }
    return {
      'id': id,
      'output': {
        'name': 'axt_protocol (AXT $axtVersion)',
        'categories': implementedCategories,
      },
    };
  }
  return {'id': id, 'unsupported': true};
}

Future<void> main() async {
  final lines = stdin.transform(utf8.decoder).transform(const LineSplitter());
  await for (final line in lines) {
    Map<String, Object?> reply;
    try {
      reply = answer(jsonDecode(line));
    } on FormatException catch (e) {
      reply = {'id': null, 'failure': 'not JSON: ${e.message}'};
    }
    stdout.writeln(jsonEncode(reply));
  }
}
