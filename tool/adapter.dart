/// The conformance adapter of `axt_protocol` (AXT `spec/conformance.md`, section 6).
///
/// The runner of the AXT conformance suite starts it and sends one JSON request
/// per line on standard input; the adapter writes one JSON answer per line on
/// standard output and nothing else. It is a test tool, not part of the library.
library;

import 'dart:convert';
import 'dart:io';

import 'package:axt_protocol/src/conformance_adapter.dart';

Future<void> main() async {
  final lines = stdin.transform(utf8.decoder).transform(const LineSplitter());
  await for (final line in lines) {
    Map<String, Object?> reply;
    try {
      reply = await answer(jsonDecode(line));
    } on FormatException catch (e) {
      reply = {'id': null, 'failure': 'not JSON: ${e.message}'};
    }
    stdout.writeln(jsonEncode(reply));
  }
}
