import 'dart:io';

import 'package:axt_protocol/src/generate_command.dart';

/// `dart run axt_protocol:generate <description.json...> -o <file>`: writes
/// the Dart classes of the types of descriptions.
Future<void> main(List<String> args) async {
  exitCode = await runGenerate(args, out: stdout, err: stderr);
}
