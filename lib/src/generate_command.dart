/// The command `dart run axt_protocol:generate`: typed Dart classes for the
/// types of descriptions, by the generator of `package:avro/generate.dart`.
library;

import 'dart:convert';
import 'dart:io';

import 'package:avro/generate.dart';

import 'errors.dart';
import 'type_description.dart';

const String _usage = '''
Usage: dart run axt_protocol:generate <description.json...> -o <file>

Writes one Dart library with an immutable class for the type of each
description, in the JSON form of spec/fields.md, section 10.3, and for the
named types inside it. Use the classes with TypedCodec of package:avro.

  -o, --output <file>  the Dart file to write
  -h, --help           print this help''';

/// The Dart source of the classes of [descriptions], their JSON texts by
/// the names they are known by, such as their paths: the schemas derived
/// from them, with the types of the namespace `axt` named `Axt…`.
///
/// Throws [AxtException] `DESCRIPTION_INVALID` for a description that is
/// not valid, and [GenerateException] where the generator stops.
GeneratedLibrary generateFromDescriptions(Map<String, String> descriptions) {
  final sources = <SchemaSource>[];
  for (final MapEntry(key: name, value: text) in descriptions.entries) {
    final Object? json;
    try {
      json = jsonDecode(text);
    } on FormatException catch (e) {
      throw AxtException(ErrorCode.descriptionInvalid, '$name: ${e.message}');
    }
    sources.add(SchemaSource(name, TypeDescription.fromJson(json).schemaText));
  }
  return generateDart(sources, prefixes: const {'axt': 'Axt'});
}

/// Runs the command with [args], writing messages to [out] and [err]; returns
/// the exit code: 0 on success, 2 for a usage error, 1 for any other failure.
/// Nothing is written on a failure. [format] formats the written file; by
/// default with `dart format`.
Future<int> runGenerate(
  List<String> args, {
  required StringSink out,
  required StringSink err,
  Future<bool> Function(String path)? format,
}) async {
  final inputs = <String>[];
  String? output;
  for (var i = 0; i < args.length; i++) {
    final a = args[i];
    if (a == '-h' || a == '--help') {
      out.writeln(_usage);
      return 0;
    }
    if (a == '-o' || a == '--output') {
      if (i + 1 == args.length) return _usageError(err, '$a needs a file');
      output = args[++i];
    } else {
      inputs.add(a);
    }
  }
  if (output == null) return _usageError(err, 'no output file');
  if (inputs.isEmpty) return _usageError(err, 'no description');
  final GeneratedLibrary library;
  try {
    library = generateFromDescriptions({
      for (final path in inputs) path: File(path).readAsStringSync(),
    });
  } on FileSystemException catch (e) {
    err.writeln('axt_protocol:generate: ${e.path}: ${e.message}');
    return 1;
  } on AxtException catch (e) {
    err.writeln('axt_protocol:generate: ${e.message}');
    return 1;
  } on GenerateException catch (e) {
    err.writeln('axt_protocol:generate: ${e.message}');
    return 1;
  }
  for (final warning in library.warnings) {
    err.writeln('axt_protocol:generate: warning: $warning');
  }
  File(output).writeAsStringSync(library.source);
  if (!await (format ?? _dartFormat)(output)) {
    err.writeln('axt_protocol:generate: $output: dart format failed');
    return 1;
  }
  out.writeln('wrote $output');
  return 0;
}

int _usageError(StringSink err, String message) {
  err
    ..writeln('axt_protocol:generate: $message')
    ..writeln()
    ..writeln(_usage);
  return 2;
}

/// Formats [path] with `dart format` of the running Dart.
Future<bool> _dartFormat(String path) async =>
    (await Process.run(Platform.resolvedExecutable, [
      'format',
      path,
    ])).exitCode ==
    0;
