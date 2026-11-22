import 'dart:convert';
import 'dart:io';

import 'package:axt_protocol/src/generate_command.dart';
import 'package:test/test.dart';

Map<String, Object?> description(String name, {String field = 'text'}) => {
  'name': 'root',
  'doc': 'A type.',
  'texts': <String, Object?>{},
  'kind': {
    'axt.ObjectField': {
      'name': name,
      'version': 1,
      'fields': [
        {
          'name': field,
          'doc': 'The text.',
          'texts': <String, Object?>{},
          'required': true,
          'kind': {'axt.StringField': <String, Object?>{}},
        },
      ],
    },
  },
};

void main() {
  late Directory dir;
  setUp(() => dir = Directory.systemTemp.createTempSync('axt_generate'));
  tearDown(() => dir.deleteSync(recursive: true));

  String file(String name, Object? content) {
    final path = '${dir.path}/$name';
    File(path)
        .writeAsStringSync(content is String ? content : jsonEncode(content));
    return path;
  }

  Future<(int, String, String)> run(
    List<String> args, {
    bool formats = true,
  }) async {
    final out = StringBuffer();
    final err = StringBuffer();
    final code = await runGenerate(
      args,
      out: out,
      err: err,
      format: (_) async => formats,
    );
    return (code, '$out', '$err');
  }

  test('writes and formats the classes of descriptions', () async {
    final input = file('memo.json', description('org.example.Memo'));
    final output = '${dir.path}/memo.dart';
    final out = StringBuffer();
    final code = await runGenerate(
      [input, '-o', output],
      out: out,
      err: StringBuffer(),
    );
    expect(code, 0);
    expect('$out', contains('wrote $output'));
    final source = File(output).readAsStringSync();
    expect(source, contains('final class Memo'));
    expect(source, contains('AvroType<Memo>'));
  });

  test('usage, missing files and invalid descriptions fail', () async {
    expect((await run(['-h'])).$1, 0);
    expect((await run(['x.json'])).$1, 2);
    expect((await run(['-o'])).$1, 2);
    expect((await run(['-o', '${dir.path}/out.dart'])).$1, 2);
    final output = '${dir.path}/out.dart';
    expect((await run(['${dir.path}/none.json', '-o', output])).$1, 1);
    expect((await run([file('bad.json', '{'), '-o', output])).$1, 1);
    expect(
      (await run([
        file('invalid.json', {...description('org.example.A'), 'doc': ''}),
        '--output',
        output,
      ])).$1,
      1,
    );
    final twice = await run([
      file('a.json', description('org.example.A')),
      file('b.json', description('org.example.A', field: 'other')),
      '-o',
      output,
    ]);
    expect(twice.$1, 1);
    expect(twice.$3, contains('axt_protocol:generate'));
    expect(File(output).existsSync(), isFalse);
    final unformatted = await run([
      file('c.json', description('org.example.C')),
      '-o',
      output,
    ], formats: false);
    expect(unformatted.$1, 1);
    expect(unformatted.$3, contains('dart format failed'));
  });
}
