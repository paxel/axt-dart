/// The answers of the conformance adapter (AXT `spec/conformance.md`,
/// section 6). Not exported: only `tool/adapter.dart` uses it.
library;

import '../axt_protocol.dart';

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
