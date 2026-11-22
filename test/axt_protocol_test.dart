import 'package:axt_protocol/axt_protocol.dart';
import 'package:test/test.dart';

void main() {
  test('names the AXT version it conforms to', () {
    expect(axtVersion, '0.2.0');
  });
}
