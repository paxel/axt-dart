import 'package:axt_protocol/src/time_values.dart';
import 'package:test/test.dart';

Map<String, Object?> dateTime({
  int year = 2026,
  int month = 11,
  int day = 24,
  int hour = 10,
  int minute = 0,
  int second = 0,
  int millisecond = 0,
  String? zone,
  int? offset,
  int? instant,
}) => {
  'year': year,
  'month': month,
  'day': day,
  'hour': hour,
  'minute': minute,
  'second': second,
  'millisecond': millisecond,
  'zone': zone,
  'offset_seconds': offset,
  'instant_ms': instant,
};

void main() {
  test('axt.Date takes the parts that belong together', () {
    bool valid(int? y, int? m, int? d) =>
        isValidTimeValue('axt.Date', {'year': y, 'month': m, 'day': d});
    expect(valid(2026, 11, 24), isTrue);
    expect(valid(2027, 3, null), isTrue);
    expect(valid(2019, null, null), isTrue);
    expect(valid(null, 5, 3), isTrue);
    expect(valid(null, 2, 29), isTrue);
    expect(valid(2024, 2, 29), isTrue);
    expect(valid(2027, 2, 29), isFalse);
    expect(valid(1900, 2, 29), isFalse);
    expect(valid(2000, 2, 29), isTrue);
    expect(valid(null, null, null), isFalse);
    expect(valid(2026, null, 3), isFalse);
    expect(valid(0, 1, 1), isFalse);
    expect(valid(2026, 13, null), isFalse);
    expect(valid(2026, 4, 31), isFalse);
  });

  test('axt.Time keeps its ranges', () {
    bool valid(int h, int m, int s, int ms) => isValidTimeValue('axt.Time', {
      'hour': h,
      'minute': m,
      'second': s,
      'millisecond': ms,
    });
    expect(valid(23, 59, 59, 999), isTrue);
    expect(valid(24, 0, 0, 0), isFalse);
    expect(valid(0, 0, 60, 0), isFalse);
    expect(valid(0, 0, 0, -1), isFalse);
  });

  test('axt.DateTime: floating, zoned, and the instant of the wall clock', () {
    expect(isValidTimeValue('axt.DateTime', dateTime()), isTrue);
    final zoned = dateTime(
      zone: 'Europe/Berlin',
      offset: 3600,
      instant: 1795510800000,
    );
    expect(isValidTimeValue('axt.DateTime', zoned), isTrue);
    expect(
      isValidTimeValue('axt.DateTime', {...zoned, 'instant_ms': 1795510800001}),
      isFalse,
    );
    expect(isValidTimeValue('axt.DateTime', {...zoned, 'zone': null}), isFalse);
    expect(
      isValidTimeValue('axt.DateTime', {...zoned, 'offset_seconds': 64801}),
      isFalse,
    );
    expect(
      isValidTimeValue('axt.DateTime', {...zoned, 'zone': 'Europe/../x'}),
      isFalse,
    );
    expect(isValidTimeValue('axt.DateTime', dateTime(month: 0)), isFalse);
    expect(isValidTimeValue('axt.DateTime', dateTime(day: 31)), isFalse);
    expect(isValidTimeValue('axt.DateTime', dateTime(hour: 24)), isFalse);
  });

  test('axt.Duration has parts of one sign', () {
    bool valid(int m, int d, int ms) => isValidTimeValue('axt.Duration', {
      'months': m,
      'days': d,
      'millis': ms,
    });
    expect(valid(1, 2, 3), isTrue);
    expect(valid(0, 0, -900000), isTrue);
    expect(valid(0, 0, 0), isTrue);
    expect(valid(1, -1, 0), isFalse);
  });

  test('a name that is no time type is an argument error', () {
    expect(() => isValidTimeValue('axt.Nope', {}), throwsArgumentError);
  });

  test('zone names keep the syntax of the database', () {
    expect(isZoneName('America/Argentina/Buenos_Aires'), isTrue);
    expect(isZoneName('Etc/GMT+1'), isTrue);
    expect(isZoneName('UTC'), isTrue);
    expect(isZoneName(''), isFalse);
    expect(isZoneName('Europe//Berlin'), isFalse);
    expect(isZoneName('.'), isFalse);
    expect(isZoneName('-x'), isFalse);
    expect(isZoneName('Europe/Berlin '), isFalse);
    expect(isZoneName('a' * 65), isFalse);
  });

  test('daysFromCivil counts from 1970-01-01', () {
    expect(daysFromCivil(1970, 1, 1), 0);
    expect(daysFromCivil(2000, 3, 1), 11017);
    expect(daysFromCivil(1, 1, 1), -719162);
    expect(daysFromCivil(1969, 12, 31), -1);
  });
}
