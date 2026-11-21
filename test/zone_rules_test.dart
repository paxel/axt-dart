import 'package:axt_protocol/src/zone_rules.dart';
import 'package:test/test.dart';

Map<String, Object?> berlin(
  int year,
  int month,
  int day,
  int hour,
  int minute, {
  required int offset,
  required int instant,
}) => {
  'year': year,
  'month': month,
  'day': day,
  'hour': hour,
  'minute': minute,
  'second': 0,
  'millisecond': 0,
  'zone': 'Europe/Berlin',
  'offset_seconds': offset,
  'instant_ms': instant,
};

Map<String, Object?> floating(int year, int month, int day, int hour) => {
  'year': year,
  'month': month,
  'day': day,
  'hour': hour,
  'minute': 0,
  'second': 0,
  'millisecond': 0,
  'zone': null,
  'offset_seconds': null,
  'instant_ms': null,
};

Map<String, Object?> duration({int months = 0, int days = 0, int millis = 0}) =>
    {'months': months, 'days': days, 'millis': millis};

void main() {
  final rules = TzdbZoneRules();

  test('the rules know Berlin and not Mars', () {
    expect(rules.offsetAt('Europe/Berlin', 1782896400000), 7200);
    expect(rules.offsetAt('Mars/Olympus_Mons', 0), isNull);
    expect(TzdbZoneRules().offsetAt('UTC', 0), 0);
  });

  test('civil dates and wall clocks round-trip', () {
    for (final ms in [0, -1, 1792888200000, -62135596800000, 253402300799999]) {
      final wall = wallClockOf(ms);
      expect(wallClockMs(wall), ms, reason: '$wall');
    }
    expect(civilFromDays(0), (1970, 1, 1));
    expect(civilFromDays(-1), (1969, 12, 31));
  });

  group('placeWallClock', () {
    test('in an overlap takes the preferred offset, else the larger', () {
      final wall = wallClockMs(floating(2026, 10, 25, 2)) + 30 * 60000;
      expect(
        placeWallClock(rules, 'Europe/Berlin', wall)['instant_ms'],
        1792888200000,
      );
      expect(
        placeWallClock(
          rules,
          'Europe/Berlin',
          wall,
          preferred: 3600,
        )['instant_ms'],
        1792891800000,
      );
    });

    test('in a gap moves the wall clock later by the gap', () {
      final wall = wallClockMs(floating(2027, 3, 28, 2)) + 30 * 60000;
      final placed = placeWallClock(rules, 'Europe/Berlin', wall);
      expect(placed['hour'], 3);
      expect(placed['minute'], 30);
      expect(placed['offset_seconds'], 7200);
    });
  });

  group('resolveDateTime', () {
    final summer = berlin(
      2026,
      7,
      1,
      10,
      0,
      offset: 3600,
      instant: 1782896400000,
    );

    test('keeps a floating time, an unknown zone and a value that agrees', () {
      expect(
        resolveDateTime(rules, floating(2026, 7, 1, 10), Anchor.local),
        floating(2026, 7, 1, 10),
      );
      final mars = {...summer, 'zone': 'Mars/Olympus_Mons'};
      expect(resolveDateTime(rules, mars, Anchor.local), mars);
      final agrees = {
        ...summer,
        'offset_seconds': 7200,
        'instant_ms': 1782892800000,
      };
      expect(resolveDateTime(rules, agrees, Anchor.instant), agrees);
    });

    test('local keeps the wall clock, instant keeps the instant', () {
      final local = resolveDateTime(rules, summer, Anchor.local);
      expect(local['hour'], 10);
      expect(local['instant_ms'], 1782892800000);
      final instant = resolveDateTime(rules, summer, Anchor.instant);
      expect(instant['hour'], 11);
      expect(instant['instant_ms'], 1782896400000);
    });
  });

  group('addDuration', () {
    test('months clamp the day; floating millis move the wall clock', () {
      expect(
        addDuration(
          rules,
          floating(2027, 1, 31, 9),
          duration(months: 1),
        )['day'],
        28,
      );
      expect(
        addDuration(
          rules,
          floating(2028, 1, 31, 9),
          duration(months: 1),
        )['day'],
        29,
      );
      expect(
        addDuration(
          rules,
          floating(2026, 12, 31, 23),
          duration(millis: 3600000),
        )['year'],
        2027,
      );
    });

    final october = berlin(
      2026,
      10,
      24,
      10,
      0,
      offset: 7200,
      instant: 1792828800000,
    );

    test('a day keeps the wall clock, 24 hours keep the instant', () {
      expect(addDuration(rules, october, duration(days: 1))['hour'], 10);
      expect(
        addDuration(rules, october, duration(millis: 86400000))['hour'],
        9,
      );
    });

    test('an unknown zone keeps its offset', () {
      final mars = {...october, 'zone': 'Mars/Olympus_Mons'};
      final later = addDuration(rules, mars, duration(days: 1, millis: 1000));
      expect(later['offset_seconds'], 7200);
      expect(later['second'], 1);
      expect(later['instant_ms'], 1792828800000 + 86400000 + 1000);
    });

    test('a sum outside the years 1 to 9999 fails', () {
      expect(
        () => addDuration(rules, floating(9999, 12, 1, 0), duration(months: 1)),
        throwsRangeError,
      );
      expect(
        () => addDuration(rules, floating(9999, 12, 31, 0), duration(days: 1)),
        throwsRangeError,
      );
      expect(
        () => addDuration(
          rules,
          floating(9999, 12, 31, 23),
          duration(millis: 3600000),
        ),
        throwsRangeError,
      );
    });
  });
}
