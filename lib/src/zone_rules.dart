/// Zone rules, and reading and adding to an `axt.DateTime` with them (AXT
/// `spec/time.md`, sections 6.3, 6.4 and 7.2).
library;

import 'package:timezone/data/latest_all.dart' as tzdata;
import 'package:timezone/timezone.dart' as tz;

import 'time_values.dart';

/// The offsets of the zones of a time zone database.
abstract interface class ZoneRules {
  /// The offset in seconds of [zone] at [instantMs], or null when the rules do
  /// not know the zone.
  int? offsetAt(String zone, int instantMs);
}

/// The zone rules of the IANA time zone database that the package `timezone`
/// carries.
final class TzdbZoneRules implements ZoneRules {
  TzdbZoneRules() {
    if (!_loaded) {
      tzdata.initializeTimeZones();
      _loaded = true;
    }
  }

  static bool _loaded = false;

  @override
  int? offsetAt(String zone, int instantMs) {
    final tz.Location location;
    try {
      location = tz.getLocation(zone);
    } on tz.LocationNotFoundException {
      return null;
    }
    return location.timeZone(instantMs).offset.inSeconds;
  }
}

const int _dayMs = 86400000;

/// The milliseconds from 1970-01-01T00:00 to the wall clock of [v], counted
/// as if it were UTC.
int wallClockMs(Map<String, Object?> v) =>
    daysFromCivil(v['year']! as int, v['month']! as int, v['day']! as int) *
        _dayMs +
    (v['hour']! as int) * 3600000 +
    (v['minute']! as int) * 60000 +
    (v['second']! as int) * 1000 +
    (v['millisecond']! as int);

/// The wall clock fields of [ms] milliseconds from 1970-01-01T00:00.
Map<String, int> wallClockOf(int ms) {
  final days = ms >= 0 ? ms ~/ _dayMs : -((-ms - 1) ~/ _dayMs) - 1;
  final rest = ms - days * _dayMs;
  final (year, month, day) = civilFromDays(days);
  return {
    'year': year,
    'month': month,
    'day': day,
    'hour': rest ~/ 3600000,
    'minute': rest ~/ 60000 % 60,
    'second': rest ~/ 1000 % 60,
    'millisecond': rest % 1000,
  };
}

/// The date [days] days after 1970-01-01 in the proleptic Gregorian calendar.
(int, int, int) civilFromDays(int days) {
  final z = days + 719468;
  final era = (z >= 0 ? z : z - 146096) ~/ 146097;
  final dayOfEra = z - era * 146097;
  final yearOfEra =
      (dayOfEra - dayOfEra ~/ 1460 + dayOfEra ~/ 36524 - dayOfEra ~/ 146096) ~/
      365;
  final dayOfYear =
      dayOfEra - (365 * yearOfEra + yearOfEra ~/ 4 - yearOfEra ~/ 100);
  final mp = (5 * dayOfYear + 2) ~/ 153;
  final day = dayOfYear - (153 * mp + 2) ~/ 5 + 1;
  final month = mp < 10 ? mp + 3 : mp - 9;
  return (yearOfEra + era * 400 + (month <= 2 ? 1 : 0), month, day);
}

/// A zoned value with the wall clock of [wallMs], [offset] and the instant
/// they give.
Map<String, Object?> _zoned(String zone, int wallMs, int offset) => {
  ...wallClockOf(wallMs),
  'zone': zone,
  'offset_seconds': offset,
  'instant_ms': wallMs - 1000 * offset,
};

/// Places the wall clock [wallMs] in [zone], which [rules] know, with
/// [preferred] as the preferred offset (section 6.3): the offset given if the
/// wall clock occurs with it; otherwise the one it occurs with; in an overlap
/// the larger; in a gap the wall clock moved later by the gap.
Map<String, Object?> placeWallClock(
  ZoneRules rules,
  String zone,
  int wallMs, {
  int? preferred,
}) {
  int offsetAt(int instant) => rules.offsetAt(zone, instant)!;
  final before = offsetAt(wallMs - _dayMs);
  final after = offsetAt(wallMs + _dayMs);
  final occurs = <int>{
    for (final offset in {before, after})
      if (offsetAt(wallMs - 1000 * offset) == offset) offset,
  };
  if (occurs.isEmpty) {
    return _zoned(zone, wallMs + 1000 * (after - before), after);
  }
  final offset = preferred != null && occurs.contains(preferred)
      ? preferred
      : occurs.reduce((a, b) => a > b ? a : b);
  return _zoned(zone, wallMs, offset);
}

/// The anchor of a field: what a receiver keeps when its zone rules differ.
enum Anchor { local, instant }

/// [dateTime] as a receiver with [rules] takes it for a field with [anchor]
/// (section 6.4).
Map<String, Object?> resolveDateTime(
  ZoneRules rules,
  Map<String, Object?> dateTime,
  Anchor anchor,
) {
  final zone = dateTime['zone'];
  if (zone is! String) return dateTime;
  final instant = dateTime['instant_ms']! as int;
  final offset = rules.offsetAt(zone, instant);
  if (offset == null || offset == dateTime['offset_seconds']) return dateTime;
  return switch (anchor) {
    Anchor.local => placeWallClock(rules, zone, wallClockMs(dateTime)),
    Anchor.instant => _zoned(zone, instant + 1000 * offset, offset),
  };
}

/// [dateTime] plus [duration] (section 7.2). Throws [RangeError] when the
/// result, or the date after the months or the days, lies outside the years
/// 1 to 9999.
Map<String, Object?> addDuration(
  ZoneRules rules,
  Map<String, Object?> dateTime,
  Map<String, Object?> duration,
) {
  final months = duration['months']! as int;
  final days = duration['days']! as int;
  final millis = duration['millis']! as int;
  final monthIndex =
      (dateTime['year']! as int) * 12 +
      (dateTime['month']! as int) -
      1 +
      months;
  final year = monthIndex ~/ 12;
  final month = monthIndex % 12 + 1;
  _checkYear(year);
  final day = [
    dateTime['day']! as int,
    daysInMonth(year, month),
  ].reduce((a, b) => a < b ? a : b);
  final timeOfDay = wallClockMs(dateTime) % _dayMs;
  final wallMs = (daysFromCivil(year, month, day) + days) * _dayMs + timeOfDay;
  _checkYear(wallClockOf(wallMs)['year']!);
  final zone = dateTime['zone'];
  final Map<String, Object?> result;
  if (zone is! String) {
    result = {...dateTime, ...wallClockOf(wallMs + millis)};
  } else {
    final known = rules.offsetAt(zone, dateTime['instant_ms']! as int) != null;
    final offset = dateTime['offset_seconds']! as int;
    final placed = months == 0 && days == 0
        ? dateTime
        : known
        ? placeWallClock(rules, zone, wallMs, preferred: offset)
        : _zoned(zone, wallMs, offset);
    final instant = (placed['instant_ms']! as int) + millis;
    final newOffset = known ? rules.offsetAt(zone, instant)! : offset;
    result = _zoned(zone, instant + 1000 * newOffset, newOffset);
  }
  _checkYear(result['year']! as int);
  return result;
}

void _checkYear(int year) {
  if (year < 1 || year > 9999) {
    throw RangeError.range(year, 1, 9999, 'year');
  }
}
