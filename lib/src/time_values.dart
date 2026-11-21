/// The validity of the time types `axt.Date`, `axt.Time`, `axt.DateTime` and
/// `axt.Duration` (AXT `spec/time.md`, sections 4 to 7.1). None of the rules
/// needs a time zone database.
library;

import 'dart:convert';

/// The full names of the time types.
const Set<String> timeTypes = {
  'axt.Date',
  'axt.Time',
  'axt.DateTime',
  'axt.Duration',
};

/// Whether [value], a decoded record of the time type [fullName], is valid.
bool isValidTimeValue(String fullName, Map<String, Object?> value) =>
    switch (fullName) {
      'axt.Date' => _validDate(value),
      'axt.Time' => _validTime(value),
      'axt.DateTime' => _validDateTime(value),
      'axt.Duration' => _validDuration(value),
      _ => throw ArgumentError.value(fullName, 'fullName', 'no time type'),
    };

bool _in(Object? value, int low, int high) =>
    value is int && value >= low && value <= high;

bool _isLeap(int year) => year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);

/// The days of [month] in [year], or of a leap year when [year] is null.
int daysInMonth(int? year, int month) => switch (month) {
  2 => year == null || _isLeap(year) ? 29 : 28,
  4 || 6 || 9 || 11 => 30,
  _ => 31,
};

bool _validDate(Map<String, Object?> v) {
  final year = v['year'];
  final month = v['month'];
  final day = v['day'];
  if (year == null && month == null && day == null) return false;
  if (month == null && day != null) return false;
  if (year != null && !_in(year, 1, 9999)) return false;
  if (month != null && !_in(month, 1, 12)) return false;
  if (day != null) {
    return _in(day, 1, daysInMonth(year as int?, month! as int));
  }
  return true;
}

bool _validTime(Map<String, Object?> v) =>
    _in(v['hour'], 0, 23) &&
    _in(v['minute'], 0, 59) &&
    _in(v['second'], 0, 59) &&
    _in(v['millisecond'], 0, 999);

final RegExp _zonePart = RegExp(r'^[A-Za-z0-9._+-]+$');

/// Whether [zone] has the syntax of a zone name (section 6.1).
bool isZoneName(String zone) {
  if (utf8.encode(zone).length > 64) return false;
  for (final part in zone.split('/')) {
    if (!_zonePart.hasMatch(part) ||
        part == '.' ||
        part == '..' ||
        part.startsWith('-')) {
      return false;
    }
  }
  return true;
}

/// The days from 1970-01-01 to [year]-[month]-[day] of the proleptic
/// Gregorian calendar.
int daysFromCivil(int year, int month, int day) {
  final y = month <= 2 ? year - 1 : year;
  final era = (y >= 0 ? y : y - 399) ~/ 400;
  final yearOfEra = y - era * 400;
  final dayOfYear = (153 * (month + (month > 2 ? -3 : 9)) + 2) ~/ 5 + day - 1;
  final dayOfEra =
      yearOfEra * 365 + yearOfEra ~/ 4 - yearOfEra ~/ 100 + dayOfYear;
  return era * 146097 + dayOfEra - 719468;
}

bool _validDateTime(Map<String, Object?> v) {
  final year = v['year'];
  final month = v['month'];
  if (!_in(year, 1, 9999) || !_in(month, 1, 12)) return false;
  final day = v['day'];
  if (!_in(day, 1, daysInMonth(year! as int, month! as int))) return false;
  if (!_validTime(v)) return false;
  final zone = v['zone'];
  final offset = v['offset_seconds'];
  final instant = v['instant_ms'];
  if (zone == null && offset == null && instant == null) return true;
  if (zone is! String || offset is! int || instant is! int) return false;
  if (!isZoneName(zone) || !_in(offset, -64800, 64800)) return false;
  final wallClock =
      daysFromCivil(year as int, month as int, day! as int) * 86400000 +
      (v['hour']! as int) * 3600000 +
      (v['minute']! as int) * 60000 +
      (v['second']! as int) * 1000 +
      (v['millisecond']! as int);
  return instant == wallClock - 1000 * offset;
}

bool _validDuration(Map<String, Object?> v) {
  final parts = [v['months'], v['days'], v['millis']].cast<int>();
  return parts.every((p) => p >= 0) || parts.every((p) => p <= 0);
}
