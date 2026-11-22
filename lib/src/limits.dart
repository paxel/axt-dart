/// The limits of the specification (AXT `types/axt/limits.json`).
library;

import 'dart:convert';

import 'schemas.g.dart' show axtLimitsJson;

/// The limits by name.
final Map<String, int> axtLimits = {
  for (final MapEntry(:key, :value)
      in ((jsonDecode(axtLimitsJson) as Map<String, Object?>)['limits']!
              as Map<String, Object?>)
          .entries)
    key: ((value! as Map<String, Object?>)['value']! as num).toInt(),
};

/// The limit [name]; throws [ArgumentError] for a name that has none.
int limit(String name) =>
    axtLimits[name] ?? (throw ArgumentError.value(name, 'name'));
