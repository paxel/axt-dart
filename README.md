# axt_protocol

[![CI](https://github.com/paxel/axt-dart/actions/workflows/ci.yml/badge.svg?branch=summer)](https://github.com/paxel/axt-dart/actions/workflows/ci.yml)
[![Security](https://github.com/paxel/axt-dart/actions/workflows/security.yml/badge.svg?branch=summer)](https://github.com/paxel/axt-dart/actions/workflows/security.yml)
[![CodeQL](https://github.com/paxel/axt-dart/actions/workflows/codeql.yml/badge.svg?branch=summer)](https://github.com/paxel/axt-dart/actions/workflows/codeql.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/paxel/axt-dart/badge)](https://scorecard.dev/viewer/?uri=github.com/paxel/axt-dart)
[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=paxel_axt-dart&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=paxel_axt-dart)
[![Coverage](https://img.shields.io/endpoint?url=https%3A%2F%2Fraw.githubusercontent.com%2Fpaxel%2Faxt-dart%2Fsummer%2F.github%2Fbadges%2Fcoverage-dart.json)](coverage-floors.toml)
[![Fuzz](https://github.com/paxel/axt-dart/actions/workflows/fuzz.yml/badge.svg?branch=summer)](https://github.com/paxel/axt-dart/actions/workflows/fuzz.yml)
[![Release](https://img.shields.io/github/v/release/paxel/axt-dart)](https://github.com/paxel/axt-dart/releases)
[![License](https://img.shields.io/badge/license-Apache--2.0%20OR%20MIT-blue)](README.md#licence)

The Dart library of [AXT](https://github.com/paxel/axt) (Avro eXchange Transfer), the open
standard that lets small, independent apps exchange typed records with each other.

Status: in development; 0.1.0, for AXT 0.1.0, is on [pub.dev](https://pub.dev/packages/axt_protocol).

## Conformance

`axt_protocol` conforms to **AXT 0.2.0**. Its CI runs the conformance suite of the
[AXT 0.2.0 release](https://github.com/paxel/axt/releases/tag/v0.2.0), pinned by its SHA-256 and
checked against its attestation, against the library's own adapter.

The first release implements the categories every library must implement (`encoding`, `types`,
`time`, `records`, `manifest`, `keys`, `protocol`, `shares`, `bricks`) and the transport `file`.

## Typed classes

`dart run axt_protocol:generate <description.json...> -o <file>` writes a Dart class for the
type of each description, in the JSON form of `spec/fields.md`, section 10.3; read and write its
records with `TypedCodec` of `package:avro`. The eight example types of AXT 0.2.0 ship generated
in `package:axt_protocol/examples.dart`.

## Platforms

Native only: the Dart VM and AOT on Android, iOS and desktop. Flutter web is not supported.

## Licence

Licensed under either of the [Apache License, Version 2.0](LICENSE-APACHE) or the
[MIT License](LICENSE-MIT), at your option (see [LICENSE](LICENSE)).
