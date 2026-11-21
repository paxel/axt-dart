# axt_protocol

The Dart library of [AXT](https://github.com/paxel/axt) (Avro eXchange Transfer), the open
standard that lets small, independent apps exchange typed records with each other.

Status: in development, nothing is published yet.

## Conformance

`axt_protocol` conforms to **AXT 0.1.0**. Its CI runs the conformance suite of the
[AXT 0.1.0 release](https://github.com/paxel/axt/releases/tag/v0.1.0), pinned by its SHA-256 and
checked against its attestation, against the library's own adapter.

The first release implements the categories every library must implement (`encoding`, `types`,
`time`, `records`, `manifest`, `keys`, `protocol`, `shares`) and the transport `file`.

## Platforms

Native only: the Dart VM and AOT on Android, iOS and desktop. Flutter web is not supported.

## Licence

Licensed under either of the [Apache License, Version 2.0](LICENSE-APACHE) or the
[MIT License](LICENSE-MIT), at your option.
