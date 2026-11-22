# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.2.0]

### Added

- Passes the conformance category `bricks`: descriptions of types are validated, their schemas derived, and record values checked against them, including relations and extensions ([axtdrt-1015](https://github.com/paxel/axt-dart/issues/18)).
- Relations resolve across senders: `AxtNode.resolve` finds the record a relation points at, also of another sender or of the app itself, following the senders' device sets and joins, and `AxtNode.linkedFrom` lists the relations that point at a record ([axtdrt-1017](https://github.com/paxel/axt-dart/issues/20)).
- Extensions of other apps are carried unchanged when their type is unknown; where the user changed one, it is kept per extension, and merged field by field with the sender's when the app knows the extension's type from its readers ([axtdrt-1018](https://github.com/paxel/axt-dart/issues/21)).
- Relations merge per relation: the relations the user added, changed or removed stay when the sender updates the record ([axtdrt-1019](https://github.com/paxel/axt-dart/issues/22)).

### Changed

- Conforms to AXT 0.2.0 in place of 0.1.0: offers and files of AXT 0.1.0 are no longer read ([axtdrt-1014](https://github.com/paxel/axt-dart/issues/17)).
- Types are given as descriptions: `OutgoingRecord` and the `readers` of `AxtNode.open` take a `TypeDescription`, made from the JSON form of a description, in place of a schema text; files and offers carry descriptions, and an offered type whose description is not valid is declined with `DESCRIPTION_INVALID` ([axtdrt-1016](https://github.com/paxel/axt-dart/issues/19)).

---

Historical changes have been moved to [OLDER_CHANGES.md](OLDER_CHANGES.md).
