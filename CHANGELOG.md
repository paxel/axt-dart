# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.2.0]

### Added

- Passes the conformance category `bricks`: descriptions of types are validated, their schemas derived, and record values checked against them, including relations and extensions ([axtdrt-1015](https://github.com/paxel/axt-dart/issues/18)).

### Changed

- Conforms to AXT 0.2.0 in place of 0.1.0: offers and files of AXT 0.1.0 are no longer read ([axtdrt-1014](https://github.com/paxel/axt-dart/issues/17)).
- Types are given as descriptions: `OutgoingRecord` and the `readers` of `AxtNode.open` take a `TypeDescription`, made from the JSON form of a description, in place of a schema text; files and offers carry descriptions, and an offered type whose description is not valid is declined with `DESCRIPTION_INVALID` ([axtdrt-1016](https://github.com/paxel/axt-dart/issues/19)).

---

Historical changes have been moved to [OLDER_CHANGES.md](OLDER_CHANGES.md).
