# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.1.0]

### Added

- Conforms to AXT 0.1.0: passes every vector of the categories `encoding`, `types`, `time`, `keys`, `manifest`, `records`, `protocol`, `shares` and `file` of its conformance suite ([axt-1011](https://github.com/paxel/axt/issues/12)).
- Reading AXT files in two steps, `inspect` for a preview of the sender and what fits, then `apply`, which hands each record to the app inside the app's own store transaction ([axtdrt-1003](https://github.com/paxel/axt-dart/issues/4), [axtdrt-1012](https://github.com/paxel/axt-dart/issues/13)).
- Writing AXT files of the records shared with one receiver, with the withdrawals it is owed, or as an export ([axtdrt-1012](https://github.com/paxel/axt-dart/issues/13), [axtdrt-1011](https://github.com/paxel/axt-dart/issues/12)).
- The user's own changes of received records are kept per field or for the whole record, as the app chooses ([axtdrt-1009](https://github.com/paxel/axt-dart/issues/10)).
- Versions as state stamps and record ids as UUIDs of version 7, so versions keep rising after a restore from a backup ([axtdrt-1012](https://github.com/paxel/axt-dart/issues/13)).

---

Historical changes have been moved to [OLDER_CHANGES.md](OLDER_CHANGES.md).
