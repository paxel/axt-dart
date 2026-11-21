# 1. The public API: the library keeps the AXT state, the app keeps its data and its secrets

Date: 2026-11-21

## Status

Accepted.

## Context

`axt_protocol` is the Dart library of AXT ([axt-1011](https://github.com/paxel/axt/issues/12)). Its first users are cat-a-log and Old Brain Fix, Flutter apps that each keep their data in their own SQLite store as an append-only log with a latest-wins projection. Neither speaks AXT yet. A receiver of AXT has to remember a lot across connections and files: its known senders and their keys and manifests, the device sets, every record's version and state, the values it last took from a sender, what it owes each receiver. The categories `encoding`, `types`, `time`, `keys` and `manifest` were built first, behind the conformance adapter only; `records`, `protocol`, `shares` and `file` need the shape of the API. Grilled on 2026-11-21 (Q7 to Q16, [axtdrt-1003](https://github.com/paxel/axt-dart/issues/4)).

## Decision

- **The library keeps the AXT state** (Q7), and saves it through a store that the app implements on its own storage.
- **The store is key-value of bytes** (Q8): `read(key)`, `write(key, bytes)`, `delete(key)`, `list(prefix)`, and a transaction around each received message and each file. The library owns the format of the values and their migrations.
- **Records are generic values** (Q9): a `Map<String, Object?>` in the form of the `avro` package, with the type's full name and schema. The app maps them onto its own entities.
- **The app keeps the private keys** (Q10): it hands the library the seed of its Ed25519 signing key and of its X25519 encryption key when it opens it. The library never writes them to the store.
- **Everything is asynchronous**, since the cryptography is: every call and every method of the store returns a `Future`.
- **Results are values; exceptions are for a whole that fails** (Q11): an operation returns a result with an outcome for each message and record. An `AxtException` with the specification's error code is thrown when the whole input is rejected (`FILE_REJECTED`), when the store fails, or for a wrong argument.
- **A file is read in two calls** (Q12): `inspect(file)` checks the whole file and returns a preview (its sender, the short fingerprint, the app name, the types and how many records fit, whether the sender is a first contact); `apply(preview, acceptSender: …)` applies it.
- **The app takes each record inside the same transaction** (Q13): `apply` calls the app's `onRecord(change)` for each record, new, updated, deleted or withdrawn, with the merged value, inside the store's transaction, which the app runs on the same SQLite connection as its own data.
- **The user's own changes are found by comparing** (Q14): the library keeps the value it last took from the sender and asks the app for a record's current value while it applies; `null` means the user deleted the record.
- **The app gives the ids, the library the versions** (Q15): the app keeps an AXT id (a UUID) beside its own entity, with `newRecordId()` (version 7) as a help; the library gives each change a state stamp as its version and keeps the highest stamp in the store.
- **The app keeps its shares** (Q16): its share rules stay in its own model and UI. For each send and each file it hands the library the ids of the records that are shared with that receiver now; the library derives what it owes, the withdrawals and their versions, and what it sent to whom.

## Considered options

- The library with a store of its own, such as its own SQLite file: a second database next to the app's log and a native dependency.
- A stateless library: every app would implement the version rule, device sets and manifest revisions itself.
- A typed repository as the store, or an append-only event log: 15 to 20 methods for every app, or a replay at every start.
- Typed classes for the example types, or converters the app registers: more to maintain for every schema version; both can come later on top of generic values.
- The library generating and keeping the private keys: the secrets would sit in the store, and an app could not keep the key it has.
- Reading a file in one call with a callback, or a second read after the user accepts the sender.
- Handing records back after the library's commit, or confirming each one: a crash in between would lose records for good, or the library would keep every record until confirmed.
- The app reporting every change of its user, or the library keeping its own map of entity keys to ids.

## Consequences

- The library keeps one copy of every received record that is there, to compare with.
- An app's store must run the library's transaction and its own writes on one connection, or the two can drift apart.
- The library's stamps keep versions rising after a restore from a backup, as long as the clock is not far behind.
- The names of the classes, the configuration of the policies of `spec/records.md`, section 6, and the codec of written files (`deflate`) are the implementer's.
