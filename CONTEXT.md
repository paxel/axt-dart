# axt_protocol

The Dart library of AXT: what an app holds, sends and receives when it speaks AXT. The terms of the specification itself are those of [paxel/axt](https://github.com/paxel/axt) (`spec/`); this file names the library's own.

## Language

**Store**:
The key-value storage of bytes that the app implements for the library, with a transaction around each received message and file.
_Avoid_: database, repository

**Seed**:
The 32 bytes of a private key, the Ed25519 signing key or the X25519 encryption key, that the app keeps and hands the library.
_Avoid_: secret, private key file

**Record value**:
A record as a generic Avro value, `Map<String, Object?>`, with its type's full name and schema.

**Preview**:
What `inspect` returns for a file before anything is applied: sender, short fingerprint, app name, the types that fit, first contact or not.

**Change**:
What the app gets in `onRecord` for one received record: new, updated, deleted or withdrawn, with the merged value.

**Taken value**:
The value of a record as the library last took it from its sender, kept to find the user's own changes.
_Avoid_: original, base

**Shared ids**:
The ids of the app's records that are shared with one receiver now, which the app hands the library for each send and file.

## Relationships

- The app gives a record its **id**; the library gives each change its version, a state stamp.
- A **Change** is delivered inside the **Store**'s transaction, so the app's data and the library's bookkeeping are written together.
- The library compares the app's current value with the **Taken value**; a field that differs is the user's own change.

## Flagged ambiguities

- "Share" is the app's rule; the library only sees **Shared ids**.
