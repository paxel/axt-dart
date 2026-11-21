/// The Avro object container file of AXT, read to the bytes of each datum as
/// stored, since a message's signature covers those bytes (AXT
/// `spec/envelope.md`, sections 4 and 8; `spec/keys.md`, section 2.2).
library;

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'errors.dart';

/// The largest file as stored.
const int maxFileBytes = 256 * 1024 * 1024;

/// The largest metadata of a file, keys and values together.
const int maxMetadataBytes = 8 * 1024 * 1024;

/// The largest data block after decompression.
const int maxBlockBytes = 64 * 1024 * 1024;

/// The largest sum of all data blocks after decompression.
const int maxTotalBytes = 1024 * 1024 * 1024;

AxtException _rejected(String why) => AxtException(ErrorCode.fileRejected, why);

/// A reader of Avro binary data that rejects instead of reading beyond the
/// end.
final class _Input {
  _Input(this.bytes, [this.offset = 0]);

  final Uint8List bytes;
  int offset;

  int get remaining => bytes.length - offset;

  int long() {
    var value = 0;
    var shift = 0;
    while (true) {
      if (offset >= bytes.length || shift > 63) {
        throw _rejected('a varint is cut');
      }
      final b = bytes[offset++];
      value |= (b & 0x7f) << shift;
      if (b & 0x80 == 0) break;
      shift += 7;
    }
    return (value >>> 1) ^ -(value & 1);
  }

  Uint8List take(int length) {
    if (length < 0 || length > remaining) {
      throw _rejected('a length is beyond the end');
    }
    final out = Uint8List.sublistView(bytes, offset, offset + length);
    offset += length;
    return out;
  }

  Uint8List lengthPrefixed() => take(long());
}

/// The header and the datums of a container file.
final class Container {
  Container._(this.metadata, this.datums);

  /// The metadata entries, values as stored.
  final Map<String, Uint8List> metadata;

  /// The bytes of each datum, in the order of the file.
  final List<Uint8List> datums;

  /// Reads [file], splitting each block into datums with [datumLength], which
  /// gives the length of the datum that starts at an offset of a block.
  ///
  /// Throws [AxtException] `FILE_REJECTED` for bytes that are no container
  /// file, a codec other than `null` and `deflate`, or a size above a limit.
  factory Container.read(
    Uint8List file,
    int Function(Uint8List block, int offset) datumLength,
  ) {
    if (file.length > maxFileBytes) {
      throw _rejected('the file is above 256 MiB');
    }
    final input = _Input(file);
    final magic = input.take(4);
    if (magic[0] != 0x4f ||
        magic[1] != 0x62 ||
        magic[2] != 0x6a ||
        magic[3] != 1) {
      throw _rejected('no Avro object container file');
    }
    final start = input.offset;
    final metadata = <String, Uint8List>{};
    while (true) {
      var count = input.long();
      if (count == 0) break;
      if (count < 0) {
        count = -count;
        input.long();
      }
      for (var i = 0; i < count; i++) {
        final String key;
        try {
          key = utf8.decode(input.lengthPrefixed());
        } on FormatException {
          throw _rejected('a metadata key is no UTF-8');
        }
        metadata[key] = input.lengthPrefixed();
      }
      if (input.offset - start > maxMetadataBytes) {
        throw _rejected('the metadata is above 8 MiB');
      }
    }
    final codec = metadata['avro.codec'];
    final compression = codec == null
        ? 'null'
        : ascii.decode(codec, allowInvalid: true);
    if (compression != 'null' && compression != 'deflate') {
      throw _rejected('the codec $compression is neither null nor deflate');
    }
    final sync = input.take(16);
    final datums = <Uint8List>[];
    var total = 0;
    while (input.remaining > 0) {
      final count = input.long();
      final stored = input.lengthPrefixed();
      final block = compression == 'null' ? stored : _inflate(stored);
      if (block.length > maxBlockBytes) {
        throw _rejected('a block is above 64 MiB');
      }
      total += block.length;
      if (total > maxTotalBytes) throw _rejected('the blocks are above 1 GiB');
      if (count < 0) throw _rejected('a negative block count');
      var offset = 0;
      for (var i = 0; i < count; i++) {
        final length = datumLength(block, offset);
        datums.add(Uint8List.sublistView(block, offset, offset + length));
        offset += length;
      }
      if (offset != block.length) {
        throw _rejected('bytes are left over in a block');
      }
      final marker = input.take(16);
      for (var i = 0; i < 16; i++) {
        if (marker[i] != sync[i]) {
          throw _rejected('a block ends without the sync marker');
        }
      }
    }
    return Container._(metadata, datums);
  }
}

Uint8List _inflate(Uint8List stored) {
  final out = BytesBuilder(copy: false);
  final sink = ZLibDecoder(raw: true).startChunkedConversion(_LimitSink(out));
  try {
    sink
      ..add(stored)
      ..close();
  } on FormatException {
    throw _rejected('a block does not inflate');
  }
  return out.takeBytes();
}

final class _LimitSink implements Sink<List<int>> {
  _LimitSink(this.out);

  final BytesBuilder out;

  @override
  void add(List<int> chunk) {
    out.add(chunk);
    if (out.length > maxBlockBytes) throw _rejected('a block is above 64 MiB');
  }

  @override
  void close() {}
}

/// The length of the `axt.Envelope` of format 1 that starts at [offset] of
/// [block], found from its bytes alone (keys.md, section 2.2): `format`,
/// `kind`, `sender`, `record`, `body` and `signature`.
int envelopeLength(Uint8List block, int offset) {
  final input = _Input(block, offset);
  input
    ..long()
    ..long()
    ..take(32);
  switch (input.long()) {
    case 0:
      break;
    case 1:
      input
        ..lengthPrefixed()
        ..long();
    default:
      throw _rejected('a record union index is neither 0 nor 1');
  }
  input
    ..lengthPrefixed()
    ..take(64);
  return input.offset - offset;
}

/// Writes a container file of [datums], each already encoded, with
/// [metadata] first and then `avro.codec`.
Uint8List writeContainer(
  Map<String, Uint8List> metadata,
  List<Uint8List> datums, {
  required Uint8List syncMarker,
  bool deflate = true,
}) {
  final out = BytesBuilder();
  void long(int value) {
    var v = (value << 1) ^ (value >> 63);
    while (v & ~0x7f != 0) {
      out.addByte((v & 0x7f) | 0x80);
      v >>>= 7;
    }
    out.addByte(v);
  }

  void bytes(List<int> value) {
    long(value.length);
    out.add(value);
  }

  out.add([0x4f, 0x62, 0x6a, 1]);
  final entries = {
    ...metadata,
    'avro.codec': ascii.encode(deflate ? 'deflate' : 'null'),
  };
  long(entries.length);
  for (final MapEntry(:key, :value) in entries.entries) {
    bytes(utf8.encode(key));
    bytes(value);
  }
  long(0);
  out.add(syncMarker);
  if (datums.isNotEmpty) {
    final raw = [for (final d in datums) ...d];
    long(datums.length);
    bytes(deflate ? ZLibEncoder(raw: true).convert(raw) : raw);
    out.add(syncMarker);
  }
  return out.takeBytes();
}
