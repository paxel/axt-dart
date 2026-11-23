/// The errors of AXT (`spec/protocol.md`, section 8.2, and
/// `spec/conformance.md`, section 4.2).
library;

/// An error code of AXT.
enum ErrorCode {
  tooLarge('TOO_LARGE'),
  formatUnsupported('FORMAT_UNSUPPORTED'),
  invalidMessage('INVALID_MESSAGE'),
  schemaUnknown('SCHEMA_UNKNOWN'),
  doesNotResolve('DOES_NOT_RESOLVE'),
  undecodable('UNDECODABLE'),
  valueInvalid('VALUE_INVALID'),
  signatureInvalid('SIGNATURE_INVALID'),
  keyInvalid('KEY_INVALID'),
  encryptionKeyInvalid('ENCRYPTION_KEY_INVALID'),
  notOpened('NOT_OPENED'),
  paddingInvalid('PADDING_INVALID'),
  deviceRejected('DEVICE_REJECTED'),
  joinInvalid('JOIN_INVALID'),
  manifestInvalid('MANIFEST_INVALID'),
  recordIdInvalid('RECORD_ID_INVALID'),
  versionInvalid('VERSION_INVALID'),
  typeChanged('TYPE_CHANGED'),
  descriptionInvalid('DESCRIPTION_INVALID'),
  fileRejected('FILE_REJECTED'),
  offerInvalid('OFFER_INVALID'),
  notAccepted('NOT_ACCEPTED'),
  proposalsNotTaken('PROPOSALS_NOT_TAKEN');

  const ErrorCode(this.code);

  /// The code as the specification writes it.
  final String code;
}

/// A rejection with an AXT error code.
final class AxtException implements Exception {
  const AxtException(this.code, this.message, {this.field});

  /// Why AXT rejects it.
  final ErrorCode code;

  /// What went wrong, in words.
  final String message;

  /// For `VALUE_INVALID`: the field path of the value (metadata.md, section
  /// 7.2), or null for a path above 1,024 bytes.
  final String? field;

  @override
  String toString() => 'AxtException(${code.code}): $message';
}
