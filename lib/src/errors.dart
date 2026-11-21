/// The errors of AXT (`spec/protocol.md`, section 8.2, and
/// `spec/conformance.md`, section 4.2).
library;

/// An error code of AXT.
enum ErrorCode {
  tooLarge('TOO_LARGE'),
  formatUnsupported('FORMAT_UNSUPPORTED'),
  invalidMessage('INVALID_MESSAGE');

  const ErrorCode(this.code);

  /// The code as the specification writes it.
  final String code;
}

/// A rejection with an AXT error code.
final class AxtException implements Exception {
  const AxtException(this.code, this.message);

  /// Why AXT rejects it.
  final ErrorCode code;

  /// What went wrong, in words.
  final String message;

  @override
  String toString() => 'AxtException(${code.code}): $message';
}
