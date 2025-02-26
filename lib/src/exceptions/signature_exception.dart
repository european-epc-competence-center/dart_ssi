class RevokedException implements Exception {
  String message;
  String code;

  RevokedException(this.message, this.code);
}

class SignatureException implements Exception {
  String message;
  String code;

  SignatureException(this.message, this.code);

  @override
  String toString() {
    return '$code: $message';
  }
}
