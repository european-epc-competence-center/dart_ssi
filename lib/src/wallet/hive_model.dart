import 'package:hive/hive.dart';

part 'hive_model.g.dart';

/// A credential when it is stored.
@HiveType(typeId: 0)
class Credential {
  /// Path used to derive keypair for proofing that one own it.
  @HiveField(0)
  String hdPath;

  /// Signed version according to W3C-Data Model with all attribute values hashed.
  @HiveField(1)
  String w3cCredential;

  /// Json-Structure containing hash, salt and value per attribute.
  @HiveField(2)
  String plaintextCredential;

  Credential(this.hdPath, this.w3cCredential, this.plaintextCredential);

    /// Convert a Credential object to a JSON-encodable Map
  Map<String, dynamic> toJson() {
    return {
      'hdPath': hdPath,
      'w3cCredential': w3cCredential,
      'plaintextCredential': plaintextCredential,
    };
  }

  /// Create a Credential object from a JSON map
  factory Credential.fromJson(Map<String, dynamic> json) {
    return Credential(
      json['hdPath'] as String,
      json['w3cCredential'] as String,
      json['plaintextCredential'] as String,
    );
  }

  @override
  String toString() =>
      '$w3cCredential uses Path $hdPath an has this data: $plaintextCredential';
}

@HiveType(typeId: 1)

/// A connection with an other party (issuer, verifier,...).
class Connection {
  /// HD-Path for own key.
  @HiveField(0)
  String hdPath;

  /// Did of the other party.
  @HiveField(1)
  String otherDid;

  /// A nma efor this connection.
  @HiveField(2)
  String name;

  Connection(this.hdPath, this.otherDid, this.name);

    /// Convert a Connection object to a JSON-encodable Map
  Map<String, dynamic> toJson() {
    return {
      'hdPath': hdPath,
      'otherDid': otherDid,
      'name': name,
    };
  }

  /// Create a Connection object from a JSON map
  factory Connection.fromJson(Map<String, dynamic> json) {
    return Connection(
      json['hdPath'] as String,
      json['otherDid'] as String,
      json['name'] as String,
    );
  }

  @override
  String toString() =>
      'Connection with $otherDid uses Path $hdPath und (user)name $name.';
}

@HiveType(typeId: 2)
class ExchangeHistoryEntry {
  @HiveField(0)
  DateTime timestamp;

  /// Description of the action done with the credential (Present, issue ...)
  @HiveField(1)
  String action;

  /// Did/name/url of party the credential was presented to
  @HiveField(2)
  String otherParty;

  /// Credential attributes that were shown
  @HiveField(3)
  List<String> shownAttributes;

  ExchangeHistoryEntry(
      this.timestamp, this.action, this.otherParty, this.shownAttributes);

  /// Convert an ExchangeHistoryEntry object to a JSON-encodable Map
  Map<String, dynamic> toJson() {
    return {
      'timestamp': timestamp.toIso8601String(), // Convert DateTime to string
      'action': action,
      'otherParty': otherParty,
      'shownAttributes': shownAttributes,
    };
  }

  /// Create an ExchangeHistoryEntry object from a JSON map
  factory ExchangeHistoryEntry.fromJson(Map<String, dynamic> json) {
    return ExchangeHistoryEntry(
      DateTime.parse(json['timestamp']), // Convert string back to DateTime
      json['action'] as String,
      json['otherParty'] as String,
      List<String>.from(json['shownAttributes']), // Ensure shownAttributes is a List<String>
    );
  }

  @override
  String toString() {
    return 'ExchangeHistoryEntry{timestamp: $timestamp, action: $action, otherParty: $otherParty, shownAttributes: $shownAttributes}';
  }
}

@HiveType(typeId: 3)
class DidcommConversation {
  /// Did/name/url of party the credential was presented to
  @HiveField(0)
  String lastMessage;

  @HiveField(1)
  String protocol;

  @HiveField(2)
  String myDid;

  DidcommConversation(this.lastMessage, this.protocol, this.myDid);

  /// Convert a Connection object to a JSON-encodable Map
  Map<String, dynamic> toJson() {
    return {
      'lastMessage': lastMessage,
      'protocol': protocol,
      'myDid': myDid,
    };
  }

  /// Create a Connection object from a JSON map
  factory DidcommConversation.fromJson(Map<String, dynamic> json) {
    return DidcommConversation(
      json['lastMessage'] as String,
      json['protocol'] as String,
      json['myDid'] as String,
    );
  }

  @override
  String toString() {
    return 'DidcommConversation{lastMessage: $lastMessage, protocol: $protocol, myDid: $myDid}';
  }
}
