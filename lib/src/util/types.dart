import 'dart:convert';

abstract class JsonObject {
  JsonObject();
  JsonObject.fromJson(dynamic jsonData);
  Map<String, dynamic> toJson();
  @override
  String toString() {
    return jsonEncode(toJson());
  }
}
