// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

#include "subject.hpp"

#include "crypto.hpp"
#include "util.hpp"

#include <cstdint>

namespace iya::gnap {
namespace {

bool utf8_ok(const std::string& value) {
  const auto* bytes = reinterpret_cast<const unsigned char*>(value.data());
  size_t i = 0;
  while (i < value.size()) {
    unsigned char c = bytes[i];
    size_t need = 0;
    if ((c & 0x80) == 0) need = 1;
    else if ((c & 0xE0) == 0xC0) need = 2;
    else if ((c & 0xF0) == 0xE0) need = 3;
    else if ((c & 0xF8) == 0xF0) need = 4;
    else return false;
    if (i + need > value.size()) return false;
    for (size_t n = 1; n < need; n++) {
      if ((bytes[i + n] & 0xC0) != 0x80) return false;
    }
    if (need == 2 && c < 0xC2) return false;
    if (need == 3) {
      unsigned code = (c & 0x0F) << 12 | (bytes[i + 1] & 0x3F) << 6 | (bytes[i + 2] & 0x3F);
      if (code < 0x800 || (code >= 0xD800 && code <= 0xDFFF)) return false;
    }
    if (need == 4) {
      unsigned code = (c & 0x07) << 18 | (bytes[i + 1] & 0x3F) << 12 | (bytes[i + 2] & 0x3F) << 6 | (bytes[i + 3] & 0x3F);
      if (code < 0x10000 || code > 0x10FFFF) return false;
    }
    i += need;
  }
  return true;
}

int hex_value(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

bool decode_component(const std::string& value, std::string& out) {
  out.clear();
  for (size_t i = 0; i < value.size();) {
    if (value[i] != '%') {
      out.push_back(value[i]);
      i++;
      continue;
    }
    if (i + 3 > value.size()) return false;
    int hi = hex_value(value[i + 1]);
    int lo = hex_value(value[i + 2]);
    if (hi < 0 || lo < 0) return false;
    out.push_back(static_cast<char>((hi << 4) | lo));
    i += 3;
  }
  return utf8_ok(out);
}

bool account_user(const std::string& uri, std::string& user) {
  if (uri.rfind("acct:", 0) != 0) return false;
  auto at = uri.find('@', 5);
  if (at == std::string::npos || at == 5 || at + 1 >= uri.size()) return false;
  user = uri.substr(5, at - 5);
  return true;
}

const Json* find_sub(const Json* list, const std::string& format, const std::string& field) {
  if (list == nullptr || list->type != Type::Array) return nullptr;
  for (const auto& item : list->arr) {
    if (item.type != Type::Object || jstr_key(item, "format") != format) continue;
    const Json* value = item.get(field);
    if (value != nullptr && value->type == Type::String) return &item;
  }
  return nullptr;
}

std::vector<std::string> string_items(const Json* value) {
  std::vector<std::string> out;
  if (value == nullptr || value->type == Type::Null) return out;
  if (value->type == Type::Array) {
    for (const auto& item : value->arr) {
      if (item.type == Type::String) out.push_back(item.text);
      else if (item.type != Type::Null) out.push_back(item.dump());
    }
    return out;
  }
  if (value->type == Type::String) return {value->text};
  return {value->dump()};
}

Json simple_subject(const Json* identifier, const std::string& issuer) {
  Json out = Json::object();
  if (identifier == nullptr || identifier->type != Type::Object) return out;
  std::string format = jstr_key(*identifier, "format");
  if (format.empty()) format = jstr_key(*identifier, "subject_type");
  if (format == "iss_sub") {
    const Json* sub = identifier->get("sub");
    const Json* iss = identifier->get("iss");
    if (sub != nullptr && sub->type == Type::String && (iss == nullptr || iss->type == Type::Null || jstr(iss) == issuer)) {
      out.set("sub", Json::str(sub->text));
    }
  } else if (format == "email") {
    const Json* email = identifier->get("email");
    if (email != nullptr && email->type == Type::String) out.set("email", Json::str(email->text));
  } else if (format == "opaque") {
    const Json* id = identifier->get("id");
    if (id != nullptr && id->type == Type::String) out.set("opaque", Json::str(id->text));
  } else if (format == "aliases") {
    const Json* items = identifier->get("identifiers");
    if (items != nullptr && items->type == Type::Array) {
      for (const auto& one : items->arr) {
        Json part = simple_subject(&one, issuer);
        for (const auto& field : part.obj) out.set(field.first, field.second);
      }
    }
  }
  return out;
}

}  // namespace

Subject person_from_value(const Json& doc, const std::string& issuer, const std::vector<std::string>& audiences, double skew,
                          const std::function<std::vector<Json>()>& keys) {
  Subject person;
  if (doc.type != Type::Object) return person;
  const Json* iss_sub = find_sub(doc.get("sub_ids"), "iss_sub", "sub");
  const Json* opaque = find_sub(doc.get("sub_ids"), "opaque", "id");
  const Json* account = find_sub(doc.get("sub_ids"), "account", "uri");
  const Json* id_token = nullptr;
  if (const Json* assertions = doc.get("assertions"); assertions != nullptr && assertions->type == Type::Array) {
    for (const auto& item : assertions->arr) {
      if (item.type == Type::Object && jstr_key(item, "format") == "id_token" && item.get("value") != nullptr &&
          item.get("value")->type == Type::String) {
        id_token = &item;
        break;
      }
    }
  }
  std::string sub;
  std::string iss;
  if (iss_sub != nullptr) {
    sub = jstr_key(*iss_sub, "sub");
    if (const Json* iss_value = iss_sub->get("iss"); iss_value != nullptr && iss_value->type == Type::String) iss = iss_value->text;
  }
  Json claims = Json::object();
  bool verified = false;
  if (id_token != nullptr) {
    if (!keys) throw Error("validation", "subject key lookup must be synchronous");
    std::vector<Json> published = keys();
    JwsParts verified_jws = verify_jws_with_keys(jstr_key(*id_token, "value"), published);
    const Json& payload = verified_jws.payload;
    if (jstr_key(payload, "iss") != issuer) {
      std::string got = payload.get("iss") == nullptr ? "" : (payload.get("iss")->type == Type::String ? payload.get("iss")->text : payload.get("iss")->dump());
      throw Error("validation", "the id_token was issued by " + got + ", not " + issuer);
    }
    std::string token_sub = jstr_key(payload, "sub");
    if (token_sub.empty()) throw Error("validation", "the id_token has no sub");
    if (!is_number(payload.get("exp"))) throw Error("validation", "the id_token has no exp");
    double now = now_sec();
    if (payload.get("exp")->as_float() + skew < now) throw Error("validation", "the id_token has expired");
    if (is_number(payload.get("nbf")) && payload.get("nbf")->as_float() - skew > now) {
      throw Error("validation", "the id_token is not valid yet");
    }
    if (is_number(payload.get("iat")) && payload.get("iat")->as_float() - skew > now) {
      throw Error("validation", "the id_token is issued in the future");
    }
    auto aud = string_items(payload.get("aud"));
    std::vector<std::string> known;
    for (const auto& item : audiences)
      if (!item.empty()) known.push_back(item);
    if (!known.empty()) {
      bool match = false;
      for (const auto& one : aud)
        if (contains_string(known, one)) match = true;
      if (!match) {
        std::string shown = aud.empty() ? "(no audience)" : aud[0];
        for (size_t i = 1; i < aud.size(); i++) shown += ", " + aud[i];
        std::string wanted = known[0];
        for (size_t i = 1; i < known.size(); i++) wanted += " or " + known[i];
        throw Error("validation", "the id_token is for " + shown + ", not " + wanted);
      }
    }
    if (!sub.empty() && token_sub != sub) {
      throw Error("validation", "the id_token is about somebody other than the subject identifier");
    }
    sub = token_sub;
    iss = jstr_key(payload, "iss");
    claims = payload;
    verified = true;
  }
  if (sub.empty() && opaque != nullptr) sub = jstr_key(*opaque, "id");
  if (sub.empty() && account != nullptr) sub = jstr_key(*account, "uri");
  if (sub.empty()) return person;
  person.present = true;
  person.sub = sub;
  person.iss = iss;
  person.assertion_verified = verified;
  if (account != nullptr) {
    person.has_uid = true;
    std::string user;
    std::string uri = jstr_key(*account, "uri");
    if (!account_user(uri, user)) {
      person.has_uid = false;
    } else {
      std::string decoded;
      if (!decode_component(user, decoded)) person.uid = user;
      else person.uid = decoded;
    }
  }
  if (const Json* email = claims.get("email"); email != nullptr && email->type == Type::String) person.email = email->text;
  if (const Json* name = claims.get("name"); name != nullptr && name->type == Type::String) person.name = name->text;
  if (const Json* sid = claims.get("sid"); sid != nullptr && sid->type == Type::String) person.sid = sid->text;
  else if (const Json* sid = claims.get("session_id"); sid != nullptr && sid->type == Type::String) person.sid = sid->text;
  return person;
}

Json subject_of_value(const Json& doc, const std::string& issuer) {
  Json out = Json::object();
  if (doc.type != Type::Object) return out;
  std::string format = jstr_key(doc, "format");
  if (format.empty()) format = jstr_key(doc, "subject_type");
  if (format == "complex" || (format.empty() && (doc.get("user") != nullptr || doc.get("session") != nullptr))) {
    Json user = simple_subject(doc.get("user"), issuer);
    Json session = simple_subject(doc.get("session"), issuer);
    if (!jstr_key(user, "sub").empty()) out.set("person", Json::str(jstr_key(user, "sub")));
    if (!jstr_key(user, "email").empty()) out.set("email", Json::str(jstr_key(user, "email")));
    std::string session_id = jstr_key(session, "opaque");
    if (session_id.empty()) session_id = jstr_key(session, "sub");
    if (!session_id.empty()) out.set("idp_session", Json::str(session_id));
    return out;
  }
  Json one = simple_subject(&doc, issuer);
  if (!jstr_key(one, "sub").empty()) out.set("person", Json::str(jstr_key(one, "sub")));
  if (!jstr_key(one, "email").empty()) out.set("email", Json::str(jstr_key(one, "email")));
  return out;
}

Subject person_from_subject_json(const std::string& subject_json, const std::string& issuer) {
  Json doc = Json::parse(subject_json);
  return person_from_value(doc, issuer, {}, 0, [] { return std::vector<Json>{}; });
}

std::string subject_of_json(const std::string& sub_id_json, const std::string& issuer) {
  Json doc = Json::parse(sub_id_json);
  return subject_of_value(doc, issuer).dump();
}

}  // namespace iya::gnap
