// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

#include "json.hpp"

#include <algorithm>
#include <cstdio>
#include <cstdlib>

namespace iya::gnap {
namespace {

class Parser {
 public:
  explicit Parser(const std::string& in) : s(in) {}

  Json parse() {
    Json value = parse_value(0);
    skip();
    if (i != s.size()) throw Error("protocol", "JSON has trailing data");
    return value;
  }

 private:
  const std::string& s;
  size_t i = 0;

  void skip() {
    while (i < s.size() && (s[i] == ' ' || s[i] == '\t' || s[i] == '\n' || s[i] == '\r')) i++;
  }

  Json parse_value(int depth) {
    if (depth > 64) throw Error("protocol", "JSON is nested too deeply");
    skip();
    if (i >= s.size()) throw Error("protocol", "JSON ended early");
    char c = s[i];
    if (c == '{') return parse_object(depth);
    if (c == '[') return parse_array(depth);
    if (c == '"') return Json::str(parse_string());
    if (c == 't') return literal("true", Json::boolean(true));
    if (c == 'f') return literal("false", Json::boolean(false));
    if (c == 'n') return literal("null", Json::nul());
    if (c == '-' || (c >= '0' && c <= '9')) return parse_number();
    throw Error("protocol", "JSON has an unexpected character");
  }

  Json literal(const char* word, Json value) {
    for (size_t n = 0; word[n]; n++) {
      if (i >= s.size() || s[i] != word[n]) throw Error("protocol", "JSON has an unexpected character");
      i++;
    }
    return value;
  }

  Json parse_number() {
    size_t start = i;
    if (s[i] == '-') i++;
    if (i >= s.size() || s[i] < '0' || s[i] > '9') throw Error("protocol", "JSON has a bad number");
    if (s[i] == '0') {
      i++;
    } else {
      while (i < s.size() && s[i] >= '0' && s[i] <= '9') i++;
    }
    if (i < s.size() && s[i] == '.') {
      i++;
      if (i >= s.size() || s[i] < '0' || s[i] > '9') throw Error("protocol", "JSON has a bad number");
      while (i < s.size() && s[i] >= '0' && s[i] <= '9') i++;
    }
    if (i < s.size() && (s[i] == 'e' || s[i] == 'E')) {
      i++;
      if (i < s.size() && (s[i] == '+' || s[i] == '-')) i++;
      if (i >= s.size() || s[i] < '0' || s[i] > '9') throw Error("protocol", "JSON has a bad number");
      while (i < s.size() && s[i] >= '0' && s[i] <= '9') i++;
    }
    Json out;
    out.type = Type::Number;
    out.text = s.substr(start, i - start);
    return out;
  }

  std::string parse_string() {
    if (s[i] != '"') throw Error("protocol", "JSON has a bad string");
    i++;
    std::string out;
    while (i < s.size()) {
      unsigned char c = static_cast<unsigned char>(s[i]);
      if (c == '"') {
        i++;
        return out;
      }
      if (c == '\\') {
        i++;
        if (i >= s.size()) throw Error("protocol", "JSON has a bad string");
        char e = s[i++];
        switch (e) {
          case '"':
          case '\\':
          case '/':
            out.push_back(e);
            break;
          case 'b':
            out.push_back('\b');
            break;
          case 'f':
            out.push_back('\f');
            break;
          case 'n':
            out.push_back('\n');
            break;
          case 'r':
            out.push_back('\r');
            break;
          case 't':
            out.push_back('\t');
            break;
          case 'u':
            append_unicode(out);
            break;
          default:
            throw Error("protocol", "JSON has a bad string");
        }
        continue;
      }
      if (c < 0x20) throw Error("protocol", "JSON has a bad string");
      out.push_back(static_cast<char>(c));
      i++;
    }
    throw Error("protocol", "JSON has a bad string");
  }

  static int hex_value(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
  }

  unsigned code_unit() {
    if (i + 4 > s.size()) throw Error("protocol", "JSON has a bad string");
    unsigned v = 0;
    for (int n = 0; n < 4; n++) {
      int h = hex_value(s[i++]);
      if (h < 0) throw Error("protocol", "JSON has a bad string");
      v = (v << 4) | static_cast<unsigned>(h);
    }
    return v;
  }

  static void append_cp(std::string& out, unsigned cp) {
    if (cp <= 0x7F) {
      out.push_back(static_cast<char>(cp));
    } else if (cp <= 0x7FF) {
      out.push_back(static_cast<char>(0xC0 | (cp >> 6)));
      out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    } else if (cp <= 0xFFFF) {
      out.push_back(static_cast<char>(0xE0 | (cp >> 12)));
      out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
      out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    } else {
      out.push_back(static_cast<char>(0xF0 | (cp >> 18)));
      out.push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3F)));
      out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
      out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    }
  }

  void append_unicode(std::string& out) {
    unsigned cp = code_unit();
    if (cp >= 0xD800 && cp <= 0xDBFF) {
      if (i + 2 > s.size() || s[i] != '\\' || s[i + 1] != 'u') throw Error("protocol", "JSON has a bad string");
      i += 2;
      unsigned lo = code_unit();
      if (lo < 0xDC00 || lo > 0xDFFF) throw Error("protocol", "JSON has a bad string");
      cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
    } else if (cp >= 0xDC00 && cp <= 0xDFFF) {
      throw Error("protocol", "JSON has a bad string");
    }
    append_cp(out, cp);
  }

  Json parse_array(int depth) {
    i++;
    Json out = Json::array();
    skip();
    if (i < s.size() && s[i] == ']') {
      i++;
      return out;
    }
    while (i < s.size()) {
      out.push(parse_value(depth + 1));
      skip();
      if (i < s.size() && s[i] == ',') {
        i++;
        continue;
      }
      if (i < s.size() && s[i] == ']') {
        i++;
        return out;
      }
      throw Error("protocol", "JSON has a bad array");
    }
    throw Error("protocol", "JSON has a bad array");
  }

  Json parse_object(int depth) {
    i++;
    Json out = Json::object();
    skip();
    if (i < s.size() && s[i] == '}') {
      i++;
      return out;
    }
    while (i < s.size()) {
      skip();
      if (i >= s.size() || s[i] != '"') throw Error("protocol", "JSON has a bad object");
      std::string key = parse_string();
      skip();
      if (i >= s.size() || s[i] != ':') throw Error("protocol", "JSON has a bad object");
      i++;
      out.set(key, parse_value(depth + 1));
      skip();
      if (i < s.size() && s[i] == ',') {
        i++;
        continue;
      }
      if (i < s.size() && s[i] == '}') {
        i++;
        return out;
      }
      throw Error("protocol", "JSON has a bad object");
    }
    throw Error("protocol", "JSON has a bad object");
  }
};

void dump_into(const Json& value, std::string& out) {
  switch (value.type) {
    case Type::Null:
      out += "null";
      break;
    case Type::Bool:
      out += value.b ? "true" : "false";
      break;
    case Type::Number:
      out += value.text;
      break;
    case Type::String:
      out += json_escape(value.text);
      break;
    case Type::Array: {
      out += '[';
      for (size_t n = 0; n < value.arr.size(); n++) {
        if (n) out += ',';
        dump_into(value.arr[n], out);
      }
      out += ']';
      break;
    }
    case Type::Object: {
      std::vector<std::pair<std::string, const Json*>> keys;
      keys.reserve(value.obj.size());
      for (const auto& item : value.obj) keys.emplace_back(item.first, &item.second);
      std::sort(keys.begin(), keys.end(), [](const auto& a, const auto& b) { return a.first < b.first; });
      out += '{';
      for (size_t n = 0; n < keys.size(); n++) {
        if (n) out += ',';
        out += json_escape(keys[n].first);
        out += ':';
        dump_into(*keys[n].second, out);
      }
      out += '}';
      break;
    }
  }
}

}  // namespace

std::string json_escape(const std::string& value) {
  std::string out = "\"";
  for (unsigned char c : value) {
    switch (c) {
      case '"':
        out += "\\\"";
        break;
      case '\\':
        out += "\\\\";
        break;
      case '\b':
        out += "\\b";
        break;
      case '\f':
        out += "\\f";
        break;
      case '\n':
        out += "\\n";
        break;
      case '\r':
        out += "\\r";
        break;
      case '\t':
        out += "\\t";
        break;
      default:
        if (c < 0x20) {
          char buf[8];
          std::snprintf(buf, sizeof(buf), "\\u%04x", c);
          out += buf;
        } else {
          out.push_back(static_cast<char>(c));
        }
    }
  }
  out += '"';
  return out;
}

Json Json::parse(const std::string& in) { return Parser(in).parse(); }
Json Json::nul() { return Json(); }
Json Json::boolean(bool value) {
  Json out;
  out.type = Type::Bool;
  out.b = value;
  return out;
}
Json Json::integer(long long value) {
  Json out;
  out.type = Type::Number;
  out.text = std::to_string(value);
  return out;
}
Json Json::str(std::string value) {
  Json out;
  out.type = Type::String;
  out.text = std::move(value);
  return out;
}
Json Json::array() {
  Json out;
  out.type = Type::Array;
  return out;
}
Json Json::object() {
  Json out;
  out.type = Type::Object;
  return out;
}
Json& Json::push(Json value) {
  if (type != Type::Array) type = Type::Array;
  arr.push_back(std::move(value));
  return *this;
}
Json& Json::set(const std::string& key, Json value) {
  if (type != Type::Object) type = Type::Object;
  for (auto& item : obj) {
    if (item.first == key) {
      item.second = std::move(value);
      return *this;
    }
  }
  obj.emplace_back(key, std::move(value));
  return *this;
}
bool Json::has(const std::string& key) const {
  for (const auto& item : obj)
    if (item.first == key) return true;
  return false;
}
const Json* Json::get(const std::string& key) const {
  for (const auto& item : obj)
    if (item.first == key) return &item.second;
  return nullptr;
}
Json* Json::get(const std::string& key) {
  for (auto& item : obj)
    if (item.first == key) return &item.second;
  return nullptr;
}
std::string Json::dump() const {
  std::string out;
  dump_into(*this, out);
  return out;
}
double Json::as_float() const {
  if (type != Type::Number) return 0;
  char* end = nullptr;
  double value = std::strtod(text.c_str(), &end);
  if (end == text.c_str()) return 0;
  return value;
}

}  // namespace iya::gnap
