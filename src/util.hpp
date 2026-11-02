// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

#pragma once

#include "json.hpp"

#include <cctype>
#include <chrono>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

namespace iya::gnap {

inline std::string trim_copy(const std::string& value) {
  size_t begin = 0;
  while (begin < value.size() && std::isspace(static_cast<unsigned char>(value[begin]))) begin++;
  size_t end = value.size();
  while (end > begin && std::isspace(static_cast<unsigned char>(value[end - 1]))) end--;
  return value.substr(begin, end - begin);
}

inline std::string trim_right_slash(std::string value) {
  while (!value.empty() && value.back() == '/') value.pop_back();
  return value;
}

inline bool contains_string(const std::vector<std::string>& list, const std::string& want) {
  for (const auto& item : list)
    if (item == want) return true;
  return false;
}

inline const Json* jget(const Json& doc, const std::string& key) { return doc.get(key); }

inline std::string jstr(const Json* value) {
  if (value == nullptr || value->type != Type::String) return "";
  return value->text;
}

inline std::string jstr_key(const Json& doc, const std::string& key) { return jstr(doc.get(key)); }

inline bool is_number(const Json* value) { return value != nullptr && value->type == Type::Number; }

inline double now_ms() {
  return static_cast<double>(
      std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())
          .count());
}

inline double now_sec() {
  return static_cast<double>(
      std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count());
}

inline std::string read_text_file(const std::string& path) {
  std::ifstream in(path, std::ios::binary);
  if (!in) return "";
  std::ostringstream buffer;
  buffer << in.rdbuf();
  if (!in && !in.eof()) return "";
  return buffer.str();
}

inline bool read_text_file_ok(const std::string& path, std::string& out, std::string& error) {
  std::ifstream in(path, std::ios::binary);
  if (!in) {
    error = "open " + path + ": no such file or directory";
    return false;
  }
  std::ostringstream buffer;
  buffer << in.rdbuf();
  out = buffer.str();
  return true;
}

inline std::string join_path(const std::string& base, const std::string& path) {
  if (path.empty()) return base;
  if (path[0] == '/') return path;
  if (base.empty() || base == ".") return path;
  if (base.back() == '/') return base + path;
  return base + "/" + path;
}

inline std::string json_quote(const std::string& value) { return json_escape(value); }

}  // namespace iya::gnap
