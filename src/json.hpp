// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

#pragma once

#include "iya/gnap.hpp"

#include <string>
#include <utility>
#include <vector>

namespace iya::gnap {

enum class Type { Null, Bool, Number, String, Array, Object };

class Json {
 public:
  Type type = Type::Null;
  bool b = false;
  std::string text;
  std::vector<Json> arr;
  std::vector<std::pair<std::string, Json>> obj;

  static Json parse(const std::string& in);
  static Json nul();
  static Json boolean(bool value);
  static Json integer(long long value);
  static Json str(std::string value);
  static Json array();
  static Json object();

  Json& push(Json value);
  Json& set(const std::string& key, Json value);
  bool has(const std::string& key) const;
  const Json* get(const std::string& key) const;
  Json* get(const std::string& key);
  std::string dump() const;
  double as_float() const;
  bool is_string() const { return type == Type::String; }
};

std::string json_escape(const std::string& value);

}  // namespace iya::gnap
