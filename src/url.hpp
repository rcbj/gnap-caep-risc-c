// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

#pragma once

#include <map>
#include <string>
#include <utility>
#include <vector>

namespace iya::gnap {

struct Url {
  std::string scheme;
  std::string host;
  std::string port;
  std::string path;
  std::string query;
};

bool parse_absolute(const std::string& raw, Url& out);
std::string hostport_of(const Url& url);
std::string origin_of(const Url& url);
std::string href_of(const Url& url);
std::string origin_string(const std::string& raw);
std::string href_string(const std::string& raw);
bool is_loopback(const std::string& raw);
std::vector<std::string> well_known(const std::string& issuer, const std::string& suffix);
std::string path_unescape(const std::string& in, bool& ok);
std::map<std::string, std::vector<std::string>> parse_form(const std::string& text);
std::map<std::string, std::vector<std::string>> finish_names(const std::string& query);

}  // namespace iya::gnap
