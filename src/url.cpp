// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

#include "url.hpp"

#include "iya/gnap.hpp"

#include <cctype>

namespace iya::gnap {
namespace {

std::string lower_copy(std::string value) {
  for (char& c : value) {
    if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
  }
  return value;
}

int hex_digit(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

std::string form_decode(const std::string& in) {
  std::string out;
  for (size_t i = 0; i < in.size(); i++) {
    if (in[i] == '+') {
      out.push_back(' ');
      continue;
    }
    if (in[i] == '%' && i + 2 < in.size()) {
      int hi = hex_digit(in[i + 1]);
      int lo = hex_digit(in[i + 2]);
      if (hi >= 0 && lo >= 0) {
        out.push_back(static_cast<char>((hi << 4) | lo));
        i += 2;
        continue;
      }
    }
    out.push_back(in[i]);
  }
  return out;
}

}  // namespace

bool parse_absolute(const std::string& raw, Url& out) {
  auto pos = raw.find("://");
  if (pos == std::string::npos || pos == 0) return false;
  out = Url();
  out.scheme = lower_copy(raw.substr(0, pos));
  if (out.scheme != "http" && out.scheme != "https") return false;
  size_t i = pos + 3;
  if (i >= raw.size()) return false;
  if (raw[i] == '[') {
    auto end = raw.find(']', i);
    if (end == std::string::npos) return false;
    out.host = raw.substr(i + 1, end - i - 1);
    i = end + 1;
  } else {
    size_t start = i;
    while (i < raw.size() && raw[i] != ':' && raw[i] != '/' && raw[i] != '?' && raw[i] != '#') i++;
    out.host = raw.substr(start, i - start);
  }
  if (out.host.empty()) return false;
  if (i < raw.size() && raw[i] == ':') {
    i++;
    size_t start = i;
    if (i >= raw.size() || !std::isdigit(static_cast<unsigned char>(raw[i]))) return false;
    while (i < raw.size() && std::isdigit(static_cast<unsigned char>(raw[i]))) i++;
    out.port = raw.substr(start, i - start);
  }
  if (i < raw.size() && raw[i] == '/') {
    size_t start = i;
    while (i < raw.size() && raw[i] != '?' && raw[i] != '#') i++;
    out.path = raw.substr(start, i - start);
  }
  if (i < raw.size() && raw[i] == '?') {
    i++;
    size_t start = i;
    while (i < raw.size() && raw[i] != '#') i++;
    out.query = raw.substr(start, i - start);
  }
  return true;
}

std::string hostport_of(const Url& url) {
  std::string host = url.host;
  if (host.find(':') != std::string::npos) host = "[" + host + "]";
  if (url.port.empty() || (url.scheme == "http" && url.port == "80") || (url.scheme == "https" && url.port == "443"))
    return host;
  return host + ":" + url.port;
}

std::string origin_of(const Url& url) { return url.scheme + "://" + hostport_of(url); }

std::string href_of(const Url& url) {
  std::string path = url.path.empty() ? "/" : url.path;
  std::string out = origin_of(url) + path;
  if (!url.query.empty()) out += "?" + url.query;
  return out;
}

std::string origin_string(const std::string& raw) {
  Url url;
  if (!parse_absolute(raw, url)) throw Error("validation", raw + " is not a URL");
  return origin_of(url);
}

std::string href_string(const std::string& raw) {
  Url url;
  if (!parse_absolute(raw, url)) throw Error("validation", raw + " is not a URL");
  return href_of(url);
}

bool is_loopback(const std::string& raw) {
  Url url;
  if (!parse_absolute(raw, url)) return false;
  std::string host = lower_copy(url.host);
  return host == "localhost" || host == "127.0.0.1" || host == "::1";
}

std::vector<std::string> well_known(const std::string& issuer, const std::string& suffix) {
  Url url;
  if (!parse_absolute(issuer, url)) throw Error("validation", issuer + " is not a URL");
  std::string origin = origin_of(url);
  std::string path = url.path;
  while (!path.empty() && path.back() == '/') path.pop_back();
  std::string inserted = origin + "/.well-known/" + suffix + path;
  std::string appended = origin + path + "/.well-known/" + suffix;
  if (inserted == appended) return {inserted};
  return {inserted, appended};
}

std::string path_unescape(const std::string& in, bool& ok) {
  std::string out;
  ok = true;
  for (size_t i = 0; i < in.size(); i++) {
    if (in[i] != '%') {
      out.push_back(in[i]);
      continue;
    }
    if (i + 2 >= in.size()) {
      ok = false;
      return in;
    }
    int hi = hex_digit(in[i + 1]);
    int lo = hex_digit(in[i + 2]);
    if (hi < 0 || lo < 0) {
      ok = false;
      return in;
    }
    out.push_back(static_cast<char>((hi << 4) | lo));
    i += 2;
  }
  return out;
}

std::map<std::string, std::vector<std::string>> parse_form(const std::string& text) {
  std::map<std::string, std::vector<std::string>> out;
  size_t i = 0;
  while (i < text.size()) {
    size_t amp = text.find('&', i);
    if (amp == std::string::npos) amp = text.size();
    std::string part = text.substr(i, amp - i);
    if (!part.empty()) {
      auto eq = part.find('=');
      std::string key = form_decode(eq == std::string::npos ? part : part.substr(0, eq));
      std::string value = form_decode(eq == std::string::npos ? "" : part.substr(eq + 1));
      out[key].push_back(value);
    }
    i = amp + 1;
  }
  return out;
}

std::map<std::string, std::vector<std::string>> finish_names(const std::string& query) {
  std::string text = query;
  if (text.find("://") != std::string::npos || (!text.empty() && text[0] == '/')) {
    Url url;
    if (!parse_absolute(text, url) && !(text[0] == '/' && text.find("://") == std::string::npos)) {
      auto q = text.find('?');
      if (q == std::string::npos) throw Error("validation", "the finish redirect could not be read");
      text = text.substr(q + 1);
    } else if (text.find("://") != std::string::npos) {
      Url absolute;
      if (!parse_absolute(text, absolute)) throw Error("validation", "the finish redirect could not be read");
      text = absolute.query;
    } else {
      auto q = text.find('?');
      text = q == std::string::npos ? "" : text.substr(q + 1);
    }
  } else if (!text.empty() && (text[0] == '?' || text[0] == '#')) {
    text = text.substr(1);
  }
  return parse_form(text);
}

}  // namespace iya::gnap
