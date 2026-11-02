// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

#include "codec.hpp"

#include "iya/gnap.hpp"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include <cstdio>

namespace iya::gnap {
namespace {

int b64_value(char c) {
  if (c >= 'A' && c <= 'Z') return c - 'A';
  if (c >= 'a' && c <= 'z') return c - 'a' + 26;
  if (c >= '0' && c <= '9') return c - '0' + 52;
  if (c == '+' || c == '-') return 62;
  if (c == '/' || c == '_') return 63;
  return -1;
}

std::string encode_b64(const unsigned char* data, size_t n, bool url) {
  static const char kStd[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  static const char kUrl[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  const char* table = url ? kUrl : kStd;
  std::string out;
  out.reserve((n + 2) / 3 * 4);
  for (size_t i = 0; i < n; i += 3) {
    unsigned value = static_cast<unsigned>(data[i]) << 16;
    if (i + 1 < n) value |= static_cast<unsigned>(data[i + 1]) << 8;
    if (i + 2 < n) value |= static_cast<unsigned>(data[i + 2]);
    out.push_back(table[(value >> 18) & 63]);
    out.push_back(table[(value >> 12) & 63]);
    if (i + 1 < n) out.push_back(table[(value >> 6) & 63]);
    else if (!url) out.push_back('=');
    if (i + 2 < n) out.push_back(table[value & 63]);
    else if (!url) out.push_back('=');
  }
  return out;
}

bool decode_b64(const std::string& in, std::vector<unsigned char>& out, bool url, bool strict) {
  std::string text = in;
  if (url) {
    for (char c : text) {
      if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_')) {
        if (strict) return false;
      }
    }
    while (text.size() % 4) text.push_back('=');
  }
  if (text.size() % 4 == 1) return false;
  out.clear();
  unsigned value = 0;
  int bits = 0;
  for (size_t i = 0; i < text.size(); i++) {
    char c = text[i];
    if (c == '=') {
      if (bits == 0) return false;
      break;
    }
    int n = b64_value(c);
    if (n < 0) return false;
    if (url && strict && (c == '+' || c == '/')) return false;
    value = (value << 6) | static_cast<unsigned>(n);
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out.push_back(static_cast<unsigned char>((value >> bits) & 0xFF));
    }
  }
  return true;
}

}  // namespace

std::string b64url_encode(const unsigned char* data, size_t n) { return encode_b64(data, n, true); }
std::string b64url_encode(const std::string& data) {
  return encode_b64(reinterpret_cast<const unsigned char*>(data.data()), data.size(), true);
}
std::string b64std_encode(const unsigned char* data, size_t n) { return encode_b64(data, n, false); }

bool b64url_decode(const std::string& in, std::vector<unsigned char>& out, bool strict) {
  return decode_b64(in, out, true, strict);
}
bool b64std_decode(const std::string& in, std::vector<unsigned char>& out) { return decode_b64(in, out, false, false); }

std::vector<unsigned char> sha256_bytes(const unsigned char* data, size_t n) {
  std::vector<unsigned char> out(32);
  unsigned int len = 32;
  if (EVP_Digest(data, n, out.data(), &len, EVP_sha256(), nullptr) != 1) {
    throw Error("signature", "SHA-256 failed");
  }
  out.resize(len);
  return out;
}
std::vector<unsigned char> sha256_bytes(const std::string& data) {
  return sha256_bytes(reinterpret_cast<const unsigned char*>(data.data()), data.size());
}
std::string sha256_raw(const std::string& data) {
  auto sum = sha256_bytes(data);
  return std::string(reinterpret_cast<char*>(sum.data()), sum.size());
}

bool timing_equal(const std::string& a, const std::string& b) {
  if (a.size() != b.size()) return false;
  return CRYPTO_memcmp(a.data(), b.data(), a.size()) == 0;
}

std::string random_bytes(size_t n) {
  std::string out(n, '\0');
  if (RAND_bytes(reinterpret_cast<unsigned char*>(&out[0]), static_cast<int>(n)) != 1) {
    throw Error("protocol", "the random source failed");
  }
  return out;
}

std::string hex_colon(const unsigned char* data, size_t n) {
  std::string out;
  for (size_t i = 0; i < n; i++) {
    if (i) out.push_back(':');
    char buf[3];
    std::snprintf(buf, sizeof(buf), "%02X", data[i]);
    out += buf;
  }
  return out;
}

}  // namespace iya::gnap
