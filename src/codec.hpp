// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

#pragma once

#include <cstddef>
#include <string>
#include <vector>

namespace iya::gnap {

std::string b64url_encode(const unsigned char* data, size_t n);
std::string b64url_encode(const std::string& data);
inline std::string b64url_encode(const std::vector<unsigned char>& data) {
  return b64url_encode(data.data(), data.size());
}
std::string b64std_encode(const unsigned char* data, size_t n);
bool b64url_decode(const std::string& in, std::vector<unsigned char>& out, bool strict);
bool b64std_decode(const std::string& in, std::vector<unsigned char>& out);
std::vector<unsigned char> sha256_bytes(const unsigned char* data, size_t n);
std::vector<unsigned char> sha256_bytes(const std::string& data);
inline std::vector<unsigned char> sha256_bytes(const std::vector<unsigned char>& data) {
  return sha256_bytes(data.data(), data.size());
}
std::string sha256_raw(const std::string& data);
bool timing_equal(const std::string& a, const std::string& b);
std::string random_bytes(size_t n);
std::string hex_colon(const unsigned char* data, size_t n);

}  // namespace iya::gnap
