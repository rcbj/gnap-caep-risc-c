// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

#include "iya/gnap.hpp"

#include <iostream>
#include <string>

namespace {

std::string escape_json(const std::string& value) {
  std::string out;
  for (unsigned char c : value) {
    if (c == '\\' || c == '"') {
      out.push_back('\\');
      out.push_back(static_cast<char>(c));
    } else if (c == '\n') {
      out += "\\n";
    } else if (c == '\r') {
      out += "\\r";
    } else {
      out.push_back(static_cast<char>(c));
    }
  }
  return out;
}

}  // namespace

int main() {
  auto key = iya::gnap::create_self_signed("app.example", {}, {});
  std::string json =
      "{\"grantEndpoint\":\"https://idp.example/gnap\",\"application\":\"app\",\"privateKey\":\"" +
      escape_json(key.private_key_pem) +
      "\",\"keyProof\":\"httpsig\",\"transmitterIssuer\":\"https://idp.example/issuer/\"}";
  auto cfg = iya::gnap::Config::resolve_json(json, ".");
  if (cfg.access_json != "[\"ssf.read\",\"ssf.manage\"]" || cfg.signals != -1 ||
      cfg.ssf_transmitter != "https://idp.example/issuer" || cfg.application != "app") {
    std::cerr << "config " << cfg.access_json << " signals " << cfg.signals << " tx " << cfg.ssf_transmitter << "\n";
    return 1;
  }
  auto client = iya::gnap::Client::from_json(json, ".");
  if (client.config().application != "app" || client.config().grant_endpoint != "https://idp.example/gnap") {
    std::cerr << "client config\n";
    return 1;
  }
  if (iya::gnap::interaction_hash("abc", "def", "xyz", "https://as.example/gnap") !=
      "2o3b9NeEcvp0At5d-71yCgybP45eTGm1_pTNMmjv_V0") {
    std::cerr << "hash\n";
    return 1;
  }
  return 0;
}
