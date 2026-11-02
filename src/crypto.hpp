// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

#pragma once

#include "json.hpp"

#include <map>
#include <memory>
#include <string>
#include <vector>

#include <openssl/evp.h>

namespace iya::gnap {

struct ClientKey {
  std::string proof;
  std::string private_pem;
  std::string alg;
  std::string kid;
  std::string thumb;
  std::map<std::string, std::string> jwk;
  std::string cert_pem;
  std::string chain_pem;
  EVP_PKEY* pkey = nullptr;

  ClientKey() = default;
  ~ClientKey();
  ClientKey(const ClientKey&) = delete;
  ClientKey& operator=(const ClientKey&) = delete;
};

std::shared_ptr<ClientKey> load_client_key(const std::string& private_pem, const std::string& certificate_pem,
                                           const std::string& proof);
Json public_key_object(const ClientKey& key);
std::vector<unsigned char> sign_message(const ClientKey& key, const std::string& data);
bool verify_message(EVP_PKEY* pub, const std::string& alg, const std::string& data, const unsigned char* sig,
                    size_t sig_len);
std::map<std::string, std::string> sign_http(const ClientKey& key, const std::string& method, const std::string& url,
                                             const std::map<std::string, std::string>& headers, const std::string* body);
std::string make_detached_jws(const ClientKey& key, const std::string& method, const std::string& url,
                              const std::string* body, const std::string& token);
struct JwsParts {
  Json header;
  Json payload;
};
JwsParts verify_jws_with_keys(const std::string& token, const std::vector<Json>& keys);
std::string fingerprint_cert_pem(const std::string& pem);

}  // namespace iya::gnap
