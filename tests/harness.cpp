// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

#include "harness.h"

#include "codec.hpp"
#include "json.hpp"

#include <openssl/bn.h>
#include <openssl/rand.h>
#include <openssl/core_names.h>
#include <openssl/ecdsa.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/param_build.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <cctype>
#include <cstring>
#include <functional>
#include <ctime>
#include <map>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

using iya::gnap::Json;
using iya::gnap::Type;
using iya::gnap::b64std_decode;
using iya::gnap::b64url_decode;
using iya::gnap::b64url_encode;
using iya::gnap::sha256_bytes;

namespace {

struct Seen {
  std::string method;
  std::string url;
  std::string body;
  std::string authorization;
  std::string signature;
  std::string detached;
  std::string cert;
};

struct Behavior {
  bool foreign = false;
  bool bearer = false;
  bool too_fast = false;
  bool too_fast_sent = false;
  std::string aud = "instance-1";
  std::string sub = "user-1";
  std::string iss_sub;
};

std::string lower_copy(std::string value) {
  for (char& c : value)
    if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
  return value;
}

std::string trim_copy(const std::string& value) {
  size_t begin = 0;
  while (begin < value.size() && std::isspace(static_cast<unsigned char>(value[begin]))) begin++;
  size_t end = value.size();
  while (end > begin && std::isspace(static_cast<unsigned char>(value[end - 1]))) end--;
  return value.substr(begin, end - begin);
}

std::string header_get(const std::string& headers, const std::string& name) {
  std::string want = lower_copy(name);
  size_t at = 0;
  while (at < headers.size()) {
    auto end = headers.find("\r\n", at);
    if (end == std::string::npos) end = headers.size();
    std::string line = headers.substr(at, end - at);
    auto colon = line.find(':');
    if (colon != std::string::npos && lower_copy(line.substr(0, colon)) == want) return trim_copy(line.substr(colon + 1));
    if (end == headers.size()) break;
    at = end + 2;
  }
  return "";
}

std::string fingerprint_x509(X509* cert) {
  int len = i2d_X509(cert, nullptr);
  std::vector<unsigned char> der(static_cast<size_t>(len));
  unsigned char* p = der.data();
  i2d_X509(cert, &p);
  auto sum = sha256_bytes(der);
  std::string out;
  for (size_t i = 0; i < sum.size(); i++) {
    if (i) out.push_back(':');
    char buf[3];
    std::snprintf(buf, sizeof(buf), "%02X", sum[i]);
    out += buf;
  }
  return out;
}

std::string pem_of_pkey(EVP_PKEY* key) {
  BIO* bio = BIO_new(BIO_s_mem());
  PEM_write_bio_PKCS8PrivateKey(bio, key, nullptr, nullptr, 0, nullptr, nullptr);
  char* data = nullptr;
  long len = BIO_get_mem_data(bio, &data);
  std::string out(data, static_cast<size_t>(len));
  BIO_free(bio);
  return out;
}

std::string pem_of_cert(X509* cert) {
  BIO* bio = BIO_new(BIO_s_mem());
  PEM_write_bio_X509(bio, cert);
  char* data = nullptr;
  long len = BIO_get_mem_data(bio, &data);
  std::string out(data, static_cast<size_t>(len));
  BIO_free(bio);
  return out;
}

EVP_PKEY* make_p256() {
  EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
  EVP_PKEY_keygen_init(ctx);
  EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, NID_X9_62_prime256v1);
  EVP_PKEY* key = nullptr;
  EVP_PKEY_keygen(ctx, &key);
  EVP_PKEY_CTX_free(ctx);
  return key;
}

X509* self_cert(EVP_PKEY* key, const char* cn, bool ip) {
  X509* cert = X509_new();
  X509_set_version(cert, 2);
  ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);
  X509_gmtime_adj(X509_getm_notBefore(cert), -60);
  X509_gmtime_adj(X509_getm_notAfter(cert), 86400L * 365);
  X509_set_pubkey(cert, key);
  X509_NAME* name = X509_get_subject_name(cert);
  X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, reinterpret_cast<const unsigned char*>(cn), -1, -1, 0);
  X509_set_issuer_name(cert, name);
  if (ip) {
    X509V3_CTX v3;
    X509V3_set_ctx_nodb(&v3);
    X509V3_set_ctx(&v3, cert, cert, nullptr, nullptr, 0);
    X509_EXTENSION* alt = X509V3_EXT_conf_nid(nullptr, &v3, NID_subject_alt_name, "DNS:localhost,IP:127.0.0.1");
    if (alt != nullptr) {
      X509_add_ext(cert, alt, -1);
      X509_EXTENSION_free(alt);
    }
  }
  X509_sign(cert, key, EVP_sha256());
  return cert;
}

EVP_PKEY* make_rsa() {
  EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
  EVP_PKEY_keygen_init(ctx);
  EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048);
  EVP_PKEY* key = nullptr;
  EVP_PKEY_keygen(ctx, &key);
  EVP_PKEY_CTX_free(ctx);
  return key;
}

std::string bn_b64(const BIGNUM* bn) {
  std::vector<unsigned char> raw(static_cast<size_t>(BN_num_bytes(bn)));
  BN_bn2bin(bn, raw.data());
  return b64url_encode(raw.data(), raw.size());
}

std::string rsa_jwk_json(EVP_PKEY* key, const char* kid) {
  BIGNUM* n = nullptr;
  BIGNUM* e = nullptr;
  EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_RSA_N, &n);
  EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_RSA_E, &e);
  Json doc = Json::object();
  doc.set("alg", Json::str("RS256"));
  doc.set("e", Json::str(bn_b64(e)));
  doc.set("kid", Json::str(kid));
  doc.set("kty", Json::str("RSA"));
  doc.set("n", Json::str(bn_b64(n)));
  doc.set("use", Json::str("sig"));
  BN_free(n);
  BN_free(e);
  return doc.dump();
}

std::string sign_rs256(EVP_PKEY* key, const std::string& header_json, const std::string& payload_json) {
  std::string signing = b64url_encode(header_json) + "." + b64url_encode(payload_json);
  EVP_MD_CTX* ctx = EVP_MD_CTX_new();
  EVP_DigestSignInit(ctx, nullptr, EVP_sha256(), nullptr, key);
  size_t len = 0;
  EVP_DigestSign(ctx, nullptr, &len, reinterpret_cast<const unsigned char*>(signing.data()), signing.size());
  std::vector<unsigned char> sig(len);
  EVP_DigestSign(ctx, sig.data(), &len, reinterpret_cast<const unsigned char*>(signing.data()), signing.size());
  sig.resize(len);
  EVP_MD_CTX_free(ctx);
  return signing + "." + b64url_encode(sig.data(), sig.size());
}

bool ecdsa_verify_raw(EVP_PKEY* key, const std::string& data, const unsigned char* sig, size_t sig_len) {
  if (key == nullptr || sig_len == 0 || sig_len % 2 != 0) return false;
  size_t half = sig_len / 2;
  BIGNUM* r = BN_bin2bn(sig, static_cast<int>(half), nullptr);
  BIGNUM* s = BN_bin2bn(sig + half, static_cast<int>(half), nullptr);
  ECDSA_SIG* ecdsa = ECDSA_SIG_new();
  if (ECDSA_SIG_set0(ecdsa, r, s) != 1) {
    BN_free(r);
    BN_free(s);
    ECDSA_SIG_free(ecdsa);
    return false;
  }
  int der_len = i2d_ECDSA_SIG(ecdsa, nullptr);
  std::vector<unsigned char> der(static_cast<size_t>(der_len));
  unsigned char* p = der.data();
  i2d_ECDSA_SIG(ecdsa, &p);
  ECDSA_SIG_free(ecdsa);
  EVP_MD_CTX* ctx = EVP_MD_CTX_new();
  bool ok = EVP_DigestVerifyInit(ctx, nullptr, EVP_sha256(), nullptr, key) == 1 &&
            EVP_DigestVerify(ctx, der.data(), der.size(), reinterpret_cast<const unsigned char*>(data.data()), data.size()) == 1;
  EVP_MD_CTX_free(ctx);
  return ok;
}

EVP_PKEY* ec_public_from_jwk(const Json& jwk) {
  auto decode = [](const std::string& text, std::vector<unsigned char>& out) { return b64url_decode(text, out, true); };
  std::vector<unsigned char> x;
  std::vector<unsigned char> y;
  if (!decode(jwk.get("x")->text, x) || !decode(jwk.get("y")->text, y)) return nullptr;
  int size = 32;
  std::string crv = jwk.get("crv") == nullptr ? "" : jwk.get("crv")->text;
  const char* group = "prime256v1";
  if (crv == "P-384") {
    group = "secp384r1";
    size = 48;
  } else if (crv == "P-521") {
    group = "secp521r1";
    size = 66;
  }
  std::vector<unsigned char> point(static_cast<size_t>(1 + size * 2), 0);
  point[0] = 0x04;
  if (static_cast<int>(x.size()) <= size) std::memcpy(point.data() + 1 + size - x.size(), x.data(), x.size());
  if (static_cast<int>(y.size()) <= size) std::memcpy(point.data() + 1 + size + size - y.size(), y.data(), y.size());
  OSSL_PARAM_BLD* bld = OSSL_PARAM_BLD_new();
  OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_GROUP_NAME, group, 0);
  OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PUB_KEY, point.data(), point.size());
  OSSL_PARAM* params = OSSL_PARAM_BLD_to_param(bld);
  EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr);
  EVP_PKEY* key = nullptr;
  if (ctx == nullptr || EVP_PKEY_fromdata_init(ctx) != 1 || EVP_PKEY_fromdata(ctx, &key, EVP_PKEY_PUBLIC_KEY, params) != 1) {
    EVP_PKEY_free(key);
    key = nullptr;
  }
  EVP_PKEY_CTX_free(ctx);
  OSSL_PARAM_free(params);
  OSSL_PARAM_BLD_free(bld);
  return key;
}

std::string response_of(int status, const std::string& body, const std::string& type) {
  std::string reason = "OK";
  if (status == 201) reason = "Created";
  else if (status == 204) reason = "No Content";
  else if (status == 400) reason = "Bad Request";
  else if (status == 401) reason = "Unauthorized";
  else if (status == 404) reason = "Not Found";
  std::string out = "HTTP/1.1 " + std::to_string(status) + " " + reason + "\r\n";
  if (!type.empty()) out += "content-type: " + type + "\r\n";
  out += "content-length: " + std::to_string(body.size()) + "\r\nconnection: close\r\n\r\n" + body;
  return out;
}

struct Auth {
  std::string base;
  std::string server_cert;
  std::string client_key;
  std::string client_cert;
  std::string fingerprint;
  EVP_PKEY* id_key = nullptr;
  std::string id_jwk;
  EVP_PKEY* public_key = nullptr;
  std::string kid;
  int listen_fd = -1;
  SSL_CTX* ctx = nullptr;
  std::thread thread;
  std::atomic<bool> stop{false};
  std::mutex mu;
  std::vector<Seen> seen;
  Behavior behavior;
};

Auth* auth = nullptr;

std::string id_token(Auth* state, const std::string& aud, const std::string& sub) {
  long now = static_cast<long>(std::time(nullptr));
  Json header = Json::object();
  header.set("alg", Json::str("RS256"));
  header.set("kid", Json::str("id1"));
  header.set("typ", Json::str("JWT"));
  Json payload = Json::object();
  payload.set("aud", Json::str(aud));
  payload.set("email", Json::str(sub + "@example.com"));
  payload.set("exp", Json::integer(now + 600));
  payload.set("iat", Json::integer(now));
  payload.set("iss", Json::str(state->base));
  payload.set("name", Json::str("Ada"));
  payload.set("sid", Json::str("sess-1"));
  payload.set("sub", Json::str(sub));
  return sign_rs256(state->id_key, header.dump(), payload.dump());
}

std::string verify_request(Auth* state, const std::string& method, const std::string& target, const std::string& headers,
                           const std::string& body) {
  if (!body.empty() && target.size() >= 5 && target.compare(target.size() - 5, 5, "/gnap") == 0 && method == "POST") {
    try {
      Json doc = Json::parse(body);
      const Json* client = doc.get("client");
      if (client != nullptr && client->type == Type::Object) {
        const Json* key = client->get("key");
        const Json* jwk = key == nullptr ? nullptr : key->get("jwk");
        if (jwk != nullptr && jwk->type == Type::Object && jwk->get("kty") != nullptr && jwk->get("kty")->text == "EC") {
          EVP_PKEY* pub = ec_public_from_jwk(*jwk);
          if (pub == nullptr) return "jwk";
          std::lock_guard<std::mutex> lock(state->mu);
          EVP_PKEY_free(state->public_key);
          state->public_key = pub;
          state->kid = jwk->get("kid") == nullptr ? "" : jwk->get("kid")->text;
        }
      }
    } catch (...) {
    }
  }
  std::string signature = header_get(headers, "signature");
  std::string input = header_get(headers, "signature-input");
  if (!signature.empty()) {
    if (input.find(";alg=") != std::string::npos) return "alg parameter";
    auto open = input.find("sig1=(");
    auto close = input.find(')');
    if (open == std::string::npos || close == std::string::npos || close < open) return input;
    std::string inside = input.substr(open + 6, close - (open + 6));
    std::string rest = input.substr(close + 1);
    if (rest.find("tag=\"gnap\"") == std::string::npos) return "tag";
    std::string kid;
    EVP_PKEY* pub = nullptr;
    {
      std::lock_guard<std::mutex> lock(state->mu);
      kid = state->kid;
      if (state->public_key != nullptr) pub = state->public_key;
      EVP_PKEY_up_ref(pub);
    }
    if (rest.find("keyid=\"" + kid + "\"") == std::string::npos) {
      EVP_PKEY_free(pub);
      return "keyid";
    }
    std::vector<std::string> names;
    std::string quoted;
    size_t at = 0;
    while (at < inside.size()) {
      auto q1 = inside.find('"', at);
      if (q1 == std::string::npos) break;
      auto q2 = inside.find('"', q1 + 1);
      if (q2 == std::string::npos) break;
      std::string name = inside.substr(q1 + 1, q2 - q1 - 1);
      if (!quoted.empty()) quoted.push_back(' ');
      quoted += "\"" + name + "\"";
      names.push_back(name);
      at = q2 + 1;
    }
    std::string serialised = "(" + quoted + ")" + rest;
    std::string base;
    for (const auto& component : names) {
      std::string value;
      if (component == "@method") {
        value = method;
      } else if (component == "@target-uri") {
        value = target;
      } else {
        value = trim_copy(header_get(headers, component));
      }
      if (!base.empty()) base.push_back('\n');
      base += "\"" + component + "\": " + value;
    }
    if (!base.empty()) base.push_back('\n');
    base += "\"@signature-params\": " + serialised;
    auto colon = signature.find("sig1=:");
    auto end = signature.rfind(':');
    if (colon == std::string::npos || end == std::string::npos || end <= colon + 6) {
      EVP_PKEY_free(pub);
      return "signature";
    }
    std::string b64 = signature.substr(colon + 6, end - (colon + 6));
    std::vector<unsigned char> raw;
    if (!b64std_decode(b64, raw) || raw.empty() || raw.size() % 2 != 0 || pub == nullptr ||
        !ecdsa_verify_raw(pub, base, raw.data(), raw.size())) {
      EVP_PKEY_free(pub);
      return "httpsig verify";
    }
    EVP_PKEY_free(pub);
    if (!body.empty()) {
      auto sum = sha256_bytes(body);
      std::string digest = "sha-256=:";
      digest += iya::gnap::b64std_encode(sum.data(), sum.size());
      digest += ":";
      if (header_get(headers, "content-digest") != digest) return "content-digest";
    }
  }
  std::string detached = header_get(headers, "detached-jws");
  if (!detached.empty()) {
    std::string parts[3];
    size_t start = 0;
    int count = 0;
    for (size_t i = 0; i <= detached.size() && count < 3; i++) {
      if (i == detached.size() || detached[i] == '.') {
        if (count < 3) parts[count++] = detached.substr(start, i - start);
        start = i + 1;
      }
    }
    if (count != 3) return "detached";
    std::vector<unsigned char> header_raw;
    if (!b64url_decode(parts[0], header_raw, false)) return "detached";
    Json header = Json::parse(std::string(reinterpret_cast<char*>(header_raw.data()), header_raw.size()));
    if ((header.get("typ") == nullptr || header.get("typ")->text != "gnap-binding-jwsd") ||
        (header.get("alg") == nullptr || header.get("alg")->text != "ES256")) {
      return "jws header";
    }
    std::string kid;
    EVP_PKEY* pub = nullptr;
    {
      std::lock_guard<std::mutex> lock(state->mu);
      kid = state->kid;
      pub = state->public_key;
      EVP_PKEY_up_ref(pub);
    }
    std::string htm = header.get("htm") == nullptr ? "" : header.get("htm")->text;
    std::string uri = header.get("uri") == nullptr ? "" : header.get("uri")->text;
    std::string header_kid = header.get("kid") == nullptr ? "" : header.get("kid")->text;
    if (header_kid != kid || htm != method || uri != target) {
      EVP_PKEY_free(pub);
      return "jws claim";
    }
    std::string authorization = header_get(headers, "authorization");
    if (!authorization.empty()) {
      std::string token = authorization.rfind("GNAP ", 0) == 0 ? authorization.substr(5) : authorization;
      std::string ath = header.get("ath") == nullptr ? "" : header.get("ath")->text;
      if (ath != b64url_encode(sha256_bytes(token))) {
        EVP_PKEY_free(pub);
        return "ath";
      }
    } else if (header.get("ath") != nullptr) {
      EVP_PKEY_free(pub);
      return "ath present";
    }
    std::string payload;
    if (!body.empty()) payload = b64url_encode(sha256_bytes(body));
    if (parts[1] != payload) {
      EVP_PKEY_free(pub);
      return "payload";
    }
    std::vector<unsigned char> sig;
    if (!b64url_decode(parts[2], sig, false) || pub == nullptr || sig.size() % 2 != 0 ||
        !ecdsa_verify_raw(pub, parts[0] + "." + parts[1], sig.data(), sig.size())) {
      EVP_PKEY_free(pub);
      return "jwsd verify";
    }
    EVP_PKEY_free(pub);
  }
  return "";
}

std::string handle_auth(Auth* state, const std::string& method, const std::string& path, const std::string& headers,
                        const std::string& body, const std::string& cert) {
  std::string target = state->base + path;
  {
    std::lock_guard<std::mutex> lock(state->mu);
    state->seen.push_back(Seen{method, path, body, header_get(headers, "authorization"), header_get(headers, "signature"),
                               header_get(headers, "detached-jws"), cert});
  }
  std::string problem = verify_request(state, method, target, headers, body);
  if (!problem.empty()) {
    Json err = Json::object();
    err.set("error", Json::str("invalid_client"));
    err.set("error_description", Json::str(problem));
    return response_of(401, err.dump(), "application/json");
  }
  Behavior behavior;
  {
    std::lock_guard<std::mutex> lock(state->mu);
    behavior = state->behavior;
    if (path == "/continue" && method == "POST" && behavior.too_fast && !behavior.too_fast_sent) {
      state->behavior.too_fast_sent = true;
      Json cont = Json::object();
      Json access = Json::object();
      access.set("value", Json::str("cont-token"));
      cont.set("access_token", std::move(access));
      cont.set("uri", Json::str(state->base + "/continue"));
      cont.set("wait", Json::integer(0));
      Json err = Json::object();
      err.set("continue", std::move(cont));
      err.set("error", Json::str("too_fast"));
      return response_of(400, err.dump(), "application/json");
    }
  }
  if (method == "OPTIONS" && path == "/gnap") {
    Json doc = Json::object();
    Json proofs = Json::array();
    proofs.push(Json::str("httpsig"));
    proofs.push(Json::str("jwsd"));
    proofs.push(Json::str("mtls"));
    Json start = Json::array();
    start.push(Json::str("redirect"));
    Json finish = Json::array();
    finish.push(Json::str("redirect"));
    finish.push(Json::str("push"));
    Json subs = Json::array();
    subs.push(Json::str("iss_sub"));
    subs.push(Json::str("opaque"));
    Json assertions = Json::array();
    assertions.push(Json::str("id_token"));
    doc.set("assertion_formats_supported", std::move(assertions));
    doc.set("grant_request_endpoint", Json::str(state->base + "/gnap"));
    doc.set("interaction_finish_methods_supported", std::move(finish));
    doc.set("interaction_start_modes_supported", std::move(start));
    doc.set("key_proofs_supported", std::move(proofs));
    doc.set("sub_id_formats_supported", std::move(subs));
    return response_of(200, doc.dump(), "application/json");
  }
  if (path == "/.well-known/openid-configuration") {
    Json doc = Json::object();
    doc.set("issuer", Json::str(state->base));
    doc.set("jwks_uri", Json::str(state->base + "/jwks"));
    return response_of(200, doc.dump(), "application/json");
  }
  if (path == "/jwks") {
    Json keys = Json::array();
    keys.push(Json::parse(state->id_jwk));
    Json doc = Json::object();
    doc.set("keys", std::move(keys));
    return response_of(200, doc.dump(), "application/json");
  }
  if (path == "/gnap" && method == "POST") {
    std::string cont = behavior.foreign ? "https://evil.example/continue" : state->base + "/continue";
    Json finish = Json::object();
    finish.set("finish", Json::str("server-nonce"));
    finish.set("redirect", Json::str(state->base + "/interact/1"));
    Json access = Json::object();
    access.set("value", Json::str("cont-token"));
    Json continue_doc = Json::object();
    continue_doc.set("access_token", std::move(access));
    continue_doc.set("uri", Json::str(cont));
    continue_doc.set("wait", Json::integer(0));
    Json doc = Json::object();
    doc.set("continue", std::move(continue_doc));
    doc.set("instance_id", Json::str("instance-1"));
    doc.set("interact", std::move(finish));
    return response_of(200, doc.dump(), "application/json");
  }
  if (path == "/continue" && method == "POST") {
    if (header_get(headers, "authorization") != "GNAP cont-token") {
      Json err = Json::object();
      err.set("error", Json::str("invalid_token"));
      return response_of(401, err.dump(), "application/json");
    }
    std::string subject_sub = behavior.iss_sub.empty() ? behavior.sub : behavior.iss_sub;
    Json token = Json::object();
    Json access = Json::array();
    access.push(Json::str("ssf.read"));
    access.push(Json::str("ssf.manage"));
    token.set("access", std::move(access));
    token.set("expires_in", Json::integer(3600));
    Json manage_token = Json::object();
    manage_token.set("value", Json::str("manage-1"));
    Json manage = Json::object();
    manage.set("access_token", std::move(manage_token));
    manage.set("uri", Json::str(state->base + "/token/grant-9"));
    token.set("manage", std::move(manage));
    token.set("value", Json::str("access-1"));
    if (behavior.bearer) {
      Json flags = Json::array();
      flags.push(Json::str("bearer"));
      token.set("flags", std::move(flags));
    }
    Json cont_token = Json::object();
    cont_token.set("value", Json::str("cont-next"));
    Json cont = Json::object();
    cont.set("access_token", std::move(cont_token));
    cont.set("uri", Json::str(state->base + "/continue/grant-9"));
    Json iss = Json::object();
    iss.set("format", Json::str("iss_sub"));
    iss.set("iss", Json::str(state->base));
    iss.set("sub", Json::str(subject_sub));
    Json assertion = Json::object();
    assertion.set("format", Json::str("id_token"));
    assertion.set("value", Json::str(id_token(state, behavior.aud, behavior.sub)));
    Json subs = Json::array();
    subs.push(std::move(iss));
    Json assertions = Json::array();
    assertions.push(std::move(assertion));
    Json subject = Json::object();
    subject.set("assertions", std::move(assertions));
    subject.set("sub_ids", std::move(subs));
    Json doc = Json::object();
    doc.set("access_token", std::move(token));
    doc.set("continue", std::move(cont));
    doc.set("instance_id", Json::str("instance-1"));
    doc.set("subject", std::move(subject));
    return response_of(200, doc.dump(), "application/json");
  }
  if (path == "/token/grant-9" && method == "POST") {
    if (header_get(headers, "authorization") != "GNAP manage-1") {
      Json err = Json::object();
      err.set("error", Json::str("invalid_token"));
      return response_of(401, err.dump(), "application/json");
    }
    Json token = Json::object();
    token.set("expires_in", Json::integer(3600));
    Json manage_token = Json::object();
    manage_token.set("value", Json::str("manage-2"));
    Json manage = Json::object();
    manage.set("access_token", std::move(manage_token));
    manage.set("uri", Json::str(state->base + "/token/grant-9"));
    token.set("manage", std::move(manage));
    token.set("value", Json::str("access-2"));
    Json doc = Json::object();
    doc.set("access_token", std::move(token));
    return response_of(200, doc.dump(), "application/json");
  }
  if (method == "DELETE") return response_of(204, "", "application/json");
  Json err = Json::object();
  err.set("error", Json::str("not_found"));
  return response_of(404, err.dump(), "application/json");
}

void serve_fd(int fd, SSL* ssl, const std::function<std::string(const std::string&, const std::string&, const std::string&, const std::string&)>& handler) {
  std::string raw;
  char buf[4096];
  while (raw.find("\r\n\r\n") == std::string::npos) {
    int n = ssl == nullptr ? static_cast<int>(::recv(fd, buf, sizeof(buf), 0)) : SSL_read(ssl, buf, sizeof(buf));
    if (n <= 0) {
      if (ssl != nullptr) SSL_shutdown(ssl);
      close(fd);
      return;
    }
    raw.append(buf, static_cast<size_t>(n));
    if (raw.size() > 2 * 1024 * 1024) break;
  }
  auto split = raw.find("\r\n\r\n");
  if (split == std::string::npos) {
    close(fd);
    return;
  }
  std::string head = raw.substr(0, split);
  std::string body = raw.substr(split + 4);
  auto line_end = head.find("\r\n");
  std::string start = line_end == std::string::npos ? head : head.substr(0, line_end);
  std::string headers = line_end == std::string::npos ? "" : head.substr(line_end + 2);
  std::string method;
  std::string path;
  auto sp1 = start.find(' ');
  auto sp2 = sp1 == std::string::npos ? std::string::npos : start.find(' ', sp1 + 1);
  if (sp1 != std::string::npos) {
    method = start.substr(0, sp1);
    path = sp2 == std::string::npos ? start.substr(sp1 + 1) : start.substr(sp1 + 1, sp2 - sp1 - 1);
  }
  auto q = path.find('?');
  if (q != std::string::npos) path = path.substr(0, q);
  std::string length = header_get(headers, "content-length");
  if (!length.empty()) {
    long need = std::strtol(length.c_str(), nullptr, 10);
    while (static_cast<long>(body.size()) < need) {
      int n = ssl == nullptr ? static_cast<int>(::recv(fd, buf, sizeof(buf), 0)) : SSL_read(ssl, buf, sizeof(buf));
      if (n <= 0) break;
      body.append(buf, static_cast<size_t>(n));
    }
    if (static_cast<long>(body.size()) > need) body.resize(static_cast<size_t>(need));
  }
  std::string reply = handler(method, path, headers, body);
  size_t sent = 0;
  while (sent < reply.size()) {
    int n = ssl == nullptr ? static_cast<int>(::send(fd, reply.data() + sent, reply.size() - sent, MSG_NOSIGNAL))
                           : SSL_write(ssl, reply.data() + sent, static_cast<int>(reply.size() - sent));
    if (n <= 0) break;
    sent += static_cast<size_t>(n);
  }
  if (ssl != nullptr) SSL_shutdown(ssl);
  close(fd);
}

int listen_loopback(int& port) {
  int fd = ::socket(AF_INET, SOCK_STREAM, 0);
  int yes = 1;
  setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  addr.sin_port = htons(0);
  if (bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
    close(fd);
    return -1;
  }
  socklen_t len = sizeof(addr);
  getsockname(fd, reinterpret_cast<sockaddr*>(&addr), &len);
  port = ntohs(addr.sin_port);
  listen(fd, 32);
  return fd;
}

struct TxItem {
  std::string jti;
  std::string token;
};

struct Tx {
  std::string base;
  int listen_fd = -1;
  std::thread thread;
  std::atomic<bool> stop{false};
  std::mutex mu;
  std::vector<TxItem> queue;
  std::vector<std::string> acked;
  std::map<std::string, std::string> errs;
  int streams = 0;
  std::string authorization;
  EVP_PKEY* key = nullptr;
  EVP_PKEY* other = nullptr;
  std::string jwk;
};

Tx* tx = nullptr;
std::mutex unit_mu;
EVP_PKEY* unit_key = nullptr;
EVP_PKEY* unit_other = nullptr;
std::string unit_jwk;

std::string random_jti() {
  unsigned char buf[16];
  RAND_bytes(buf, sizeof(buf));
  return b64url_encode(buf, sizeof(buf));
}

std::string sets_json_locked(Tx* state) {
  std::string out = "{\"sets\":{";
  for (size_t i = 0; i < state->queue.size(); i++) {
    if (i) out.push_back(',');
    out += Json::str(state->queue[i].jti).dump();
    out.push_back(':');
    out += Json::str(state->queue[i].token).dump();
  }
  out += "},\"moreAvailable\":false}";
  return out;
}

void drop_locked(Tx* state, const std::string& jti) {
  std::vector<TxItem> next;
  for (const auto& item : state->queue)
    if (item.jti != jti) next.push_back(item);
  state->queue = std::move(next);
}

std::string handle_tx(Tx* state, const std::string& method, const std::string& path, const std::string& headers,
                      const std::string& body) {
  std::string authz = header_get(headers, "authorization");
  {
    std::lock_guard<std::mutex> lock(state->mu);
    state->authorization = authz;
  }
  if (authz != "GNAP app-token" && path != "/.well-known/ssf-configuration" && path.rfind("/jwks", 0) != 0) {
    Json err = Json::object();
    err.set("error", Json::str("invalid_token"));
    return response_of(401, err.dump(), "application/json");
  }
  if (path == "/.well-known/ssf-configuration" && method == "GET") {
    Json methods = Json::array();
    methods.push(Json::str("urn:ietf:rfc:8936"));
    Json doc = Json::object();
    doc.set("configuration_endpoint", Json::str(state->base + "/ssf/stream"));
    doc.set("delivery_methods_supported", std::move(methods));
    doc.set("issuer", Json::str(state->base));
    doc.set("jwks_uri", Json::str(state->base + "/jwks"));
    doc.set("verification_endpoint", Json::str(state->base + "/ssf/verify"));
    return response_of(200, doc.dump(), "application/json");
  }
  if (path == "/jwks") {
    Json keys = Json::array();
    keys.push(Json::parse(state->jwk));
    Json doc = Json::object();
    doc.set("keys", std::move(keys));
    return response_of(200, doc.dump(), "application/json");
  }
  if (path == "/ssf/stream" && method == "GET") return response_of(200, "[]", "application/json");
  if (path == "/ssf/stream" && method == "POST") {
    Json doc = Json::parse(body.empty() ? "{}" : body);
    int id = 0;
    {
      std::lock_guard<std::mutex> lock(state->mu);
      state->streams++;
      id = state->streams;
    }
    std::string method_name = "urn:ietf:rfc:8936";
    if (doc.get("delivery") != nullptr && doc.get("delivery")->type == Type::Object && doc.get("delivery")->get("method") != nullptr &&
        doc.get("delivery")->get("method")->type == Type::String) {
      method_name = doc.get("delivery")->get("method")->text;
    }
    Json delivery = Json::object();
    delivery.set("endpoint_url", Json::str(state->base + "/ssf/poll/s" + std::to_string(id)));
    delivery.set("method", Json::str(method_name));
    Json stream = Json::object();
    stream.set("aud", Json::str("my-app"));
    stream.set("delivery", std::move(delivery));
    if (doc.get("events_requested") != nullptr) {
      stream.set("events_delivered", *doc.get("events_requested"));
      stream.set("events_requested", *doc.get("events_requested"));
    }
    stream.set("iss", Json::str(state->base));
    stream.set("stream_id", Json::str("s" + std::to_string(id)));
    return response_of(201, stream.dump(), "application/json");
  }
  if (path == "/ssf/verify") return response_of(204, "", "");
  if (path.rfind("/ssf/poll/", 0) == 0) {
    Json doc = body.empty() ? Json::object() : Json::parse(body);
    std::string payload;
    {
      std::lock_guard<std::mutex> lock(state->mu);
      if (doc.get("ack") != nullptr && doc.get("ack")->type == Type::Array) {
        for (const auto& item : doc.get("ack")->arr) {
          if (item.type != Type::String) continue;
          state->acked.push_back(item.text);
          drop_locked(state, item.text);
        }
      }
      if (doc.get("setErrs") != nullptr && doc.get("setErrs")->type == Type::Object) {
        for (const auto& item : doc.get("setErrs")->obj) {
          std::string err = item.second.type == Type::Object && item.second.get("err") != nullptr ? item.second.get("err")->text : "";
          state->errs[item.first] = err;
          drop_locked(state, item.first);
        }
      }
      payload = sets_json_locked(state);
    }
    return response_of(200, payload, "application/json");
  }
  Json err = Json::object();
  err.set("error", Json::str("not_found"));
  return response_of(404, err.dump(), "application/json");
}

}  // namespace

int harness_auth_start(void) {
  if (auth != nullptr) return 0;
  auth = new Auth();
  EVP_PKEY* server_key = make_p256();
  X509* server_cert = self_cert(server_key, "localhost", true);
  EVP_PKEY* client_key = make_p256();
  X509* client_cert = self_cert(client_key, "gnap-client", false);
  auth->server_cert = pem_of_cert(server_cert);
  auth->client_key = pem_of_pkey(client_key);
  auth->client_cert = pem_of_cert(client_cert);
  auth->fingerprint = fingerprint_x509(client_cert);
  auth->id_key = make_rsa();
  auth->id_jwk = rsa_jwk_json(auth->id_key, "id1");
  auth->ctx = SSL_CTX_new(TLS_server_method());
  SSL_CTX_set_min_proto_version(auth->ctx, TLS1_2_VERSION);
  SSL_CTX_use_certificate(auth->ctx, server_cert);
  SSL_CTX_use_PrivateKey(auth->ctx, server_key);
  SSL_CTX_set_verify(auth->ctx, SSL_VERIFY_PEER, [](int, X509_STORE_CTX*) { return 1; });
  X509_free(server_cert);
  X509_free(client_cert);
  EVP_PKEY_free(server_key);
  EVP_PKEY_free(client_key);
  int port = 0;
  auth->listen_fd = listen_loopback(port);
  if (auth->listen_fd < 0) return -1;
  auth->base = "https://127.0.0.1:" + std::to_string(port);
  auth->thread = std::thread([] {
    while (!auth->stop.load()) {
      sockaddr_in peer{};
      socklen_t len = sizeof(peer);
      int fd = accept(auth->listen_fd, reinterpret_cast<sockaddr*>(&peer), &len);
      if (fd < 0) break;
      SSL* ssl = SSL_new(auth->ctx);
      SSL_set_fd(ssl, fd);
      if (SSL_accept(ssl) != 1) {
        SSL_free(ssl);
        close(fd);
        continue;
      }
      X509* peer_cert = SSL_get1_peer_certificate(ssl);
      std::string fp = peer_cert == nullptr ? "" : fingerprint_x509(peer_cert);
      X509_free(peer_cert);
      serve_fd(fd, ssl, [fp](const std::string& method, const std::string& path, const std::string& headers, const std::string& body) {
        return handle_auth(auth, method, path, headers, body, fp);
      });
      SSL_free(ssl);
    }
  });
  return 0;
}

void harness_auth_reset(void) {
  std::lock_guard<std::mutex> lock(auth->mu);
  auth->seen.clear();
  auth->behavior = Behavior();
}

void harness_auth_stop(void) {
  if (auth == nullptr) return;
  auth->stop = true;
  if (auth->listen_fd >= 0) {
    shutdown(auth->listen_fd, SHUT_RDWR);
    close(auth->listen_fd);
    auth->listen_fd = -1;
  }
  if (auth->thread.joinable()) auth->thread.join();
  SSL_CTX_free(auth->ctx);
  EVP_PKEY_free(auth->id_key);
  EVP_PKEY_free(auth->public_key);
  delete auth;
  auth = nullptr;
}

const char* harness_auth_base(void) { return auth->base.c_str(); }
const char* harness_auth_server_cert(void) { return auth->server_cert.c_str(); }
const char* harness_auth_client_key(void) { return auth->client_key.c_str(); }
const char* harness_auth_client_cert(void) { return auth->client_cert.c_str(); }
const char* harness_auth_fingerprint(void) { return auth->fingerprint.c_str(); }

void harness_set_foreign(int value) {
  std::lock_guard<std::mutex> lock(auth->mu);
  auth->behavior.foreign = value != 0;
}
void harness_set_bearer(int value) {
  std::lock_guard<std::mutex> lock(auth->mu);
  auth->behavior.bearer = value != 0;
}
void harness_set_too_fast(int value) {
  std::lock_guard<std::mutex> lock(auth->mu);
  auth->behavior.too_fast = value != 0;
}
void harness_set_aud(const char* value) {
  std::lock_guard<std::mutex> lock(auth->mu);
  auth->behavior.aud = value == nullptr ? "" : value;
}
void harness_set_sub(const char* value) {
  std::lock_guard<std::mutex> lock(auth->mu);
  auth->behavior.sub = value == nullptr ? "" : value;
}
void harness_set_iss_sub(const char* value) {
  std::lock_guard<std::mutex> lock(auth->mu);
  auth->behavior.iss_sub = value == nullptr ? "" : value;
}
int harness_too_fast_sent(void) {
  std::lock_guard<std::mutex> lock(auth->mu);
  return auth->behavior.too_fast_sent ? 1 : 0;
}
void harness_clear_seen(void) {
  std::lock_guard<std::mutex> lock(auth->mu);
  auth->seen.clear();
}
int harness_url_count(const char* url) {
  std::lock_guard<std::mutex> lock(auth->mu);
  int count = 0;
  for (const auto& item : auth->seen)
    if (item.url == url) count++;
  return count;
}
const char* harness_last_post_gnap_body(void) {
  std::lock_guard<std::mutex> lock(auth->mu);
  static std::string body;
  body.clear();
  for (const auto& item : auth->seen)
    if (item.method == "POST" && item.url == "/gnap") body = item.body;
  return body.c_str();
}
int harness_last_has_signature(void) {
  std::lock_guard<std::mutex> lock(auth->mu);
  if (auth->seen.empty()) return 0;
  return auth->seen.back().signature.empty() ? 0 : 1;
}
const char* harness_first(const char* url, const char* field) {
  std::lock_guard<std::mutex> lock(auth->mu);
  static std::string value;
  value.clear();
  for (const auto& item : auth->seen) {
    if (item.url != url) continue;
    std::string name = field == nullptr ? "" : field;
    if (name == "signature") value = item.signature;
    else if (name == "detached") value = item.detached;
    else if (name == "cert") value = item.cert;
    else if (name == "authorization") value = item.authorization;
    else if (name == "method") value = item.method;
    else if (name == "body") value = item.body;
    break;
  }
  return value.c_str();
}
const char* harness_last_method(void) {
  std::lock_guard<std::mutex> lock(auth->mu);
  static std::string value;
  value = auth->seen.empty() ? "" : auth->seen.back().method;
  return value.c_str();
}
const char* harness_last_authorization(void) {
  std::lock_guard<std::mutex> lock(auth->mu);
  static std::string value;
  value = auth->seen.empty() ? "" : auth->seen.back().authorization;
  return value.c_str();
}
int harness_detached_contains_dot(const char* url) {
  std::lock_guard<std::mutex> lock(auth->mu);
  for (const auto& item : auth->seen)
    if (item.url == url && item.detached.find('.') != std::string::npos) return 1;
  return 0;
}

int harness_tx_start(void) {
  if (tx != nullptr) return 0;
  tx = new Tx();
  tx->key = make_rsa();
  tx->other = make_rsa();
  tx->jwk = rsa_jwk_json(tx->key, "k1");
  int port = 0;
  tx->listen_fd = listen_loopback(port);
  if (tx->listen_fd < 0) return -1;
  tx->base = "http://127.0.0.1:" + std::to_string(port);
  tx->thread = std::thread([] {
    while (!tx->stop.load()) {
      sockaddr_in peer{};
      socklen_t len = sizeof(peer);
      int fd = accept(tx->listen_fd, reinterpret_cast<sockaddr*>(&peer), &len);
      if (fd < 0) break;
      serve_fd(fd, nullptr, [](const std::string& method, const std::string& path, const std::string& headers, const std::string& body) {
        return handle_tx(tx, method, path, headers, body);
      });
    }
  });
  return 0;
}

void harness_tx_stop(void) {
  if (tx == nullptr) return;
  tx->stop = true;
  if (tx->listen_fd >= 0) {
    shutdown(tx->listen_fd, SHUT_RDWR);
    close(tx->listen_fd);
  }
  if (tx->thread.joinable()) tx->thread.join();
  EVP_PKEY_free(tx->key);
  EVP_PKEY_free(tx->other);
  delete tx;
  tx = nullptr;
}

const char* harness_tx_base(void) { return tx->base.c_str(); }

void harness_tx_deliver(const char* event_type, const char* sub_json, int other_key, char* jti_out, unsigned long jti_len) {
  std::string jti = random_jti();
  Json header = Json::object();
  header.set("alg", Json::str("RS256"));
  header.set("kid", Json::str("k1"));
  header.set("typ", Json::str("secevent+jwt"));
  Json body = Json::object();
  body.set("event_timestamp", Json::integer(1));
  Json events = Json::object();
  events.set(event_type == nullptr ? "" : event_type, std::move(body));
  Json payload = Json::object();
  payload.set("aud", Json::str("my-app"));
  payload.set("events", std::move(events));
  payload.set("iat", Json::integer(1));
  payload.set("iss", Json::str(tx->base));
  payload.set("jti", Json::str(jti));
  if (sub_json != nullptr && sub_json[0] != '\0') payload.set("sub_id", Json::parse(sub_json));
  std::string token = sign_rs256(other_key ? tx->other : tx->key, header.dump(), payload.dump());
  {
    std::lock_guard<std::mutex> lock(tx->mu);
    tx->queue.push_back(TxItem{jti, token});
  }
  if (jti_out != nullptr && jti_len > 0) {
    std::snprintf(jti_out, jti_len, "%s", jti.c_str());
  }
}

int harness_tx_streams(void) {
  std::lock_guard<std::mutex> lock(tx->mu);
  return tx->streams;
}
const char* harness_tx_authorization(void) {
  std::lock_guard<std::mutex> lock(tx->mu);
  static std::string value;
  value = tx->authorization;
  return value.c_str();
}
int harness_tx_acked_count(void) {
  std::lock_guard<std::mutex> lock(tx->mu);
  return static_cast<int>(tx->acked.size());
}
const char* harness_tx_acked_at(int index) {
  std::lock_guard<std::mutex> lock(tx->mu);
  static std::string value;
  value = index >= 0 && static_cast<size_t>(index) < tx->acked.size() ? tx->acked[static_cast<size_t>(index)] : "";
  return value.c_str();
}
const char* harness_tx_err(const char* jti) {
  std::lock_guard<std::mutex> lock(tx->mu);
  static std::string value;
  auto found = tx->errs.find(jti == nullptr ? "" : jti);
  value = found == tx->errs.end() ? "" : found->second;
  return value.c_str();
}

int harness_sign_rs256(const char* header_json, const char* payload_json, int other_key, char* out, unsigned long out_len) {
  std::lock_guard<std::mutex> lock(unit_mu);
  if (unit_key == nullptr) {
    unit_key = make_rsa();
    unit_other = make_rsa();
    unit_jwk = rsa_jwk_json(unit_key, "k1");
  }
  std::string token = sign_rs256(other_key ? unit_other : unit_key, header_json == nullptr ? "{}" : header_json,
                                 payload_json == nullptr ? "{}" : payload_json);
  if (out == nullptr || token.size() + 1 > out_len) return -1;
  std::memcpy(out, token.data(), token.size() + 1);
  return 0;
}

const char* harness_rsa_jwk(void) {
  std::lock_guard<std::mutex> lock(unit_mu);
  if (unit_key == nullptr) {
    unit_key = make_rsa();
    unit_other = make_rsa();
    unit_jwk = rsa_jwk_json(unit_key, "k1");
  }
  return unit_jwk.c_str();
}
