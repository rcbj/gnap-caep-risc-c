// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

#include "crypto.hpp"

#include "codec.hpp"
#include "url.hpp"
#include "util.hpp"

#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/ecdsa.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/param_build.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <cstring>
#include <ctime>
#include <map>
#include <memory>

namespace iya::gnap {
namespace {

struct BioFree {
  void operator()(BIO* bio) const { BIO_free(bio); }
};
struct PkeyFree {
  void operator()(EVP_PKEY* key) const { EVP_PKEY_free(key); }
};
struct X509Free {
  void operator()(X509* cert) const { X509_free(cert); }
};
struct MdFree {
  void operator()(EVP_MD_CTX* ctx) const { EVP_MD_CTX_free(ctx); }
};
struct BnFree {
  void operator()(BIGNUM* bn) const { BN_free(bn); }
};

using BioPtr = std::unique_ptr<BIO, BioFree>;
using PkeyPtr = std::unique_ptr<EVP_PKEY, PkeyFree>;
using CertPtr = std::unique_ptr<X509, X509Free>;

std::string bio_string(BIO* bio) {
  char* data = nullptr;
  long len = BIO_get_mem_data(bio, &data);
  if (len <= 0 || data == nullptr) return "";
  return std::string(data, static_cast<size_t>(len));
}

std::string b64url_vec(const std::vector<unsigned char>& data) { return b64url_encode(data.data(), data.size()); }

std::vector<unsigned char> bn_bytes(const BIGNUM* bn) {
  if (bn == nullptr || BN_is_zero(bn)) return {0};
  std::vector<unsigned char> out(static_cast<size_t>(BN_num_bytes(bn)));
  BN_bn2bin(bn, out.data());
  return out;
}

std::vector<unsigned char> bn_pad(const BIGNUM* bn, int size) {
  std::vector<unsigned char> out(static_cast<size_t>(size));
  if (bn != nullptr) BN_bn2binpad(bn, out.data(), size);
  return out;
}

int curve_size_bits(EVP_PKEY* key) { return EVP_PKEY_bits(key); }

std::string curve_name_from_bits(int bits) {
  if (bits == 256) return "P-256";
  if (bits == 384) return "P-384";
  if (bits == 521) return "P-521";
  throw Error("config", "a key of this type is not a GNAP client key this library loads");
}

const char* ossl_group(const std::string& crv) {
  if (crv == "P-256") return "prime256v1";
  if (crv == "P-384") return "secp384r1";
  if (crv == "P-521") return "secp521r1";
  return nullptr;
}

int coord_size(const std::string& crv) {
  if (crv == "P-256") return 32;
  if (crv == "P-384") return 48;
  if (crv == "P-521") return 66;
  return 0;
}

const EVP_MD* md_for(const std::string& alg) {
  if (alg == "ES256" || alg == "RS256" || alg == "PS256") return EVP_sha256();
  if (alg == "ES384" || alg == "RS384" || alg == "PS384") return EVP_sha384();
  if (alg == "ES512" || alg == "RS512" || alg == "PS512") return EVP_sha512();
  return nullptr;
}

bool is_eddsa(const std::string& alg) { return alg == "EdDSA" || alg == "Ed25519"; }

std::string kty_of(EVP_PKEY* key) {
  int id = EVP_PKEY_id(key);
  if (id == EVP_PKEY_EC) return "EC";
  if (id == EVP_PKEY_RSA) return "RSA";
  if (id == EVP_PKEY_ED25519) return "OKP";
  throw Error("config", "a key of this type is not a GNAP client key this library loads");
}

std::map<std::string, std::string> jwk_of_pkey(EVP_PKEY* key) {
  std::map<std::string, std::string> jwk;
  std::string kty = kty_of(key);
  jwk["kty"] = kty;
  if (kty == "EC") {
    jwk["crv"] = curve_name_from_bits(curve_size_bits(key));
    BIGNUM* x = nullptr;
    BIGNUM* y = nullptr;
    if (EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_EC_PUB_X, &x) != 1 ||
        EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_EC_PUB_Y, &y) != 1) {
      BN_free(x);
      BN_free(y);
      throw Error("config", "a key of this type is not a GNAP client key this library loads");
    }
    int size = (curve_size_bits(key) + 7) / 8;
    jwk["x"] = b64url_vec(bn_pad(x, size));
    jwk["y"] = b64url_vec(bn_pad(y, size));
    BN_free(x);
    BN_free(y);
  } else if (kty == "RSA") {
    BIGNUM* n = nullptr;
    BIGNUM* e = nullptr;
    if (EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_RSA_N, &n) != 1 ||
        EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_RSA_E, &e) != 1) {
      BN_free(n);
      BN_free(e);
      throw Error("config", "a key of this type is not a GNAP client key this library loads");
    }
    jwk["n"] = b64url_vec(bn_bytes(n));
    jwk["e"] = b64url_vec(bn_bytes(e));
    BN_free(n);
    BN_free(e);
  } else {
    size_t len = 32;
    unsigned char raw[32];
    if (EVP_PKEY_get_raw_public_key(key, raw, &len) != 1 || len != 32) {
      throw Error("config", "a key of this type is not a GNAP client key this library loads");
    }
    jwk["crv"] = "Ed25519";
    jwk["x"] = b64url_encode(raw, len);
  }
  return jwk;
}

std::string thumbprint_of(const std::map<std::string, std::string>& jwk) {
  std::string raw;
  if (jwk.at("kty") == "EC") {
    raw = std::string("{\"crv\":\"") + jwk.at("crv") + "\",\"kty\":\"EC\",\"x\":\"" + jwk.at("x") + "\",\"y\":\"" +
          jwk.at("y") + "\"}";
  } else if (jwk.at("kty") == "RSA") {
    raw = std::string("{\"e\":\"") + jwk.at("e") + "\",\"kty\":\"RSA\",\"n\":\"" + jwk.at("n") + "\"}";
  } else if (jwk.at("kty") == "OKP") {
    raw = std::string("{\"crv\":\"") + jwk.at("crv") + "\",\"kty\":\"OKP\",\"x\":\"" + jwk.at("x") + "\"}";
  } else {
    throw Error("config", "a " + jwk.at("kty") + " key is not a GNAP client key this library loads");
  }
  return b64url_encode(sha256_bytes(raw));
}

std::string alg_of(const std::map<std::string, std::string>& jwk) {
  auto found = jwk.find("alg");
  if (found != jwk.end() && !found->second.empty() && found->second != "none") return found->second;
  if (jwk.at("kty") == "EC") {
    if (jwk.at("crv") == "P-256") return "ES256";
    if (jwk.at("crv") == "P-384") return "ES384";
    if (jwk.at("crv") == "P-521") return "ES512";
    std::string shown = jwk.at("crv").empty() ? "(none)" : jwk.at("crv");
    throw Error("config", "the curve " + shown + " has no signature algorithm");
  }
  if (jwk.at("kty") == "RSA") return "RS256";
  if (jwk.at("kty") == "OKP") return "EdDSA";
  throw Error("config", "a " + jwk.at("kty") + " key is not a GNAP client key this library loads");
}

PkeyPtr read_private(const std::string& pem) {
  BioPtr bio(BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size())));
  if (!bio) throw Error("config", "the private key could not be read: no PEM key");
  EVP_PKEY* key = PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr, nullptr);
  if (key != nullptr) return PkeyPtr(key);
  unsigned long err = ERR_peek_last_error();
  if (err != 0) {
    char buf[256];
    ERR_error_string_n(err, buf, sizeof(buf));
    throw Error("config", std::string("the private key could not be read: ") + buf);
  }
  throw Error("config", "the private key could not be read: no PEM key");
}

CertPtr read_cert(const std::string& pem) {
  BioPtr bio(BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size())));
  if (!bio) throw Error("config", "the certificate could not be read: no PEM certificate");
  X509* cert = PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr);
  if (cert == nullptr) {
    unsigned long err = ERR_peek_last_error();
    if (err == 0) throw Error("config", "the certificate could not be read: no PEM certificate");
    char buf[256];
    ERR_error_string_n(err, buf, sizeof(buf));
    throw Error("config", std::string("the certificate could not be read: ") + buf);
  }
  return CertPtr(cert);
}

std::string pkcs8_pem(EVP_PKEY* key) {
  BioPtr bio(BIO_new(BIO_s_mem()));
  if (PEM_write_bio_PKCS8PrivateKey(bio.get(), key, nullptr, nullptr, 0, nullptr, nullptr) != 1) {
    throw Error("config", "the private key could not be read: no PEM key");
  }
  return bio_string(bio.get());
}

std::string cert_pem_of(X509* cert) {
  BioPtr bio(BIO_new(BIO_s_mem()));
  if (PEM_write_bio_X509(bio.get(), cert) != 1) throw Error("config", "the certificate could not be read: no PEM certificate");
  return bio_string(bio.get());
}

std::vector<unsigned char> cert_der(X509* cert) {
  int len = i2d_X509(cert, nullptr);
  if (len <= 0) throw Error("config", "the certificate could not be read: no PEM certificate");
  std::vector<unsigned char> out(static_cast<size_t>(len));
  unsigned char* p = out.data();
  i2d_X509(cert, &p);
  return out;
}

std::vector<std::string> cert_blocks(const std::string& text) {
  std::vector<std::string> out;
  const std::string begin = "-----BEGIN CERTIFICATE-----";
  const std::string end = "-----END CERTIFICATE-----";
  size_t at = 0;
  while (at < text.size()) {
    auto start = text.find(begin, at);
    if (start == std::string::npos) break;
    auto stop = text.find(end, start);
    if (stop == std::string::npos) break;
    stop += end.size();
    out.push_back(text.substr(start, stop - start));
    at = stop;
  }
  return out;
}

std::vector<unsigned char> b64url_strict(const std::string& value, const std::string& what) {
  for (char c : value) {
    bool ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_';
    if (!ok) throw Error("signature", "the JWS " + what + " is not base64url");
  }
  std::vector<unsigned char> out;
  if (!b64url_decode(value, out, true)) throw Error("signature", "the JWS " + what + " is not base64url");
  return out;
}

std::string supported_jws() {
  return "RS256, RS384, RS512, PS256, PS384, PS512, ES256, ES384, ES512, EdDSA, Ed25519";
}

std::string kty_for_alg(const std::string& alg) {
  if (alg == "RS256" || alg == "RS384" || alg == "RS512" || alg == "PS256" || alg == "PS384" || alg == "PS512")
    return "RSA";
  if (alg == "ES256" || alg == "ES384" || alg == "ES512") return "EC";
  if (alg == "EdDSA" || alg == "Ed25519") return "OKP";
  return "";
}

PkeyPtr pkey_from_jwk(const Json& jwk) {
  std::string kty = jstr_key(jwk, "kty");
  std::string kid = jstr_key(jwk, "kid");
  try {
    if (kty == "RSA") {
      auto nb = b64url_strict(jstr_key(jwk, "n"), "signature");
      auto eb = b64url_strict(jstr_key(jwk, "e"), "signature");
      BIGNUM* n = BN_bin2bn(nb.data(), static_cast<int>(nb.size()), nullptr);
      BIGNUM* e = BN_bin2bn(eb.data(), static_cast<int>(eb.size()), nullptr);
      if (n == nullptr || e == nullptr || BN_is_negative(n) || BN_is_zero(n)) {
        BN_free(n);
        BN_free(e);
        throw Error("signature", "the key " + kid + " cannot be read: bad RSA numbers");
      }
      unsigned long exp = BN_get_word(e);
      if (exp < 2) {
        BN_free(n);
        BN_free(e);
        throw Error("signature", "the key " + kid + " cannot be read: bad RSA numbers");
      }
      OSSL_PARAM_BLD* bld = OSSL_PARAM_BLD_new();
      OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_N, n);
      OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_E, e);
      OSSL_PARAM* params = OSSL_PARAM_BLD_to_param(bld);
      EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_name(nullptr, "RSA", nullptr);
      EVP_PKEY* key = nullptr;
      if (ctx == nullptr || EVP_PKEY_fromdata_init(ctx) != 1 ||
          EVP_PKEY_fromdata(ctx, &key, EVP_PKEY_PUBLIC_KEY, params) != 1) {
        EVP_PKEY_CTX_free(ctx);
        OSSL_PARAM_free(params);
        OSSL_PARAM_BLD_free(bld);
        BN_free(n);
        BN_free(e);
        throw Error("signature", "the key " + kid + " cannot be read: bad RSA numbers");
      }
      EVP_PKEY_CTX_free(ctx);
      OSSL_PARAM_free(params);
      OSSL_PARAM_BLD_free(bld);
      BN_free(n);
      BN_free(e);
      return PkeyPtr(key);
    }
    if (kty == "EC") {
      std::string crv = jstr_key(jwk, "crv");
      const char* group = ossl_group(crv);
      int size = coord_size(crv);
      if (group == nullptr || size == 0) throw Error("signature", "the key " + kid + " cannot be read: unsupported curve");
      auto xb = b64url_strict(jstr_key(jwk, "x"), "signature");
      auto yb = b64url_strict(jstr_key(jwk, "y"), "signature");
      if (static_cast<int>(xb.size()) > size || static_cast<int>(yb.size()) > size) {
        throw Error("signature", "the key " + kid + " cannot be read: unsupported curve");
      }
      std::vector<unsigned char> point(static_cast<size_t>(1 + size * 2), 0);
      point[0] = 0x04;
      std::memcpy(point.data() + 1 + (size - static_cast<int>(xb.size())), xb.data(), xb.size());
      std::memcpy(point.data() + 1 + size + (size - static_cast<int>(yb.size())), yb.data(), yb.size());
      OSSL_PARAM_BLD* bld = OSSL_PARAM_BLD_new();
      OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_GROUP_NAME, group, 0);
      OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PUB_KEY, point.data(), point.size());
      OSSL_PARAM* params = OSSL_PARAM_BLD_to_param(bld);
      EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr);
      EVP_PKEY* key = nullptr;
      if (ctx == nullptr || EVP_PKEY_fromdata_init(ctx) != 1 ||
          EVP_PKEY_fromdata(ctx, &key, EVP_PKEY_PUBLIC_KEY, params) != 1) {
        EVP_PKEY_CTX_free(ctx);
        OSSL_PARAM_free(params);
        OSSL_PARAM_BLD_free(bld);
        throw Error("signature", "the key " + kid + " cannot be read: unsupported curve");
      }
      EVP_PKEY_CTX_free(ctx);
      OSSL_PARAM_free(params);
      OSSL_PARAM_BLD_free(bld);
      return PkeyPtr(key);
    }
    if (kty == "OKP") {
      auto raw = b64url_strict(jstr_key(jwk, "x"), "signature");
      if (raw.size() != 32) throw Error("signature", "the key " + kid + " cannot be read: bad Ed25519 key");
      EVP_PKEY* key = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr, raw.data(), raw.size());
      if (key == nullptr) throw Error("signature", "the key " + kid + " cannot be read: bad Ed25519 key");
      return PkeyPtr(key);
    }
  } catch (const Error& err) {
    if (err.what() == std::string("the JWS signature is not base64url") ||
        std::string(err.what()).find("cannot be read") != std::string::npos) {
      if (std::string(err.what()).find("cannot be read") != std::string::npos) throw;
      throw Error("signature", "the key " + kid + " cannot be read: " + err.what());
    }
    throw;
  }
  throw Error("signature", "the key " + kid + " cannot be read: unsupported " + kty);
}

std::vector<unsigned char> ecdsa_der_to_raw(const unsigned char* der, size_t der_len, int size) {
  const unsigned char* p = der;
  ECDSA_SIG* sig = d2i_ECDSA_SIG(nullptr, &p, static_cast<long>(der_len));
  if (sig == nullptr) throw Error("signature", "the signature could not be read");
  const BIGNUM* r = nullptr;
  const BIGNUM* s = nullptr;
  ECDSA_SIG_get0(sig, &r, &s);
  std::vector<unsigned char> out(static_cast<size_t>(size * 2));
  if (BN_bn2binpad(r, out.data(), size) < 0 || BN_bn2binpad(s, out.data() + size, size) < 0) {
    ECDSA_SIG_free(sig);
    throw Error("signature", "the signature could not be read");
  }
  ECDSA_SIG_free(sig);
  return out;
}

std::vector<unsigned char> raw_to_ecdsa_der(const unsigned char* sig, size_t sig_len) {
  if (sig_len == 0 || sig_len % 2 != 0) return {};
  size_t size = sig_len / 2;
  BIGNUM* r = BN_bin2bn(sig, static_cast<int>(size), nullptr);
  BIGNUM* s = BN_bin2bn(sig + size, static_cast<int>(size), nullptr);
  ECDSA_SIG* ecdsa = ECDSA_SIG_new();
  if (r == nullptr || s == nullptr || ecdsa == nullptr || ECDSA_SIG_set0(ecdsa, r, s) != 1) {
    BN_free(r);
    BN_free(s);
    ECDSA_SIG_free(ecdsa);
    return {};
  }
  int len = i2d_ECDSA_SIG(ecdsa, nullptr);
  std::vector<unsigned char> der(static_cast<size_t>(len));
  unsigned char* p = der.data();
  i2d_ECDSA_SIG(ecdsa, &p);
  ECDSA_SIG_free(ecdsa);
  return der;
}

std::string sf_string(const std::string& value) {
  std::string escaped;
  for (char c : value) {
    if (c == '\\' || c == '"') escaped.push_back('\\');
    escaped.push_back(c);
  }
  return "\"" + escaped + "\"";
}

std::string lower_header(std::string name) {
  for (char& c : name)
    if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
  return name;
}

}  // namespace

ClientKey::~ClientKey() { EVP_PKEY_free(pkey); }

std::shared_ptr<ClientKey> load_client_key(const std::string& private_pem, const std::string& certificate_pem,
                                           const std::string& proof) {
  PkeyPtr private_key = read_private(private_pem);
  auto jwk = jwk_of_pkey(private_key.get());
  jwk["alg"] = alg_of(jwk);
  std::string thumb = thumbprint_of(jwk);
  jwk["kid"] = thumb;
  CertPtr cert;
  if (!trim_copy(certificate_pem).empty()) {
    cert = read_cert(certificate_pem);
    PkeyPtr pub(X509_get_pubkey(cert.get()));
    if (!pub || EVP_PKEY_eq(private_key.get(), pub.get()) != 1) {
      throw Error("config", "the certificate is not the public half of the private key");
    }
  }
  std::string chosen = proof;
  if (chosen.empty()) chosen = cert ? "mtls" : "httpsig";
  if (chosen != "mtls" && chosen != "httpsig" && chosen != "jwsd") {
    throw Error("config", "keyProof must be mtls, httpsig, jwsd, not " + chosen);
  }
  if (chosen == "mtls" && !cert) throw Error("config", "keyProof \"mtls\" needs certificate");
  auto out = std::make_shared<ClientKey>();
  out->private_pem = pkcs8_pem(private_key.get());
  out->alg = jwk["alg"];
  out->kid = jwk["kid"];
  out->jwk = jwk;
  out->pkey = private_key.release();
  if (chosen == "mtls") {
    auto blocks = cert_blocks(certificate_pem);
    std::string leaf_source = certificate_pem;
    if (!blocks.empty()) leaf_source = blocks[0];
    out->cert_pem = trim_copy(leaf_source) + "\n";
    auto chain_source = blocks;
    if (chain_source.empty()) chain_source.push_back(certificate_pem);
    std::string chain;
    for (size_t i = 0; i < chain_source.size(); i++) {
      if (i) chain.push_back('\n');
      chain += trim_copy(chain_source[i]);
    }
    chain.push_back('\n');
    auto der = cert_der(cert.get());
    out->thumb = b64url_encode(sha256_bytes(der));
    out->chain_pem = chain;
    out->proof = "mtls";
    return out;
  }
  out->proof = chosen;
  out->thumb = jwk["kid"];
  out->cert_pem = certificate_pem;
  return out;
}

Json public_key_object(const ClientKey& key) {
  if (key.proof == "mtls") {
    if (trim_copy(key.cert_pem).empty()) throw Error("config", "mutual TLS needs the client certificate");
    Json out = Json::object();
    out.set("proof", Json::str("mtls"));
    out.set("cert", Json::str(trim_copy(key.cert_pem)));
    return out;
  }
  if (key.jwk.empty()) throw Error("config", key.proof + " needs a JWK");
  Json jwk = Json::object();
  jwk.set("kty", Json::str(key.jwk.at("kty")));
  for (const char* name : {"crv", "x", "y", "n", "e"}) {
    auto found = key.jwk.find(name);
    if (found != key.jwk.end() && !found->second.empty()) jwk.set(name, Json::str(found->second));
  }
  jwk.set("alg", Json::str(key.alg));
  jwk.set("kid", Json::str(key.kid));
  Json out = Json::object();
  out.set("proof", Json::str(key.proof));
  out.set("jwk", std::move(jwk));
  return out;
}

std::vector<unsigned char> sign_message(const ClientKey& key, const std::string& data) {
  if (key.pkey == nullptr) throw Error("config", "a key of this type is not a GNAP client key this library loads");
  if (EVP_PKEY_id(key.pkey) == EVP_PKEY_ED25519) {
    if (!is_eddsa(key.alg)) throw Error("config", "this library does not sign with " + key.alg);
    std::unique_ptr<EVP_MD_CTX, MdFree> ctx(EVP_MD_CTX_new());
    size_t len = 0;
    if (EVP_DigestSignInit(ctx.get(), nullptr, nullptr, nullptr, key.pkey) != 1 ||
        EVP_DigestSign(ctx.get(), nullptr, &len, reinterpret_cast<const unsigned char*>(data.data()), data.size()) !=
            1) {
      throw Error("signature", "the signature could not be made");
    }
    std::vector<unsigned char> out(len);
    if (EVP_DigestSign(ctx.get(), out.data(), &len, reinterpret_cast<const unsigned char*>(data.data()), data.size()) !=
        1) {
      throw Error("signature", "the signature could not be made");
    }
    out.resize(len);
    return out;
  }
  const EVP_MD* md = md_for(key.alg);
  if (md == nullptr) throw Error("config", "this library does not sign with " + key.alg);
  std::unique_ptr<EVP_MD_CTX, MdFree> ctx(EVP_MD_CTX_new());
  EVP_PKEY_CTX* pctx = nullptr;
  if (EVP_DigestSignInit(ctx.get(), &pctx, md, nullptr, key.pkey) != 1) {
    throw Error("signature", "the signature could not be made");
  }
  if (key.alg.rfind("PS", 0) == 0) {
    EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING);
    EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, RSA_PSS_SALTLEN_DIGEST);
  }
  size_t len = 0;
  if (EVP_DigestSign(ctx.get(), nullptr, &len, reinterpret_cast<const unsigned char*>(data.data()), data.size()) != 1) {
    throw Error("signature", "the signature could not be made");
  }
  std::vector<unsigned char> der(len);
  if (EVP_DigestSign(ctx.get(), der.data(), &len, reinterpret_cast<const unsigned char*>(data.data()), data.size()) !=
      1) {
    throw Error("signature", "the signature could not be made");
  }
  der.resize(len);
  if (EVP_PKEY_id(key.pkey) == EVP_PKEY_EC) {
    int size = (EVP_PKEY_bits(key.pkey) + 7) / 8;
    return ecdsa_der_to_raw(der.data(), der.size(), size);
  }
  return der;
}

bool verify_message(EVP_PKEY* pub, const std::string& alg, const std::string& data, const unsigned char* sig,
                    size_t sig_len) {
  if (pub == nullptr || sig == nullptr) return false;
  std::unique_ptr<EVP_MD_CTX, MdFree> ctx(EVP_MD_CTX_new());
  if (EVP_PKEY_id(pub) == EVP_PKEY_ED25519) {
    if (!is_eddsa(alg)) return false;
    if (EVP_DigestVerifyInit(ctx.get(), nullptr, nullptr, nullptr, pub) != 1) return false;
    return EVP_DigestVerify(ctx.get(), sig, sig_len, reinterpret_cast<const unsigned char*>(data.data()), data.size()) ==
           1;
  }
  const EVP_MD* md = md_for(alg);
  if (md == nullptr) return false;
  EVP_PKEY_CTX* pctx = nullptr;
  if (EVP_DigestVerifyInit(ctx.get(), &pctx, md, nullptr, pub) != 1) return false;
  const unsigned char* verify_sig = sig;
  size_t verify_len = sig_len;
  std::vector<unsigned char> der;
  if (EVP_PKEY_id(pub) == EVP_PKEY_EC) {
    der = raw_to_ecdsa_der(sig, sig_len);
    if (der.empty()) return false;
    verify_sig = der.data();
    verify_len = der.size();
  } else if (alg.rfind("PS", 0) == 0) {
    EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING);
    EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, RSA_PSS_SALTLEN_DIGEST);
  }
  return EVP_DigestVerify(ctx.get(), verify_sig, verify_len, reinterpret_cast<const unsigned char*>(data.data()),
                          data.size()) == 1;
}

std::map<std::string, std::string> sign_http(const ClientKey& key, const std::string& method, const std::string& url,
                                             const std::map<std::string, std::string>& headers, const std::string* body) {
  std::string href = url;
  try {
    href = href_string(url);
  } catch (const Error&) {
  }
  std::map<std::string, std::string> lower;
  for (const auto& item : headers) lower[lower_header(item.first)] = item.second;
  std::vector<std::string> components{"@method", "@target-uri"};
  std::map<std::string, std::string> added;
  if (body != nullptr && !body->empty()) {
    added["content-digest"] = content_digest(*body);
    lower["content-digest"] = added["content-digest"];
    components.push_back("content-digest");
  }
  if (lower.count("authorization")) components.push_back("authorization");
  std::string nonce = b64url_encode(random_bytes(16));
  std::string quoted;
  for (size_t i = 0; i < components.size(); i++) {
    if (i) quoted.push_back(' ');
    quoted += "\"" + components[i] + "\"";
  }
  long created = static_cast<long>(std::time(nullptr));
  std::string params = "(" + quoted + ");created=" + std::to_string(created) + ";nonce=" + sf_string(nonce) +
                       ";keyid=" + sf_string(key.kid) + ";tag=\"gnap\"";
  std::string base;
  for (const auto& component : components) {
    std::string value;
    if (component == "@method") {
      value = method;
      for (char& c : value)
        if (c >= 'a' && c <= 'z') c = static_cast<char>(c - 'a' + 'A');
    } else if (component == "@target-uri") {
      value = href;
    } else {
      auto found = lower.find(component);
      if (found == lower.end()) throw Error("signature", "Cannot sign \"" + component + "\": the request has no such header");
      value = trim_copy(found->second);
    }
    if (value.find('\r') != std::string::npos || value.find('\n') != std::string::npos) {
      throw Error("signature", "Cannot sign \"" + component + "\": the value contains a line break");
    }
    if (!base.empty()) base.push_back('\n');
    base += "\"" + component + "\": " + value;
  }
  if (!base.empty()) base.push_back('\n');
  base += "\"@signature-params\": " + params;
  auto signature = sign_message(key, base);
  added["signature-input"] = "sig1=" + params;
  added["signature"] = "sig1=:" + b64std_encode(signature.data(), signature.size()) + ":";
  return added;
}

std::string make_detached_jws(const ClientKey& key, const std::string& method, const std::string& url,
                              const std::string* body, const std::string& token) {
  std::string href = url;
  try {
    href = href_string(url);
  } catch (const Error&) {
  }
  Json header = Json::object();
  header.set("alg", Json::str(key.alg));
  header.set("created", Json::integer(static_cast<long long>(std::time(nullptr))));
  std::string htm = method;
  for (char& c : htm)
    if (c >= 'a' && c <= 'z') c = static_cast<char>(c - 'a' + 'A');
  header.set("htm", Json::str(htm));
  header.set("kid", Json::str(key.kid));
  header.set("typ", Json::str("gnap-binding-jwsd"));
  header.set("uri", Json::str(href));
  if (!token.empty()) header.set("ath", Json::str(b64url_encode(sha256_bytes(token))));
  std::string encoded = b64url_encode(header.dump());
  std::string payload;
  if (body != nullptr && !body->empty()) payload = b64url_encode(sha256_bytes(*body));
  auto signature = sign_message(key, encoded + "." + payload);
  return encoded + "." + payload + "." + b64url_encode(signature.data(), signature.size());
}

JwsParts verify_jws_with_keys(const std::string& token, const std::vector<Json>& keys) {
  std::vector<std::string> parts;
  size_t start = 0;
  for (size_t i = 0; i <= token.size(); i++) {
    if (i == token.size() || token[i] == '.') {
      parts.push_back(token.substr(start, i - start));
      start = i + 1;
    }
  }
  if (parts.size() != 3 || parts[0].empty() || parts[1].empty() || parts[2].empty()) {
    throw Error("signature", "the token is not a compact JWS");
  }
  auto header_raw = b64url_strict(parts[0], "header");
  auto payload_raw = b64url_strict(parts[1], "payload");
  Json header;
  Json payload;
  try {
    header = Json::parse(std::string(reinterpret_cast<const char*>(header_raw.data()), header_raw.size()));
  } catch (const Error&) {
    throw Error("signature", "the token's header or payload is not JSON");
  }
  if (header.type != Type::Object) throw Error("signature", "the token's header is not a JSON object");
  try {
    payload = Json::parse(std::string(reinterpret_cast<const char*>(payload_raw.data()), payload_raw.size()));
  } catch (const Error&) {
    throw Error("signature", "the token's header or payload is not JSON");
  }
  if (payload.type != Type::Object) throw Error("signature", "the token's payload is not a JSON object");
  std::string alg = jstr_key(header, "alg");
  std::string kty = kty_for_alg(alg);
  if (kty.empty()) {
    std::string shown = alg.empty() ? "(no alg)" : alg;
    throw Error("signature", "the token is signed with " + shown + ", which this client does not verify (" +
                                 supported_jws() + ")");
  }
  if (header.has("crit")) throw Error("signature", "the token's header has a crit member this client does not understand");
  std::string kid;
  if (const Json* kid_value = header.get("kid"); kid_value != nullptr && kid_value->type == Type::String) kid = kid_value->text;
  std::vector<const Json*> candidates;
  for (const auto& key : keys) {
    if (!kid.empty() && jstr_key(key, "kid") != kid) continue;
    if (jstr_key(key, "kty") != kty) continue;
    std::string use = jstr_key(key, "use");
    if (!use.empty() && use != "sig") continue;
    std::string key_alg = jstr_key(key, "alg");
    if (!key_alg.empty() && key_alg != alg) continue;
    candidates.push_back(&key);
  }
  if (candidates.empty()) {
    std::string suffix = kid.empty() ? "" : " with kid " + kid;
    throw Error("signature", "no " + kty + " signing key" + suffix + " was published");
  }
  auto signature = b64url_strict(parts[2], "signature");
  std::string data = parts[0] + "." + parts[1];
  for (const Json* jwk : candidates) {
    try {
      PkeyPtr pub = pkey_from_jwk(*jwk);
      if (verify_message(pub.get(), alg, data, signature.data(), signature.size())) {
        return JwsParts{header, payload};
      }
    } catch (const Error&) {
    }
  }
  throw Error("signature", "the token's signature does not verify against the published keys");
}

std::string fingerprint_cert_pem(const std::string& pem) {
  CertPtr cert = read_cert(pem);
  auto der = cert_der(cert.get());
  auto sum = sha256_bytes(der);
  return hex_colon(sum.data(), sum.size());
}

std::string interaction_hash(const std::string& client_nonce, const std::string& server_nonce,
                             const std::string& interact_ref, const std::string& grant_endpoint) {
  return b64url_encode(sha256_bytes(client_nonce + "\n" + server_nonce + "\n" + interact_ref + "\n" + grant_endpoint));
}

std::string content_digest(const std::string& body) {
  auto sum = sha256_bytes(body);
  return "sha-256=:" + b64std_encode(sum.data(), sum.size()) + ":";
}

KeyMaterial create_self_signed(const std::string& common_name, const std::vector<std::string>& dns_names,
                               const std::vector<std::string>& ip_addresses) {
  EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
  if (ctx == nullptr || EVP_PKEY_keygen_init(ctx) != 1 ||
      EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, NID_X9_62_prime256v1) != 1) {
    EVP_PKEY_CTX_free(ctx);
    throw Error("config", "the key could not be generated");
  }
  EVP_PKEY* raw_key = nullptr;
  if (EVP_PKEY_keygen(ctx, &raw_key) != 1) {
    EVP_PKEY_CTX_free(ctx);
    throw Error("config", "the key could not be generated");
  }
  EVP_PKEY_CTX_free(ctx);
  PkeyPtr key(raw_key);
  CertPtr cert(X509_new());
  if (!cert) throw Error("config", "the certificate could not be generated");
  X509_set_version(cert.get(), 2);
  BIGNUM* serial_bn = BN_new();
  if (BN_rand(serial_bn, 128, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY) != 1) {
    BN_free(serial_bn);
    throw Error("config", "the certificate could not be generated");
  }
  ASN1_INTEGER* serial = BN_to_ASN1_INTEGER(serial_bn, nullptr);
  BN_free(serial_bn);
  X509_set_serialNumber(cert.get(), serial);
  ASN1_INTEGER_free(serial);
  X509_gmtime_adj(X509_getm_notBefore(cert.get()), -60);
  X509_gmtime_adj(X509_getm_notAfter(cert.get()), 1095LL * 24 * 60 * 60);
  X509_set_pubkey(cert.get(), key.get());
  X509_NAME* name = X509_get_subject_name(cert.get());
  X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, reinterpret_cast<const unsigned char*>(common_name.c_str()), -1,
                             -1, 0);
  X509_set_issuer_name(cert.get(), name);
  X509V3_CTX v3;
  X509V3_set_ctx_nodb(&v3);
  X509V3_set_ctx(&v3, cert.get(), cert.get(), nullptr, nullptr, 0);
  X509_EXTENSION* usage = X509V3_EXT_conf_nid(nullptr, &v3, NID_key_usage, "digitalSignature");
  if (usage != nullptr) {
    X509_add_ext(cert.get(), usage, -1);
    X509_EXTENSION_free(usage);
  }
  X509_EXTENSION* basic = X509V3_EXT_conf_nid(nullptr, &v3, NID_basic_constraints, "CA:FALSE");
  if (basic != nullptr) {
    X509_add_ext(cert.get(), basic, -1);
    X509_EXTENSION_free(basic);
  }
  std::string san;
  for (const auto& dns : dns_names) {
    if (!san.empty()) san.push_back(',');
    san += "DNS:" + dns;
  }
  for (const auto& ip : ip_addresses) {
    if (!san.empty()) san.push_back(',');
    san += "IP:" + ip;
  }
  if (!san.empty()) {
    X509_EXTENSION* alt = X509V3_EXT_conf_nid(nullptr, &v3, NID_subject_alt_name, san.c_str());
    if (alt != nullptr) {
      X509_add_ext(cert.get(), alt, -1);
      X509_EXTENSION_free(alt);
    }
  }
  if (X509_sign(cert.get(), key.get(), EVP_sha256()) == 0) throw Error("config", "the certificate could not be generated");
  KeyMaterial material;
  material.private_key_pem = pkcs8_pem(key.get());
  material.certificate_pem = cert_pem_of(cert.get());
  auto der = cert_der(cert.get());
  auto sum = sha256_bytes(der);
  material.fingerprint = hex_colon(sum.data(), sum.size());
  return material;
}

std::string mtls_published_cert(const std::string& private_pem, const std::string& certificate_pem) {
  auto key = load_client_key(private_pem, certificate_pem, "mtls");
  return trim_copy(key->cert_pem);
}

std::string mtls_tls_chain(const std::string& private_pem, const std::string& certificate_pem) {
  auto key = load_client_key(private_pem, certificate_pem, "mtls");
  return key->chain_pem;
}

std::string certificate_fingerprint(const std::string& certificate_pem) { return fingerprint_cert_pem(certificate_pem); }

VerifiedJws verify_compact_jws(const std::string& token, const std::string& jwks_json) {
  Json doc = Json::parse(jwks_json);
  std::vector<Json> keys;
  if (doc.type == Type::Array) {
    keys = doc.arr;
  } else if (doc.type == Type::Object && doc.get("keys") != nullptr && doc.get("keys")->type == Type::Array) {
    keys = doc.get("keys")->arr;
  } else {
    throw Error("signature", "the JWKS is not a JSON object");
  }
  auto parts = verify_jws_with_keys(token, keys);
  return VerifiedJws{parts.header.dump(), parts.payload.dump()};
}

}  // namespace iya::gnap
