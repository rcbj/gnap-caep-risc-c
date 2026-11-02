// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

#include "full.hpp"

#include "url.hpp"
#include "util.hpp"

#include <cstdlib>
#include <vector>

namespace iya::gnap {
namespace {

const char* kProofs[] = {"mtls", "httpsig", "jwsd"};

std::string proofs_joined() { return "mtls, httpsig, jwsd"; }

bool exact_bool(const Json* value, bool& out) {
  if (value == nullptr || value->type != Type::Bool) return false;
  out = value->b;
  return true;
}

bool truthy(const Json* value) {
  if (value == nullptr || value->type == Type::Null) return false;
  if (value->type == Type::Bool) return value->b;
  if (value->type == Type::String) return !value->text.empty();
  if (value->type == Type::Number) return value->as_float() != 0;
  return true;
}

double number_or(const Json& doc, const std::string& key, double fallback) {
  const Json* value = doc.get(key);
  if (value == nullptr || value->type == Type::Null || value->type != Type::Number) return fallback;
  return value->as_float();
}

std::vector<std::string> string_list_or(const Json* value, const std::vector<std::string>& fallback) {
  if (value == nullptr || value->type == Type::Null || value->type != Type::Array) return fallback;
  std::vector<std::string> out;
  for (const auto& item : value->arr) out.push_back(jstr(&item));
  return out;
}

std::string read_path(const std::string& path, const std::string& base, const std::string& what) {
  std::string full = join_path(base, path);
  std::string text;
  std::string error;
  if (!read_text_file_ok(full, text, error)) throw Error("config", "could not read " + what + " at " + full + ": " + error);
  return text;
}

std::string secret_value(const std::string& raw, const std::string& base, const std::string& what) {
  if (raw.rfind("env:", 0) == 0) {
    std::string name = raw.substr(4);
    const char* env = std::getenv(name.c_str());
    if (env == nullptr || env[0] == '\0') throw Error("config", what + " reads " + name + ", and that variable is empty");
    return env;
  }
  if (raw.rfind("file:", 0) == 0) return read_path(raw.substr(5), base, what);
  return raw;
}

std::string key_value(const std::string& raw, const std::string& base, const std::string& what) {
  if (raw.rfind("env:", 0) == 0 || raw.rfind("file:", 0) == 0 || raw.find("-----BEGIN") != std::string::npos) {
    return secret_value(raw, base, what);
  }
  return read_path(raw, base, what);
}

std::string read_trust(const std::string& raw, const std::string& base) {
  if (raw.empty()) return "";
  if (raw.find("-----BEGIN") != std::string::npos) return raw;
  std::string path = raw;
  if (raw.rfind("env:", 0) == 0) {
    const char* env = std::getenv(raw.substr(4).c_str());
    return env == nullptr ? "" : env;
  }
  if (raw.rfind("file:", 0) == 0) path = raw.substr(5);
  if (path.empty()) return "";
  std::string text;
  std::string error;
  if (!read_text_file_ok(join_path(base, path), text, error)) return "";
  return text;
}

bool ssf_right(const Json& right) {
  if (right.type == Type::String) {
    std::string trimmed = trim_copy(right.text);
    return trimmed == "ssf.read" || trimmed == "ssf.manage";
  }
  if (right.type == Type::Object) {
    std::string kind = jstr_key(right, "type");
    return kind == "ssf.read" || kind == "ssf.manage";
  }
  return false;
}

std::string check_url(const std::string& value, const std::string& name, bool allow_http) {
  std::string href;
  try {
    href = href_string(value);
  } catch (const Error&) {
    throw Error("config", name + " is not a URL: " + value);
  }
  auto colon = href.find(':');
  std::string scheme = colon == std::string::npos ? "" : href.substr(0, colon);
  if (scheme == "https" || (scheme == "http" && allow_http)) return href;
  std::string extra = allow_http ? "" : ", or http on loopback";
  throw Error("config", name + " must use https" + extra + ": " + value);
}

std::string parent_dir(const std::string& path) {
  auto slash = path.find_last_of('/');
  if (slash == std::string::npos) return ".";
  if (slash == 0) return "/";
  return path.substr(0, slash);
}

}  // namespace

Config config_view(const FullConfig& full) {
  Config view;
  view.grant_endpoint = full.grant_endpoint;
  view.id_token_issuer = full.id_token_issuer;
  view.application = full.application;
  view.access_json = full.access.dump();
  view.signals = full.signals;
  view.has_ssf = full.has_ssf;
  view.ssf_transmitter = full.ssf_transmitter;
  view.poll_interval_ms = full.poll_interval_ms;
  view.finish_uri = full.finish_uri;
  view.finish_method = full.finish_method;
  view.key_proof = full.key ? full.key->proof : "";
  return view;
}

FullConfig resolve_full(const std::string& text, const std::string& base_dir) {
  Json raw;
  try {
    raw = Json::parse(text);
  } catch (const Error& err) {
    throw Error("config", std::string(err.what()));
  }
  if (raw.type != Type::Object) throw Error("config", "the configuration must be a JSON object");
  if (raw.has("signals")) {
    bool ignored = false;
    if (!exact_bool(raw.get("signals"), ignored)) throw Error("config", "signals must be true or false");
  }
  bool signals_off = false;
  bool signals_value = false;
  if (exact_bool(raw.get("signals"), signals_value) && !signals_value) signals_off = true;
  std::string application = trim_copy(jstr_key(raw, "application"));
  if (application.empty()) throw Error("config", "application is required: the registered GNAP client");
  std::string grant_raw = trim_copy(jstr_key(raw, "grantEndpoint"));
  if (grant_raw.empty()) throw Error("config", "grantEndpoint is required");
  bool allow_insecure = false;
  const Json* insecure = raw.get("allowInsecure");
  allow_insecure = insecure != nullptr && insecure->type == Type::Bool && insecure->b;
  std::string grant_endpoint = check_url(grant_raw, "grantEndpoint", allow_insecure);
  std::string origin = origin_string(grant_endpoint);
  std::string id_token_issuer = trim_right_slash(trim_copy(jstr_key(raw, "idTokenIssuer")));
  if (id_token_issuer.empty()) id_token_issuer = trim_right_slash(origin);
  if (id_token_issuer.rfind("https://", 0) != 0 && id_token_issuer.rfind("http://", 0) != 0) {
    throw Error("config", "idTokenIssuer must be an http(s) URL");
  }
  std::string proof_raw = trim_copy(jstr_key(raw, "keyProof"));
  if (!proof_raw.empty()) {
    bool known = false;
    for (const char* proof : kProofs)
      if (proof_raw == proof) known = true;
    if (!known) throw Error("config", "keyProof must be " + proofs_joined() + ", not " + proof_raw);
  }
  if (jstr_key(raw, "privateKey").empty()) throw Error("config", "privateKey is required");
  std::string private_key = key_value(jstr_key(raw, "privateKey"), base_dir, "the private key");
  std::string certificate;
  if (!jstr_key(raw, "certificate").empty()) {
    certificate = key_value(jstr_key(raw, "certificate"), base_dir, "the certificate");
  }
  auto key = load_client_key(private_key, certificate, proof_raw);
  if (key->proof == "mtls") {
    Url parsed;
    if (!parse_absolute(grant_endpoint, parsed) || parsed.scheme != "https") {
      throw Error("config", "mutual TLS needs an https grant endpoint");
    }
  }
  std::string finish_method = jstr_key(raw, "finishMethod");
  if (finish_method.empty()) finish_method = "redirect";
  if (finish_method != "redirect" && finish_method != "push") {
    throw Error("config", "finishMethod must be redirect or push");
  }
  std::string finish_raw = trim_copy(jstr_key(raw, "finishUri"));
  std::string finish_uri;
  if (!finish_raw.empty()) finish_uri = check_url(finish_raw, "finishUri", allow_insecure || is_loopback(finish_raw));
  std::string hash_method = jstr_key(raw, "hashMethod");
  if (hash_method.empty()) hash_method = "sha-256";
  if (hash_method != "sha-256") throw Error("config", "hashMethod must be sha-256");
  std::vector<std::string> interaction;
  if (!raw.has("interactionStart") || raw.get("interactionStart")->type == Type::Null) {
    interaction.push_back("redirect");
  } else if (raw.get("interactionStart")->type != Type::Array || raw.get("interactionStart")->arr.empty()) {
    throw Error("config", "interactionStart must name at least one mode");
  } else {
    for (const auto& item : raw.get("interactionStart")->arr) {
      std::string text_item = jstr(&item);
      if (text_item.empty()) throw Error("config", "interactionStart must name at least one mode");
      interaction.push_back(text_item);
    }
  }
  Json requested = Json::array();
  if (!raw.has("access") || raw.get("access")->type == Type::Null) {
    requested.push(Json::str("ssf.read"));
    requested.push(Json::str("ssf.manage"));
  } else if (raw.get("access")->type != Type::Array) {
    throw Error("config", "access must list at least one right");
  } else {
    requested = *raw.get("access");
  }
  Json access = Json::array();
  if (signals_off) {
    for (const auto& right : requested.arr)
      if (!ssf_right(right)) access.push(right);
  } else {
    access = requested;
  }
  if (access.arr.empty()) {
    if (signals_off) {
      throw Error("config",
                  "signals is false and access has no rights left after ssf.read and ssf.manage were removed; the caller "
                  "must name a right this authorization server grants");
    }
    throw Error("config", "access must list at least one right");
  }
  std::string tls_ca;
  if (raw.has("tlsCa") && raw.get("tlsCa")->type != Type::Null) tls_ca = read_trust(jstr_key(raw, "tlsCa"), base_dir);
  FullConfig cfg;
  cfg.grant_endpoint = grant_endpoint;
  cfg.id_token_issuer = id_token_issuer;
  cfg.application = application;
  cfg.access = access;
  cfg.sub_id_formats = string_list_or(raw.get("subIdFormats"), {"iss_sub", "account", "opaque"});
  cfg.assertion_formats = string_list_or(raw.get("assertionFormats"), {"id_token"});
  cfg.key = key;
  cfg.finish_uri = finish_uri;
  cfg.finish_method = finish_method;
  cfg.interaction_start = interaction;
  const Json* bound = raw.get("requireBoundTokens");
  cfg.require_bound = !(bound != nullptr && bound->type == Type::Bool && !bound->b);
  const Json* instance = raw.get("useInstanceId");
  cfg.use_instance_id = !(instance != nullptr && instance->type == Type::Bool && !instance->b);
  cfg.tls_ca = tls_ca;
  cfg.allow_insecure = allow_insecure;
  cfg.clock_tolerance_sec = number_or(raw, "clockToleranceSec", 30);
  cfg.max_wait_sec = number_or(raw, "maxWaitSec", 30);
  cfg.transaction_ttl_sec = number_or(raw, "transactionTtlSec", 600);
  if (!signals_off) {
    const Json* raw_ssf = raw.get("ssf");
    std::string transmitter;
    if (raw_ssf != nullptr && raw_ssf->type == Type::Object) transmitter = jstr_key(*raw_ssf, "transmitter");
    if (transmitter.empty()) transmitter = jstr_key(raw, "transmitterIssuer");
    transmitter = trim_right_slash(transmitter);
    if (!transmitter.empty()) {
      if (transmitter.rfind("https://", 0) != 0 && transmitter.rfind("http://", 0) != 0) {
        throw Error("config", "ssf.transmitter must be an http(s) URL");
      }
      cfg.has_ssf = true;
      cfg.ssf_transmitter = transmitter;
      if (raw_ssf != nullptr && raw_ssf->type == Type::Object && truthy(raw_ssf->get("pollIntervalMs")) &&
          is_number(raw_ssf->get("pollIntervalMs"))) {
        cfg.poll_interval_ms = static_cast<int>(raw_ssf->get("pollIntervalMs")->as_float());
      }
    }
  }
  if (const Json* display = raw.get("display"); display != nullptr && display->type == Type::Object) {
    cfg.display_name = jstr_key(*display, "name");
    cfg.display_uri = jstr_key(*display, "uri");
    cfg.has_display = !cfg.display_name.empty() || !cfg.display_uri.empty();
  }
  std::string class_id = jstr_key(raw, "classId");
  if (!class_id.empty()) cfg.class_id = class_id;
  if (signals_off) cfg.signals = 0;
  return cfg;
}

Config Config::resolve_json(const std::string& json, const std::string& base_dir) {
  return config_view(resolve_full(json, base_dir));
}

Config Config::from_file(const std::string& path) {
  std::string text;
  std::string error;
  if (!read_text_file_ok(path, text, error)) throw Error("config", "could not read " + path + ": " + error);
  std::string base = ".";
  char* absolute = realpath(path.c_str(), nullptr);
  if (absolute != nullptr) {
    base = parent_dir(absolute);
    free(absolute);
  }
  try {
    return config_view(resolve_full(text, base));
  } catch (const Error& err) {
    if (std::string(err.what()).find("JSON") != std::string::npos) {
      throw Error("config", "could not read " + path + ": " + err.what());
    }
    throw;
  }
}

}  // namespace iya::gnap
