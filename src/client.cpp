// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

#include "full.hpp"
#include "http.hpp"
#include "subject.hpp"
#include "url.hpp"
#include "util.hpp"

#include "codec.hpp"

#include <cmath>
#include <cstdlib>
#include <mutex>
#include <thread>

namespace iya::gnap {
namespace {

const char* kFront[] = {"access_token", "id_token", "token", "value", "continue", "refresh_token"};

struct Cont {
  std::string uri;
  std::string token;
  bool has_wait = false;
  double wait = 0;
};

struct Pending {
  std::string id;
  std::string client_nonce;
  std::string server_nonce;
  Cont continuation;
  double created_at = 0;
  std::string expected_sub;
};

struct GrantServer {
  std::vector<std::string> interaction_finish;
  std::vector<std::string> key_proofs;
  std::vector<std::string> sub_id_formats;
  std::vector<std::string> assertion_formats;
};

std::vector<std::string> string_list(const Json* value) {
  if (value == nullptr || value->type == Type::Null) return {};
  if (value->type != Type::Array) throw Error("discovery", "a grant-server metadata list is not an array of strings");
  std::vector<std::string> out;
  for (const auto& item : value->arr) {
    if (item.type != Type::String) throw Error("discovery", "a grant-server metadata list is not an array of strings");
    out.push_back(item.text);
  }
  return out;
}

std::vector<std::string> filter_listed(const std::vector<std::string>& have, const std::vector<std::string>& allowed) {
  std::vector<std::string> out;
  for (const auto& item : have)
    if (contains_string(allowed, item)) out.push_back(item);
  return out;
}

Json string_array(const std::vector<std::string>& values) {
  Json out = Json::array();
  for (const auto& item : values) out.push(Json::str(item));
  return out;
}

std::string upper_copy(std::string value) {
  for (char& c : value)
    if (c >= 'a' && c <= 'z') c = static_cast<char>(c - 'a' + 'A');
  return value;
}

bool has_token(const Json& answer) {
  if (answer.type != Type::Object) return false;
  const Json* value = answer.get("access_token");
  if (value == nullptr || value->type == Type::Null) return false;
  if (value->type == Type::Array) return !value->arr.empty();
  if (value->type == Type::String) return !value->text.empty();
  return true;
}

std::string grant_id_of(const std::string& uri) {
  if (uri.empty()) return "";
  Url url;
  if (!parse_absolute(uri, url)) return "";
  std::string path = url.path;
  while (!path.empty() && path.front() == '/') path.erase(path.begin());
  while (!path.empty() && path.back() == '/') path.pop_back();
  if (path.empty()) return "";
  auto slash = path.find_last_of('/');
  std::string last = slash == std::string::npos ? path : path.substr(slash + 1);
  bool ok = true;
  std::string decoded = path_unescape(last, ok);
  return ok ? decoded : last;
}

std::string first_of(const std::map<std::string, std::vector<std::string>>& names, const std::string& key) {
  auto found = names.find(key);
  if (found == names.end() || found->second.empty()) return "";
  return found->second.front();
}

}  // namespace

struct Client::Impl {
  FullConfig config;
  std::mutex mu;
  bool has_metadata = false;
  GrantServer metadata;
  std::string instance_id;
  std::vector<std::string> sub_ids;
  std::vector<std::string> assertions;
  bool has_jwks = false;
  std::vector<Json> jwks;
  std::vector<Pending> pending;
  std::vector<std::string> used;
};

Client::Client(std::unique_ptr<Impl> impl) : impl_(std::move(impl)) {}
Client::~Client() = default;
Client::Client(Client&&) noexcept = default;
Client& Client::operator=(Client&&) noexcept = default;

TlsOpt tls_of(const FullConfig& config) {
  TlsOpt opt;
  opt.ca = config.tls_ca;
  opt.insecure = config.allow_insecure;
  if (config.key && config.key->proof == "mtls" && (!config.key->chain_pem.empty() || !config.key->cert_pem.empty())) {
    opt.cert = config.key->chain_pem.empty() ? config.key->cert_pem : config.key->chain_pem;
    opt.key = config.key->private_pem;
  }
  return opt;
}

void check_same_origin(const FullConfig& config, const std::string& uri, const std::string& what) {
  Url parts;
  if (!parse_absolute(uri, parts)) throw Error("validation", what + " is not a URL: " + uri);
  if (parts.scheme != "https" && !config.allow_insecure) throw Error("validation", what + " must use https: " + uri);
  std::string got = origin_string(uri);
  std::string want = origin_string(config.grant_endpoint);
  if (got != want) throw Error("validation", what + " " + uri + " is not on the grant endpoint's origin");
}

Cont continuation_of(const FullConfig& config, const Json& raw, const std::string& what) {
  if (raw.type != Type::Object) throw Error("protocol", "the response has no " + what + " object");
  std::string token;
  if (const Json* access = raw.get("access_token"); access != nullptr && access->type == Type::Object) {
    token = jstr_key(*access, "value");
  }
  std::string uri = jstr_key(raw, "uri");
  if (uri.empty() || token.empty()) throw Error("protocol", "the response has no usable " + what + " object");
  check_same_origin(config, uri, what + ".uri");
  Cont cont;
  cont.uri = uri;
  cont.token = token;
  if (raw.has("wait") && raw.get("wait")->type != Type::Null) {
    if (!is_number(raw.get("wait")) || raw.get("wait")->as_float() < 0) {
      throw Error("protocol", what + ".wait is not a number of seconds");
    }
    cont.has_wait = true;
    cont.wait = raw.get("wait")->as_float();
  }
  return cont;
}

Json read_answer(const Answer& answer) {
  if (answer.status == 204 || answer.body.empty()) {
    if (answer.status >= 400) throw Error("protocol", "the authorization server answered " + std::to_string(answer.status));
    return Json::nul();
  }
  Json parsed;
  try {
    parsed = Json::parse(answer.body);
  } catch (const Error&) {
    throw Error("protocol", "the authorization server answered " + std::to_string(answer.status) + " with a body that is not JSON");
  }
  if (answer.status >= 200 && answer.status < 300) return parsed;
  std::string gnap;
  if (parsed.type == Type::Object && parsed.get("error") != nullptr && parsed.get("error")->type == Type::String) {
    gnap = parsed.get("error")->text;
  }
  Error err("protocol", "", gnap);
  if (parsed.type == Type::Object) {
    if (const Json* raw = parsed.get("continue"); raw != nullptr && raw->type == Type::Object) {
      std::string token;
      if (const Json* access = raw->get("access_token"); access != nullptr && access->type == Type::Object) {
        token = jstr_key(*access, "value");
      }
      std::string uri = jstr_key(*raw, "uri");
      if (!uri.empty() && !token.empty()) {
        err.has_continue = true;
        err.continue_uri = uri;
        err.continue_token = token;
        if (is_number(raw->get("wait"))) {
          err.has_wait = true;
          err.wait_sec = raw->get("wait")->as_float();
        }
      }
    }
    if (parsed.get("error_description") != nullptr && parsed.get("error_description")->type == Type::String) {
      err = Error("protocol", parsed.get("error_description")->text, gnap);
      if (parsed.get("continue") != nullptr && parsed.get("continue")->type == Type::Object) {
        const Json* raw = parsed.get("continue");
        std::string token;
        if (const Json* access = raw->get("access_token"); access != nullptr && access->type == Type::Object) {
          token = jstr_key(*access, "value");
        }
        std::string uri = jstr_key(*raw, "uri");
        if (!uri.empty() && !token.empty()) {
          err.has_continue = true;
          err.continue_uri = uri;
          err.continue_token = token;
          if (is_number(raw->get("wait"))) {
            err.has_wait = true;
            err.wait_sec = raw->get("wait")->as_float();
          }
        }
      }
    }
  }
  if (std::string(err.what()).empty()) {
    if (!gnap.empty()) err = Error("protocol", gnap, gnap);
    else err = Error("protocol", "the authorization server answered " + std::to_string(answer.status), gnap);
    if (parsed.type == Type::Object && parsed.get("continue") != nullptr && parsed.get("continue")->type == Type::Object) {
      const Json* raw = parsed.get("continue");
      std::string token;
      if (const Json* access = raw->get("access_token"); access != nullptr && access->type == Type::Object) {
        token = jstr_key(*access, "value");
      }
      std::string uri = jstr_key(*raw, "uri");
      if (!uri.empty() && !token.empty()) {
        err.has_continue = true;
        err.continue_uri = uri;
        err.continue_token = token;
        if (is_number(raw->get("wait"))) {
          err.has_wait = true;
          err.wait_sec = raw->get("wait")->as_float();
        }
      }
    }
  }
  throw err;
}

std::map<std::string, std::string> proof_headers_of(const FullConfig& config, const std::string& method, const std::string& url,
                                                    const std::string* body, const std::string& token,
                                                    const std::map<std::string, std::string>& extra) {
  std::map<std::string, std::string> headers = extra;
  if (!token.empty()) headers["authorization"] = "GNAP " + token;
  if (config.key->proof == "httpsig") {
    auto signed_headers = sign_http(*config.key, method, url, headers, body);
    for (const auto& item : signed_headers) headers[item.first] = item.second;
  } else if (config.key->proof == "jwsd") {
    headers["detached-jws"] = make_detached_jws(*config.key, method, url, body, token);
  }
  return headers;
}

Json signed_json(const FullConfig& config, const std::string& method, const std::string& url, const Json* body,
                 const std::string& token) {
  check_same_origin(config, url, "the request URL");
  std::string dumped;
  const std::string* text = nullptr;
  if (body != nullptr) {
    dumped = body->dump();
    text = &dumped;
  }
  std::map<std::string, std::string> extra;
  if (text != nullptr) extra["content-type"] = "application/json";
  auto headers = proof_headers_of(config, method, url, text, token, extra);
  headers["accept"] = "application/json";
  Answer answer = http_send(url, method, headers, text, tls_of(config), "protocol");
  return read_answer(answer);
}

Json continue_grant(const FullConfig& config, Cont current, const Json& body) {
  double waited = 0;
  int immediate = 0;
  while (true) {
    try {
      return signed_json(config, "POST", current.uri, &body, current.token);
    } catch (const Error& err) {
      if (err.gnap != "too_fast") throw;
      if (err.has_continue) {
        check_same_origin(config, err.continue_uri, "continue.uri");
        current.uri = err.continue_uri;
        current.token = err.continue_token;
        current.has_wait = err.has_wait;
        current.wait = err.wait_sec;
      }
      double wait = 0;
      if (current.has_wait && current.wait > 0) wait = current.wait;
      if (wait == 0) {
        immediate++;
        if (immediate > 2) throw;
        continue;
      }
      if (waited + wait > config.max_wait_sec) throw;
      std::this_thread::sleep_for(std::chrono::milliseconds(static_cast<int>(wait * 1000)));
      waited += wait;
    }
  }
}

std::vector<Json> id_token_keys(Client::Impl& impl) {
  {
    std::lock_guard<std::mutex> lock(impl.mu);
    if (impl.has_jwks) return impl.jwks;
  }
  TlsOpt tls = tls_of(impl.config);
  auto urls = well_known(impl.config.id_token_issuer, "openid-configuration");
  std::string jwks_uri;
  Error last("discovery", "no OpenID Provider metadata at " + (urls.empty() ? "" : urls[0]));
  for (size_t i = 0; i < urls.size(); i++) {
    Answer answer = http_send(urls[i], "GET", {{"accept", "application/json"}}, nullptr, tls, "discovery");
    if (answer.status == 404 && i + 1 != urls.size()) continue;
    Json parsed;
    bool bad = false;
    try {
      parsed = Json::parse(answer.body);
    } catch (const Error&) {
      bad = true;
    }
    if (bad || answer.status != 200 || parsed.type != Type::Object || jstr_key(parsed, "jwks_uri").empty()) {
      last = Error("discovery", urls[i] + " answered " + std::to_string(answer.status) + " without OpenID Provider metadata");
      continue;
    }
    std::string got = jstr_key(parsed, "issuer");
    if (!got.empty() && trim_right_slash(got) != trim_right_slash(impl.config.id_token_issuer)) {
      throw Error("discovery", urls[i] + " says its issuer is " + got + ", not " + impl.config.id_token_issuer);
    }
    jwks_uri = jstr_key(parsed, "jwks_uri");
    break;
  }
  if (jwks_uri.empty()) throw last;
  Answer answer = http_send(jwks_uri, "GET", {{"accept", "application/json"}}, nullptr, tls, "discovery");
  Json parsed;
  try {
    parsed = Json::parse(answer.body);
  } catch (const Error&) {
    throw Error("discovery", "the issuer JWKS is not JSON");
  }
  if (answer.status != 200 || parsed.type != Type::Object || parsed.get("keys") == nullptr ||
      parsed.get("keys")->type != Type::Array) {
    throw Error("discovery", "the issuer JWKS answered " + std::to_string(answer.status));
  }
  std::vector<Json> out;
  for (const auto& item : parsed.get("keys")->arr) {
    if (item.type != Type::Object) throw Error("discovery", "the issuer JWKS answered " + std::to_string(answer.status));
    out.push_back(item);
  }
  std::lock_guard<std::mutex> lock(impl.mu);
  impl.jwks = out;
  impl.has_jwks = true;
  return out;
}

void remember_instance(Client::Impl& impl, const Json& answer) {
  if (!impl.config.use_instance_id || answer.type != Type::Object) return;
  const Json* id = answer.get("instance_id");
  if (id != nullptr && id->type == Type::String && !id->text.empty()) {
    std::lock_guard<std::mutex> lock(impl.mu);
    impl.instance_id = id->text;
  }
}

Grant grant_from(Client::Impl& impl, const Json& answer, const Grant* previous, const Cont* previous_continue) {
  if (answer.type != Type::Object) throw Error("protocol", "the access token is not an object");
  const Json* token = answer.get("access_token");
  if (token != nullptr && token->type == Type::Array) {
    if (token->arr.empty()) token = nullptr;
    else token = &token->arr[0];
  }
  if (token == nullptr || token->type != Type::Object) throw Error("protocol", "the access token is not an object");
  std::string value = jstr_key(*token, "value");
  if (value.empty()) throw Error("protocol", "the access token has no value");
  bool bearer = false;
  if (const Json* flags = token->get("flags"); flags != nullptr && flags->type == Type::Array) {
    for (const auto& item : flags->arr) {
      std::string text = item.type == Type::String ? item.text : item.dump();
      if (text == "bearer") bearer = true;
    }
  }
  if (bearer && impl.config.require_bound) {
    throw Error("validation", "the authorization server issued a bearer token, and this client requires a key-bound one");
  }
  remember_instance(impl, answer);
  Grant grant;
  grant.access_token = value;
  grant.bearer = bearer;
  if (const Json* raw = token->get("manage"); raw != nullptr && raw->type == Type::Object) {
    std::string manage_token;
    if (const Json* access = raw->get("access_token"); access != nullptr && access->type == Type::Object) {
      manage_token = jstr_key(*access, "value");
    }
    std::string uri = jstr_key(*raw, "uri");
    if (uri.empty() || manage_token.empty()) throw Error("protocol", "the access token manage object is not usable");
    check_same_origin(impl.config, uri, "manage.uri");
    grant.has_manage = true;
    grant.manage_uri = uri;
    grant.manage_token = manage_token;
  } else if (previous != nullptr && previous->has_manage) {
    grant.has_manage = true;
    grant.manage_uri = previous->manage_uri;
    grant.manage_token = previous->manage_token;
  }
  if (answer.get("continue") != nullptr && answer.get("continue")->type != Type::Null) {
    Cont cont = continuation_of(impl.config, *answer.get("continue"), "continue");
    grant.has_continuation = true;
    grant.continuation_uri = cont.uri;
    grant.continuation_token = cont.token;
    grant.has_wait = cont.has_wait;
    grant.wait_sec = cont.wait;
  } else if (previous_continue != nullptr) {
    grant.has_continuation = true;
    grant.continuation_uri = previous_continue->uri;
    grant.continuation_token = previous_continue->token;
    grant.has_wait = previous_continue->has_wait;
    grant.wait_sec = previous_continue->wait;
  } else if (previous != nullptr && previous->has_continuation) {
    grant.has_continuation = true;
    grant.continuation_uri = previous->continuation_uri;
    grant.continuation_token = previous->continuation_token;
    grant.has_wait = previous->has_wait;
    grant.wait_sec = previous->wait_sec;
  }
  std::string instance;
  {
    std::lock_guard<std::mutex> lock(impl.mu);
    instance = impl.instance_id;
  }
  grant.instance_id = instance;
  std::vector<std::string> audiences;
  if (!instance.empty()) audiences.push_back(instance);
  if (!impl.config.application.empty()) audiences.push_back(impl.config.application);
  if (answer.get("subject") != nullptr && answer.get("subject")->type != Type::Null) {
    grant.subject = person_from_value(*answer.get("subject"), impl.config.id_token_issuer, audiences,
                                      impl.config.clock_tolerance_sec, [&impl] { return id_token_keys(impl); });
  } else if (previous != nullptr) {
    grant.subject = previous->subject;
  }
  if (is_number(token->get("expires_in"))) {
    grant.has_expires_in = true;
    grant.expires_in = token->get("expires_in")->as_float();
    grant.has_expires_at = true;
    grant.expires_at_ms = now_ms() + grant.expires_in * 1000;
  }
  grant.grant_id = grant_id_of(grant.continuation_uri);
  return grant;
}

void expect_sub(const Grant& grant, const std::string& expected) {
  if (!expected.empty() && grant.subject.present && grant.subject.sub != expected) {
    throw Error("validation", "the grant was approved by somebody other than the account that was asked for");
  }
}

void discover(Client::Impl& impl) {
  {
    std::lock_guard<std::mutex> lock(impl.mu);
    if (impl.has_metadata) return;
  }
  TlsOpt tls = tls_of(impl.config);
  Answer answer = http_send(impl.config.grant_endpoint, "OPTIONS", {{"accept", "application/json"}}, nullptr, tls, "discovery");
  Json parsed;
  try {
    parsed = Json::parse(answer.body);
  } catch (const Error&) {
    throw Error("discovery", impl.config.grant_endpoint + " did not answer JSON grant-server metadata (" +
                                 std::to_string(answer.status) + ")");
  }
  if (answer.status != 200) {
    throw Error("discovery", impl.config.grant_endpoint + " answered " + std::to_string(answer.status) + " for discovery");
  }
  if (parsed.type != Type::Object) throw Error("discovery", "grant-server metadata must be a JSON object");
  std::string endpoint = jstr_key(parsed, "grant_request_endpoint");
  if (endpoint.empty()) throw Error("discovery", "grant-server metadata has no grant_request_endpoint");
  std::string advertised;
  try {
    advertised = href_string(endpoint);
  } catch (const Error&) {
    throw Error("discovery", "grant-server metadata has no grant_request_endpoint");
  }
  std::string asked = href_string(impl.config.grant_endpoint);
  if (trim_right_slash(advertised) != trim_right_slash(asked)) {
    throw Error("discovery", "the grant server says its endpoint is " + endpoint + ", not " + impl.config.grant_endpoint);
  }
  GrantServer meta;
  meta.interaction_finish = string_list(parsed.get("interaction_finish_methods_supported"));
  meta.key_proofs = string_list(parsed.get("key_proofs_supported"));
  meta.sub_id_formats = string_list(parsed.get("sub_id_formats_supported"));
  meta.assertion_formats = string_list(parsed.get("assertion_formats_supported"));
  if (!meta.key_proofs.empty() && !contains_string(meta.key_proofs, impl.config.key->proof)) {
    throw Error("discovery", "the grant server does not accept the " + impl.config.key->proof + " key proof");
  }
  if (!meta.interaction_finish.empty() && !impl.config.finish_uri.empty() &&
      !contains_string(meta.interaction_finish, impl.config.finish_method)) {
    throw Error("discovery", "the grant server does not accept a " + impl.config.finish_method + " interaction finish");
  }
  std::lock_guard<std::mutex> lock(impl.mu);
  if (impl.has_metadata) return;
  if (!meta.sub_id_formats.empty()) impl.sub_ids = filter_listed(impl.sub_ids, meta.sub_id_formats);
  if (!meta.assertion_formats.empty()) impl.assertions = filter_listed(impl.assertions, meta.assertion_formats);
  impl.metadata = meta;
  impl.has_metadata = true;
}

Json client_member(Client::Impl& impl) {
  std::string instance;
  {
    std::lock_guard<std::mutex> lock(impl.mu);
    instance = impl.instance_id;
  }
  if (impl.config.use_instance_id && !instance.empty()) return Json::str(instance);
  Json key = public_key_object(*impl.config.key);
  Json member = Json::object();
  member.set("key", std::move(key));
  if (impl.config.has_display) {
    Json display = Json::object();
    if (!impl.config.display_name.empty()) display.set("name", Json::str(impl.config.display_name));
    if (!impl.config.display_uri.empty()) display.set("uri", Json::str(impl.config.display_uri));
    if (!display.obj.empty()) member.set("display", std::move(display));
  }
  if (!impl.config.class_id.empty()) member.set("class_id", Json::str(impl.config.class_id));
  return member;
}

std::string redirect_of(const FullConfig& config, const Json& answer) {
  const Json* interact = answer.get("interact");
  std::string redirect = interact == nullptr ? "" : jstr_key(*interact, "redirect");
  if (redirect.empty()) throw Error("protocol", "the interaction is not a redirect");
  Url parts;
  if (!parse_absolute(redirect, parts)) throw Error("protocol", "interact.redirect is not a URL: " + redirect);
  if (parts.scheme != "https" && !(parts.scheme == "http" && (config.allow_insecure || is_loopback(redirect)))) {
    throw Error("validation", "interact.redirect must use https: " + redirect);
  }
  return redirect;
}

Pending remember_pending(Client::Impl& impl, const Json& answer, const std::string& client_nonce, const std::string& expected) {
  const Json* interact = answer.get("interact");
  const Json* finish = interact == nullptr ? nullptr : interact->get("finish");
  if (finish == nullptr || finish->type != Type::String || finish->text.empty()) {
    throw Error("protocol", "the grant response has no interaction finish nonce");
  }
  Cont cont = continuation_of(impl.config, *answer.get("continue"), "continue");
  Pending pending;
  pending.id = client_nonce;
  pending.client_nonce = client_nonce;
  pending.server_nonce = finish->text;
  pending.continuation = cont;
  pending.created_at = now_ms();
  pending.expected_sub = expected;
  std::lock_guard<std::mutex> lock(impl.mu);
  double cutoff = pending.created_at - impl.config.transaction_ttl_sec * 1000;
  std::vector<Pending> kept;
  for (const auto& item : impl.pending)
    if (item.created_at >= cutoff) kept.push_back(item);
  kept.push_back(pending);
  while (kept.size() > 1000) kept.erase(kept.begin());
  impl.pending = std::move(kept);
  return pending;
}

Pending match_pending(Client::Impl& impl, const std::string& digest, const std::string& interact_ref,
                      const std::vector<std::string>& allowed, bool use_allow) {
  std::lock_guard<std::mutex> lock(impl.mu);
  for (const auto& used : impl.used)
    if (timing_equal(used, digest)) throw Error("validation", "this interaction finish was already used");
  double now = now_ms();
  for (auto it = impl.pending.begin(); it != impl.pending.end(); ++it) {
    if (use_allow && !contains_string(allowed, it->id)) continue;
    std::string expected = interaction_hash(it->client_nonce, it->server_nonce, interact_ref, impl.config.grant_endpoint);
    if (!timing_equal(digest, expected)) continue;
    if (now - it->created_at > impl.config.transaction_ttl_sec * 1000) {
      Pending expired = *it;
      impl.pending.erase(it);
      throw Error("validation", "the approval took too long; start again");
      (void)expired;
    }
    return *it;
  }
  if (use_allow) throw Error("validation", "this finish is not a sign-in this browser started");
  throw Error("validation", "the interaction hash matches no grant in progress");
}

void consume_pending(Client::Impl& impl, const Pending& pending, const std::string& digest) {
  std::lock_guard<std::mutex> lock(impl.mu);
  std::vector<Pending> kept;
  for (const auto& item : impl.pending)
    if (item.id != pending.id) kept.push_back(item);
  impl.pending = std::move(kept);
  impl.used.push_back(digest);
  if (impl.used.size() > 1000) impl.used.erase(impl.used.begin());
}

Finished finish_pending(Client::Impl& impl, const Pending& pending, const std::string& interact_ref, const std::string& digest) {
  consume_pending(impl, pending, digest);
  double due = 0;
  if (pending.continuation.has_wait) due = pending.created_at + pending.continuation.wait * 1000 - now_ms();
  if (due > 0) {
    double cap = impl.config.max_wait_sec * 1000;
    if (due > cap) due = cap;
    std::this_thread::sleep_for(std::chrono::milliseconds(static_cast<int>(due)));
  }
  Json body = Json::object();
  body.set("interact_ref", Json::str(interact_ref));
  Json answer = continue_grant(impl.config, pending.continuation, body);
  if (!has_token(answer)) throw Error("protocol", "the resource owner did not approve the grant", "user_denied");
  Grant grant = grant_from(impl, answer, nullptr, &pending.continuation);
  expect_sub(grant, pending.expected_sub);
  Finished finished;
  finished.grant = std::move(grant);
  return finished;
}

Finished finish_names_redirect(Client::Impl& impl, const std::map<std::string, std::vector<std::string>>& names,
                               const std::vector<std::string>& allowed) {
  std::vector<std::string> injected;
  for (const char* name : kFront)
    if (names.count(name)) injected.emplace_back(name);
  if (!injected.empty()) {
    std::string joined = injected[0];
    for (size_t i = 1; i < injected.size(); i++) joined += ", " + injected[i];
    throw Error("validation", "the finish redirect carries " + joined + "; GNAP does not send tokens through the browser");
  }
  for (const auto& item : names) {
    if (item.second.size() > 1) throw Error("validation", "the finish redirect repeats \"" + item.first + "\"");
  }
  std::string digest = first_of(names, "hash");
  std::string interact_ref = first_of(names, "interact_ref");
  if (digest.empty() || interact_ref.empty()) {
    std::string code = first_of(names, "error");
    if (!code.empty()) {
      std::string msg = first_of(names, "error_description");
      if (msg.empty()) msg = code;
      throw Error("protocol", msg, code);
    }
    throw Error("validation", "the finish redirect has no hash or interact_ref");
  }
  Pending pending = match_pending(impl, digest, interact_ref, allowed, true);
  return finish_pending(impl, pending, interact_ref, digest);
}

Client Client::from_json(const std::string& json, const std::string& base_dir) {
  auto impl = std::make_unique<Impl>();
  impl->config = resolve_full(json, base_dir);
  impl->sub_ids = impl->config.sub_id_formats;
  impl->assertions = impl->config.assertion_formats;
  return Client(std::move(impl));
}

Client Client::from_file(const std::string& path) {
  std::string text;
  std::string error;
  if (!read_text_file_ok(path, text, error)) throw Error("config", "could not read " + path + ": " + error);
  std::string base = ".";
  char* absolute = realpath(path.c_str(), nullptr);
  if (absolute != nullptr) {
    std::string full(absolute);
    free(absolute);
    auto slash = full.find_last_of('/');
    base = slash == std::string::npos ? "." : full.substr(0, slash);
  }
  return from_json(text, base);
}

Config Client::config() const { return config_view(impl_->config); }

TlsOpt Client::tls() const { return tls_of(impl_->config); }

GrantResult Client::request_grant() {
  discover(*impl_);
  if (impl_->config.access.arr.empty()) throw Error("config", "access is required");
  std::string client_nonce = b64url_encode(random_bytes(24));
  Json member = client_member(*impl_);
  Json access_token = Json::object();
  access_token.set("access", impl_->config.access);
  Json body = Json::object();
  body.set("access_token", std::move(access_token));
  body.set("client", std::move(member));
  if (!impl_->config.finish_uri.empty()) {
    Json finish = Json::object();
    finish.set("method", Json::str(impl_->config.finish_method));
    finish.set("uri", Json::str(impl_->config.finish_uri));
    finish.set("nonce", Json::str(client_nonce));
    Json interact = Json::object();
    interact.set("start", string_array(impl_->config.interaction_start));
    interact.set("finish", std::move(finish));
    body.set("interact", std::move(interact));
  }
  std::vector<std::string> sub_ids;
  std::vector<std::string> assertions;
  {
    std::lock_guard<std::mutex> lock(impl_->mu);
    sub_ids = impl_->sub_ids;
    assertions = impl_->assertions;
  }
  if (!sub_ids.empty() || !assertions.empty()) {
    Json subject = Json::object();
    if (!sub_ids.empty()) subject.set("sub_id_formats", string_array(sub_ids));
    if (!assertions.empty()) subject.set("assertion_formats", string_array(assertions));
    body.set("subject", std::move(subject));
  }
  Json answer = signed_json(impl_->config, "POST", impl_->config.grant_endpoint, &body, "");
  remember_instance(*impl_, answer);
  GrantResult result;
  if (answer.type == Type::Object && answer.get("interact") != nullptr && answer.get("interact")->type != Type::Null) {
    result.redirect_url = redirect_of(impl_->config, answer);
    Pending pending = remember_pending(*impl_, answer, client_nonce, "");
    result.has_pending = true;
    result.pending_id = pending.id;
    return result;
  }
  if (has_token(answer)) {
    result.has_grant = true;
    result.grant = grant_from(*impl_, answer, nullptr, nullptr);
    expect_sub(result.grant, "");
    return result;
  }
  throw Error("protocol", "the grant response has neither an interaction nor an access token");
}

Finished Client::finish_redirect(const std::string& query, const std::vector<std::string>& allowed_ids) {
  return finish_names_redirect(*impl_, finish_names(query), allowed_ids);
}

Finished Client::finish_redirect_pairs(const std::vector<std::pair<std::string, std::string>>& pairs,
                                       const std::vector<std::string>& allowed_ids) {
  std::map<std::string, std::vector<std::string>> names;
  for (const auto& item : pairs) names[item.first].push_back(item.second);
  return finish_names_redirect(*impl_, names, allowed_ids);
}

Finished Client::finish_push_json(const std::string& json) {
  Json doc = Json::parse(json);
  if (doc.type != Type::Object) throw Error("validation", "a push finish is a JSON object");
  const Json* digest = doc.get("hash");
  const Json* interact_ref = doc.get("interact_ref");
  if (digest == nullptr || digest->type != Type::String || interact_ref == nullptr || interact_ref->type != Type::String) {
    if (doc.get("error") != nullptr && doc.get("error")->type == Type::String) {
      throw Error("protocol", doc.get("error")->text, doc.get("error")->text);
    }
    throw Error("validation", "a push finish needs hash and interact_ref");
  }
  Pending pending = match_pending(*impl_, digest->text, interact_ref->text, {}, false);
  return finish_pending(*impl_, pending, interact_ref->text, digest->text);
}

std::map<std::string, std::string> Client::proof_headers(const std::string& method, const std::string& url, const std::string* body,
                                                         const std::string& token) const {
  return proof_headers_of(impl_->config, method, url, body, token, {});
}

std::map<std::string, std::string> Client::authorization_headers(const Grant& grant, const std::string& method,
                                                                 const std::string& url, const std::string* body) const {
  return proof_headers(method, url, body, grant.access_token);
}

Answer Client::call(const Grant& grant, const std::string& url, const std::string& method, const std::string* body) {
  std::string verb = method.empty() ? "GET" : method;
  auto headers = authorization_headers(grant, verb, url, body);
  return http_send(url, verb, headers, body, tls_of(impl_->config), "protocol");
}

Grant Client::rotate(const Grant& grant) {
  if (!grant.has_manage) throw Error("protocol", "this access token has no manage URI");
  check_same_origin(impl_->config, grant.manage_uri, "manage.uri");
  Json answer = signed_json(impl_->config, "POST", grant.manage_uri, nullptr, grant.manage_token);
  if (!has_token(answer)) throw Error("protocol", "the rotation returned no access token");
  Grant next = grant_from(*impl_, answer, &grant, nullptr);
  if (!grant.bearer && next.bearer) throw Error("validation", "rotating a key-bound token returned a bearer token");
  return next;
}

void Client::revoke(const Grant& grant) {
  if (!grant.has_continuation) throw Error("protocol", "this grant has no continuation, so it cannot be revoked");
  check_same_origin(impl_->config, grant.continuation_uri, "continue.uri");
  signed_json(impl_->config, "DELETE", grant.continuation_uri, nullptr, grant.continuation_token);
}

Grant Client::ensure_fresh(Grant grant) {
  double now = now_ms();
  if (!grant.has_expires_at || grant.expires_at_ms - now > 60000) return grant;
  return rotate(grant);
}

}  // namespace iya::gnap
