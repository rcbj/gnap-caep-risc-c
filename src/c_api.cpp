// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

#include "iya_gnap.h"

#include "iya/gnap.hpp"

#include "json.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <new>
#include <string>
#include <vector>

struct iya_gnap_client {
  iya::gnap::Client client;
};

struct iya_gnap_grant {
  iya::gnap::Grant grant;
};

struct iya_gnap_result {
  iya::gnap::GrantResult result;
};

struct iya_gnap_receiver {
  std::unique_ptr<iya::gnap::SignalsReceiver> receiver;
  iya_gnap_on_end on_end = nullptr;
  void* end_user = nullptr;
  iya_gnap_headers_fn headers = nullptr;
  void* header_user = nullptr;
  std::string stream_id;
};

namespace {

char* dup_str(const std::string& value) {
  char* out = static_cast<char*>(std::malloc(value.size() + 1));
  if (out == nullptr) return nullptr;
  std::memcpy(out, value.data(), value.size() + 1);
  return out;
}

int fail_out(iya_gnap_error* err, const iya::gnap::Error& error) {
  std::fprintf(stderr, "%s\n", error.what());
  if (err != nullptr) {
    err->failed = 1;
    err->code = dup_str(error.code);
    err->message = dup_str(error.what());
  }
  return -1;
}

template <typename Fn>
int guard(iya_gnap_error* err, Fn fn) {
  try {
    fn();
    if (err != nullptr) {
      err->failed = 0;
      err->code = nullptr;
      err->message = nullptr;
    }
    return 0;
  } catch (const iya::gnap::Error& error) {
    return fail_out(err, error);
  } catch (const std::exception& error) {
    return fail_out(err, iya::gnap::Error("protocol", error.what()));
  }
}

iya_gnap_grant* grant_box(iya::gnap::Grant grant) {
  auto* out = new iya_gnap_grant;
  out->grant = std::move(grant);
  return out;
}

}  // namespace

void iya_gnap_free(void* p) { std::free(p); }

void iya_gnap_error_clear(iya_gnap_error* err) {
  if (err == nullptr) return;
  std::free(err->code);
  std::free(err->message);
  err->code = nullptr;
  err->message = nullptr;
  err->failed = 0;
}

int iya_gnap_resolve(const char* json, const char* base_dir, char** access_json, int* signals, char** transmitter,
                     int* poll_ms, iya_gnap_error* err) {
  return guard(err, [&] {
    auto cfg = iya::gnap::Config::resolve_json(json == nullptr ? "" : json, base_dir == nullptr ? "" : base_dir);
    if (access_json != nullptr) *access_json = dup_str(cfg.access_json);
    if (signals != nullptr) *signals = cfg.signals;
    if (transmitter != nullptr) *transmitter = dup_str(cfg.ssf_transmitter);
    if (poll_ms != nullptr) *poll_ms = cfg.poll_interval_ms;
  });
}

int iya_gnap_interaction_hash(const char* client_nonce, const char* server_nonce, const char* interact_ref,
                              const char* grant_endpoint, char** out, iya_gnap_error* err) {
  return guard(err, [&] {
    auto hash = iya::gnap::interaction_hash(client_nonce == nullptr ? "" : client_nonce,
                                            server_nonce == nullptr ? "" : server_nonce,
                                            interact_ref == nullptr ? "" : interact_ref,
                                            grant_endpoint == nullptr ? "" : grant_endpoint);
    if (out != nullptr) *out = dup_str(hash);
  });
}

int iya_gnap_content_digest(const char* body, char** out, iya_gnap_error* err) {
  return guard(err, [&] {
    auto digest = iya::gnap::content_digest(body == nullptr ? "" : body);
    if (out != nullptr) *out = dup_str(digest);
  });
}

int iya_gnap_create_self_signed(const char* common_name, const char* const* dns, size_t dns_count, const char* const* ips,
                                size_t ip_count, char** key_pem, char** cert_pem, char** fingerprint, iya_gnap_error* err) {
  return guard(err, [&] {
    std::vector<std::string> dns_names;
    std::vector<std::string> ip_names;
    for (size_t i = 0; i < dns_count; i++) dns_names.emplace_back(dns[i] == nullptr ? "" : dns[i]);
    for (size_t i = 0; i < ip_count; i++) ip_names.emplace_back(ips[i] == nullptr ? "" : ips[i]);
    auto material = iya::gnap::create_self_signed(common_name == nullptr ? "" : common_name, dns_names, ip_names);
    if (key_pem != nullptr) *key_pem = dup_str(material.private_key_pem);
    if (cert_pem != nullptr) *cert_pem = dup_str(material.certificate_pem);
    if (fingerprint != nullptr) *fingerprint = dup_str(material.fingerprint);
  });
}

int iya_gnap_mtls_published_cert(const char* key_pem, const char* cert_pem, char** out, iya_gnap_error* err) {
  return guard(err, [&] {
    auto cert = iya::gnap::mtls_published_cert(key_pem == nullptr ? "" : key_pem, cert_pem == nullptr ? "" : cert_pem);
    if (out != nullptr) *out = dup_str(cert);
  });
}

int iya_gnap_mtls_tls_chain(const char* key_pem, const char* cert_pem, char** out, iya_gnap_error* err) {
  return guard(err, [&] {
    auto chain = iya::gnap::mtls_tls_chain(key_pem == nullptr ? "" : key_pem, cert_pem == nullptr ? "" : cert_pem);
    if (out != nullptr) *out = dup_str(chain);
  });
}

int iya_gnap_cert_fingerprint(const char* cert_pem, char** out, iya_gnap_error* err) {
  return guard(err, [&] {
    auto fp = iya::gnap::certificate_fingerprint(cert_pem == nullptr ? "" : cert_pem);
    if (out != nullptr) *out = dup_str(fp);
  });
}

iya_gnap_client* iya_gnap_client_from_json(const char* json, const char* base_dir, iya_gnap_error* err) {
  iya_gnap_client* client = nullptr;
  if (guard(err, [&] {
        client = new iya_gnap_client{iya::gnap::Client::from_json(json == nullptr ? "" : json, base_dir == nullptr ? "" : base_dir)};
      }) != 0) {
    return nullptr;
  }
  return client;
}

iya_gnap_client* iya_gnap_client_from_file(const char* path, iya_gnap_error* err) {
  iya_gnap_client* client = nullptr;
  if (guard(err, [&] {
        client = new iya_gnap_client{iya::gnap::Client::from_file(path == nullptr ? "" : path)};
      }) != 0) {
    return nullptr;
  }
  return client;
}

int iya_gnap_resolve_file(const char* path, char** access_json, int* signals, char** transmitter, int* poll_ms,
                          iya_gnap_error* err) {
  return guard(err, [&] {
    auto cfg = iya::gnap::Config::from_file(path == nullptr ? "" : path);
    if (access_json != nullptr) *access_json = dup_str(cfg.access_json);
    if (signals != nullptr) *signals = cfg.signals;
    if (transmitter != nullptr) *transmitter = dup_str(cfg.ssf_transmitter);
    if (poll_ms != nullptr) *poll_ms = cfg.poll_interval_ms;
  });
}

void iya_gnap_client_free(iya_gnap_client* client) { delete client; }

iya_gnap_result* iya_gnap_request_grant(iya_gnap_client* client, iya_gnap_error* err) {
  iya_gnap_result* result = nullptr;
  if (guard(err, [&] {
        result = new iya_gnap_result;
        result->result = client->client.request_grant();
      }) != 0) {
    return nullptr;
  }
  return result;
}

const char* iya_gnap_result_redirect(const iya_gnap_result* result) {
  if (result == nullptr || result->result.redirect_url.empty()) return nullptr;
  return result->result.redirect_url.c_str();
}

const char* iya_gnap_result_pending_id(const iya_gnap_result* result) {
  if (result == nullptr || !result->result.has_pending) return nullptr;
  return result->result.pending_id.c_str();
}

iya_gnap_grant* iya_gnap_result_take_grant(iya_gnap_result* result) {
  if (result == nullptr || !result->result.has_grant) return nullptr;
  result->result.has_grant = false;
  return grant_box(std::move(result->result.grant));
}

void iya_gnap_result_free(iya_gnap_result* result) { delete result; }

const char* iya_gnap_grant_access_token(const iya_gnap_grant* grant) {
  return grant == nullptr ? nullptr : grant->grant.access_token.c_str();
}
int iya_gnap_grant_bearer(const iya_gnap_grant* grant) { return grant != nullptr && grant->grant.bearer ? 1 : 0; }
const char* iya_gnap_grant_subject_sub(const iya_gnap_grant* grant) {
  if (grant == nullptr || !grant->grant.subject.present) return nullptr;
  return grant->grant.subject.sub.c_str();
}
const char* iya_gnap_grant_subject_email(const iya_gnap_grant* grant) {
  if (grant == nullptr) return nullptr;
  return grant->grant.subject.email.c_str();
}
const char* iya_gnap_grant_subject_sid(const iya_gnap_grant* grant) {
  if (grant == nullptr) return nullptr;
  return grant->grant.subject.sid.c_str();
}
const char* iya_gnap_grant_subject_name(const iya_gnap_grant* grant) {
  if (grant == nullptr) return nullptr;
  return grant->grant.subject.name.c_str();
}
int iya_gnap_grant_assertion_verified(const iya_gnap_grant* grant) {
  return grant != nullptr && grant->grant.subject.assertion_verified ? 1 : 0;
}
const char* iya_gnap_grant_id(const iya_gnap_grant* grant) {
  return grant == nullptr ? nullptr : grant->grant.grant_id.c_str();
}
const char* iya_gnap_grant_continuation_uri(const iya_gnap_grant* grant) {
  if (grant == nullptr || !grant->grant.has_continuation) return nullptr;
  return grant->grant.continuation_uri.c_str();
}
void iya_gnap_grant_set_expires_at(iya_gnap_grant* grant, double expires_at_ms) {
  if (grant == nullptr) return;
  grant->grant.has_expires_at = true;
  grant->grant.expires_at_ms = expires_at_ms;
}
void iya_gnap_grant_free(iya_gnap_grant* grant) { delete grant; }

iya_gnap_grant* iya_gnap_finish_redirect(iya_gnap_client* client, const char* query, const char* const* allowed,
                                         size_t allowed_count, iya_gnap_error* err) {
  iya_gnap_grant* grant = nullptr;
  if (guard(err, [&] {
        std::vector<std::string> ids;
        for (size_t i = 0; i < allowed_count; i++) ids.emplace_back(allowed[i] == nullptr ? "" : allowed[i]);
        auto finished = client->client.finish_redirect(query == nullptr ? "" : query, ids);
        grant = grant_box(std::move(finished.grant));
      }) != 0) {
    return nullptr;
  }
  return grant;
}

iya_gnap_grant* iya_gnap_finish_redirect_pairs(iya_gnap_client* client, const char* const* keys, const char* const* values,
                                               size_t pair_count, const char* const* allowed, size_t allowed_count,
                                               iya_gnap_error* err) {
  iya_gnap_grant* grant = nullptr;
  if (guard(err, [&] {
        std::vector<std::pair<std::string, std::string>> pairs;
        for (size_t i = 0; i < pair_count; i++) {
          pairs.emplace_back(keys[i] == nullptr ? "" : keys[i], values[i] == nullptr ? "" : values[i]);
        }
        std::vector<std::string> ids;
        for (size_t i = 0; i < allowed_count; i++) ids.emplace_back(allowed[i] == nullptr ? "" : allowed[i]);
        auto finished = client->client.finish_redirect_pairs(pairs, ids);
        grant = grant_box(std::move(finished.grant));
      }) != 0) {
    return nullptr;
  }
  return grant;
}

iya_gnap_grant* iya_gnap_finish_push_json(iya_gnap_client* client, const char* json, iya_gnap_error* err) {
  iya_gnap_grant* grant = nullptr;
  if (guard(err, [&] {
        auto finished = client->client.finish_push_json(json == nullptr ? "" : json);
        grant = grant_box(std::move(finished.grant));
      }) != 0) {
    return nullptr;
  }
  return grant;
}

iya_gnap_grant* iya_gnap_rotate(iya_gnap_client* client, const iya_gnap_grant* grant, iya_gnap_error* err) {
  iya_gnap_grant* next = nullptr;
  if (guard(err, [&] { next = grant_box(client->client.rotate(grant->grant)); }) != 0) return nullptr;
  return next;
}

int iya_gnap_revoke(iya_gnap_client* client, const iya_gnap_grant* grant, iya_gnap_error* err) {
  return guard(err, [&] { client->client.revoke(grant->grant); });
}

iya_gnap_grant* iya_gnap_ensure_fresh(iya_gnap_client* client, const iya_gnap_grant* grant, iya_gnap_error* err) {
  iya_gnap_grant* next = nullptr;
  if (guard(err, [&] { next = grant_box(client->client.ensure_fresh(grant->grant)); }) != 0) return nullptr;
  return next;
}

int iya_gnap_call(iya_gnap_client* client, const iya_gnap_grant* grant, const char* method, const char* url, int* status,
                  char** body, iya_gnap_error* err) {
  return guard(err, [&] {
    auto answer = client->client.call(grant->grant, url == nullptr ? "" : url, method == nullptr ? "" : method, nullptr);
    if (status != nullptr) *status = answer.status;
    if (body != nullptr) *body = dup_str(answer.body);
  });
}

int iya_gnap_person_json(const char* subject_json, const char* issuer, char** out, iya_gnap_error* err) {
  return guard(err, [&] {
    auto person = iya::gnap::person_from_subject_json(subject_json == nullptr ? "" : subject_json, issuer == nullptr ? "" : issuer);
    iya::gnap::Json doc = iya::gnap::Json::object();
    doc.set("sub", iya::gnap::Json::str(person.sub));
    doc.set("iss", iya::gnap::Json::str(person.iss));
    if (person.has_uid) doc.set("uid", iya::gnap::Json::str(person.uid));
    else doc.set("uid", iya::gnap::Json::nul());
    doc.set("email", iya::gnap::Json::str(person.email));
    doc.set("name", iya::gnap::Json::str(person.name));
    doc.set("sid", iya::gnap::Json::str(person.sid));
    doc.set("assertion_verified", iya::gnap::Json::boolean(person.assertion_verified));
    if (out != nullptr) *out = dup_str(doc.dump());
  });
}

int iya_gnap_verify_jws(const char* token, const char* jwks_json, char** payload_json, iya_gnap_error* err) {
  return guard(err, [&] {
    auto verified = iya::gnap::verify_compact_jws(token == nullptr ? "" : token, jwks_json == nullptr ? "" : jwks_json);
    if (payload_json != nullptr) *payload_json = dup_str(verified.payload_json);
  });
}

int iya_gnap_subject_of(const char* sub_id_json, const char* issuer, char** out, iya_gnap_error* err) {
  return guard(err, [&] {
    auto text = iya::gnap::subject_of_json(sub_id_json == nullptr ? "" : sub_id_json, issuer == nullptr ? "" : issuer);
    if (out != nullptr) *out = dup_str(text);
  });
}

iya_gnap_receiver* iya_gnap_receiver_new(const char* transmitter, iya_gnap_on_end on_end, void* end_user,
                                         iya_gnap_headers_fn headers, void* header_user, int poll_interval_ms,
                                         iya_gnap_error* err) {
  auto* box = new iya_gnap_receiver;
  box->on_end = on_end;
  box->end_user = end_user;
  box->headers = headers;
  box->header_user = header_user;
  if (guard(err, [&] {
        box->receiver = std::make_unique<iya::gnap::SignalsReceiver>(
            transmitter == nullptr ? "" : transmitter,
            [box](const std::vector<std::string>& ids, const iya::gnap::SignalEvent&) {
              std::vector<const char*> ptrs;
              ptrs.reserve(ids.size());
              for (const auto& id : ids) ptrs.push_back(id.c_str());
              if (box->on_end != nullptr) box->on_end(ptrs.empty() ? nullptr : ptrs.data(), ptrs.size(), box->end_user);
            },
            [box](const std::string& method, const std::string& url, const std::string& body) {
              std::map<std::string, std::string> out;
              if (box->headers == nullptr) return out;
              char* raw = box->headers(method.c_str(), url.c_str(), body.c_str(), box->header_user);
              if (raw == nullptr) return out;
              try {
                auto doc = iya::gnap::Json::parse(raw);
                std::free(raw);
                if (doc.type == iya::gnap::Type::Object) {
                  for (const auto& item : doc.obj)
                    if (item.second.type == iya::gnap::Type::String) out[item.first] = item.second.text;
                }
              } catch (...) {
                std::free(raw);
                throw;
              }
              return out;
            },
            poll_interval_ms);
      }) != 0) {
    delete box;
    return nullptr;
  }
  return box;
}

int iya_gnap_receiver_on(iya_gnap_receiver* receiver, const char* type, iya_gnap_on_event fn, void* user,
                         iya_gnap_error* err) {
  return guard(err, [&] {
    std::string event = type == nullptr ? "" : type;
    receiver->receiver->on(event, [fn, user](const iya::gnap::SignalEvent& event) {
      if (fn != nullptr) fn(event.type.c_str(), event.ended ? 1 : 0, user);
    });
  });
}

int iya_gnap_receiver_start(iya_gnap_receiver* receiver, iya_gnap_error* err) {
  return guard(err, [&] { receiver->receiver->start(); });
}

void iya_gnap_receiver_stop(iya_gnap_receiver* receiver) {
  if (receiver != nullptr && receiver->receiver) receiver->receiver->stop();
}

int iya_gnap_receiver_poll(iya_gnap_receiver* receiver, iya_gnap_error* err) {
  return guard(err, [&] { receiver->receiver->poll_once(); });
}

int iya_gnap_receiver_track(iya_gnap_receiver* receiver, const char* local_id, const char* person, const char* email,
                            const char* idp_session, iya_gnap_error* err) {
  return guard(err, [&] {
    receiver->receiver->track(local_id == nullptr ? "" : local_id, person == nullptr ? "" : person,
                              email == nullptr ? "" : email, idp_session == nullptr ? "" : idp_session);
  });
}

int iya_gnap_receiver_verify(iya_gnap_receiver* receiver, const char* state, iya_gnap_error* err) {
  return guard(err, [&] { receiver->receiver->verify_stream(state == nullptr ? "" : state); });
}

const char* iya_gnap_receiver_stream_id(const iya_gnap_receiver* receiver) {
  if (receiver == nullptr || receiver->receiver == nullptr) return nullptr;
  const_cast<iya_gnap_receiver*>(receiver)->stream_id = receiver->receiver->stream_id();
  return receiver->stream_id.c_str();
}

void iya_gnap_receiver_free(iya_gnap_receiver* receiver) { delete receiver; }
