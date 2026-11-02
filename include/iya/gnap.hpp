// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

#pragma once

#include <functional>
#include <map>
#include <memory>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace iya::gnap {

class Error : public std::runtime_error {
 public:
  std::string code;
  std::string gnap;
  bool has_continue = false;
  std::string continue_uri;
  std::string continue_token;
  bool has_wait = false;
  double wait_sec = 0;

  Error(std::string code_in, std::string message, std::string gnap_in = {})
      : std::runtime_error(std::move(message)), code(std::move(code_in)), gnap(std::move(gnap_in)) {}
};

inline constexpr char kEventSessionRevoked[] =
    "https://schemas.openid.net/secevent/caep/event-type/session-revoked";
inline constexpr char kEventCredentialChange[] =
    "https://schemas.openid.net/secevent/caep/event-type/credential-change";
inline constexpr char kEventCredentialCompromise[] =
    "https://schemas.openid.net/secevent/risc/event-type/credential-compromise";
inline constexpr char kEventAccountDisabled[] =
    "https://schemas.openid.net/secevent/risc/event-type/account-disabled";
inline constexpr char kPollDelivery[] = "urn:ietf:rfc:8936";

struct Config {
  std::string grant_endpoint;
  std::string id_token_issuer;
  std::string application;
  std::string access_json;
  int signals = -1;
  bool has_ssf = false;
  std::string ssf_transmitter;
  int poll_interval_ms = 0;
  std::string finish_uri;
  std::string finish_method;
  std::string key_proof;

  static Config resolve_json(const std::string& json, const std::string& base_dir);
  static Config from_file(const std::string& path);
};

struct Subject {
  bool present = false;
  std::string sub;
  std::string iss;
  bool has_uid = false;
  std::string uid;
  std::string email;
  std::string name;
  std::string sid;
  bool assertion_verified = false;
};

struct Grant {
  std::string access_token;
  bool bearer = false;
  bool has_expires_in = false;
  double expires_in = 0;
  bool has_expires_at = false;
  double expires_at_ms = 0;
  bool has_manage = false;
  std::string manage_uri;
  std::string manage_token;
  bool has_continuation = false;
  std::string continuation_uri;
  std::string continuation_token;
  bool has_wait = false;
  double wait_sec = 0;
  std::string instance_id;
  Subject subject;
  std::string grant_id;
};

struct GrantResult {
  std::string redirect_url;
  bool has_pending = false;
  std::string pending_id;
  bool has_grant = false;
  Grant grant;
};

struct Finished {
  Grant grant;
};

struct TlsOpt {
  std::string ca;
  std::string cert;
  std::string key;
  bool insecure = false;
};

struct Answer {
  int status = 0;
  std::string content_type;
  std::string body;
};

struct KeyMaterial {
  std::string private_key_pem;
  std::string certificate_pem;
  std::string fingerprint;
};

struct SignalEvent {
  std::string type;
  std::string payload_json;
  std::string subject_json;
  std::string jti;
  std::vector<std::string> sessions;
  bool ended = false;
};

class Client {
 public:
  static Client from_json(const std::string& json, const std::string& base_dir);
  static Client from_file(const std::string& path);
  ~Client();
  Client(Client&&) noexcept;
  Client& operator=(Client&&) noexcept;
  Client(const Client&) = delete;
  Client& operator=(const Client&) = delete;

  Config config() const;
  TlsOpt tls() const;
  GrantResult request_grant();
  Finished finish_redirect(const std::string& query, const std::vector<std::string>& allowed_ids);
  Finished finish_redirect_pairs(const std::vector<std::pair<std::string, std::string>>& pairs,
                                 const std::vector<std::string>& allowed_ids);
  Finished finish_push_json(const std::string& json);
  std::map<std::string, std::string> proof_headers(const std::string& method, const std::string& url,
                                                   const std::string* body, const std::string& token) const;
  std::map<std::string, std::string> authorization_headers(const Grant& grant, const std::string& method,
                                                           const std::string& url, const std::string* body) const;
  Answer call(const Grant& grant, const std::string& url, const std::string& method, const std::string* body);
  Grant rotate(const Grant& grant);
  void revoke(const Grant& grant);
  Grant ensure_fresh(Grant grant);

  struct Impl;

 private:
  explicit Client(std::unique_ptr<Impl> impl);
  std::unique_ptr<Impl> impl_;
};

class SignalsReceiver {
 public:
  using EndFn = std::function<void(const std::vector<std::string>&, const SignalEvent&)>;
  using EventFn = std::function<void(const SignalEvent&)>;
  using HeaderFn = std::function<std::map<std::string, std::string>(const std::string& method, const std::string& url,
                                                                    const std::string& body)>;

  SignalsReceiver(std::string transmitter, EndFn on_end, HeaderFn headers, int poll_interval_ms);
  ~SignalsReceiver();
  SignalsReceiver(SignalsReceiver&&) noexcept;
  SignalsReceiver& operator=(SignalsReceiver&&) noexcept;
  SignalsReceiver(const SignalsReceiver&) = delete;
  SignalsReceiver& operator=(const SignalsReceiver&) = delete;

  void on(const std::string& type, EventFn fn);
  void start();
  void stop();
  bool poll_once();
  void track(const std::string& local_id, const std::string& person, const std::string& email,
             const std::string& idp_session);
  void untrack(const std::string& local_id);
  void set_tls(const TlsOpt& tls);
  void verify_stream(const std::string& state);
  std::string stream_id() const;

 private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

std::string interaction_hash(const std::string& client_nonce, const std::string& server_nonce,
                             const std::string& interact_ref, const std::string& grant_endpoint);
std::string content_digest(const std::string& body);
KeyMaterial create_self_signed(const std::string& common_name, const std::vector<std::string>& dns_names,
                               const std::vector<std::string>& ip_addresses);
std::string mtls_published_cert(const std::string& private_pem, const std::string& certificate_pem);
std::string mtls_tls_chain(const std::string& private_pem, const std::string& certificate_pem);
std::string certificate_fingerprint(const std::string& certificate_pem);
Subject person_from_subject_json(const std::string& subject_json, const std::string& issuer);

struct VerifiedJws {
  std::string header_json;
  std::string payload_json;
};
VerifiedJws verify_compact_jws(const std::string& token, const std::string& jwks_json);
std::string subject_of_json(const std::string& sub_id_json, const std::string& issuer);

}  // namespace iya::gnap
