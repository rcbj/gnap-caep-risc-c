// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

#ifndef IYA_GNAP_H
#define IYA_GNAP_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define IYA_GNAP_EVENT_SESSION_REVOKED "https://schemas.openid.net/secevent/caep/event-type/session-revoked"
#define IYA_GNAP_EVENT_CREDENTIAL_CHANGE "https://schemas.openid.net/secevent/caep/event-type/credential-change"
#define IYA_GNAP_EVENT_CREDENTIAL_COMPROMISE "https://schemas.openid.net/secevent/risc/event-type/credential-compromise"
#define IYA_GNAP_EVENT_ACCOUNT_DISABLED "https://schemas.openid.net/secevent/risc/event-type/account-disabled"
#define IYA_GNAP_POLL_DELIVERY "urn:ietf:rfc:8936"

typedef struct iya_gnap_error {
  int failed;
  char *code;
  char *message;
} iya_gnap_error;

void iya_gnap_free(void *p);
void iya_gnap_error_clear(iya_gnap_error *err);

int iya_gnap_resolve(const char *json, const char *base_dir, char **access_json, int *signals,
                     char **transmitter, int *poll_ms, iya_gnap_error *err);

int iya_gnap_interaction_hash(const char *client_nonce, const char *server_nonce, const char *interact_ref,
                              const char *grant_endpoint, char **out, iya_gnap_error *err);

int iya_gnap_content_digest(const char *body, char **out, iya_gnap_error *err);

int iya_gnap_create_self_signed(const char *common_name, const char *const *dns, size_t dns_count,
                                const char *const *ips, size_t ip_count, char **key_pem, char **cert_pem,
                                char **fingerprint, iya_gnap_error *err);

int iya_gnap_mtls_published_cert(const char *key_pem, const char *cert_pem, char **out, iya_gnap_error *err);
int iya_gnap_mtls_tls_chain(const char *key_pem, const char *cert_pem, char **out, iya_gnap_error *err);
int iya_gnap_cert_fingerprint(const char *cert_pem, char **out, iya_gnap_error *err);

typedef struct iya_gnap_client iya_gnap_client;
typedef struct iya_gnap_grant iya_gnap_grant;
typedef struct iya_gnap_result iya_gnap_result;

iya_gnap_client *iya_gnap_client_from_json(const char *json, const char *base_dir, iya_gnap_error *err);
iya_gnap_client *iya_gnap_client_from_file(const char *path, iya_gnap_error *err);
int iya_gnap_resolve_file(const char *path, char **access_json, int *signals, char **transmitter, int *poll_ms,
                          iya_gnap_error *err);
void iya_gnap_client_free(iya_gnap_client *client);

iya_gnap_result *iya_gnap_request_grant(iya_gnap_client *client, iya_gnap_error *err);
const char *iya_gnap_result_redirect(const iya_gnap_result *result);
const char *iya_gnap_result_pending_id(const iya_gnap_result *result);
iya_gnap_grant *iya_gnap_result_take_grant(iya_gnap_result *result);
void iya_gnap_result_free(iya_gnap_result *result);

const char *iya_gnap_grant_access_token(const iya_gnap_grant *grant);
int iya_gnap_grant_bearer(const iya_gnap_grant *grant);
const char *iya_gnap_grant_subject_sub(const iya_gnap_grant *grant);
const char *iya_gnap_grant_subject_email(const iya_gnap_grant *grant);
const char *iya_gnap_grant_subject_sid(const iya_gnap_grant *grant);
const char *iya_gnap_grant_subject_name(const iya_gnap_grant *grant);
int iya_gnap_grant_assertion_verified(const iya_gnap_grant *grant);
const char *iya_gnap_grant_id(const iya_gnap_grant *grant);
const char *iya_gnap_grant_continuation_uri(const iya_gnap_grant *grant);
void iya_gnap_grant_set_expires_at(iya_gnap_grant *grant, double expires_at_ms);
void iya_gnap_grant_free(iya_gnap_grant *grant);

iya_gnap_grant *iya_gnap_finish_redirect(iya_gnap_client *client, const char *query, const char *const *allowed,
                                         size_t allowed_count, iya_gnap_error *err);
iya_gnap_grant *iya_gnap_finish_redirect_pairs(iya_gnap_client *client, const char *const *keys,
                                               const char *const *values, size_t pair_count,
                                               const char *const *allowed, size_t allowed_count,
                                               iya_gnap_error *err);
iya_gnap_grant *iya_gnap_finish_push_json(iya_gnap_client *client, const char *json, iya_gnap_error *err);
iya_gnap_grant *iya_gnap_rotate(iya_gnap_client *client, const iya_gnap_grant *grant, iya_gnap_error *err);
int iya_gnap_revoke(iya_gnap_client *client, const iya_gnap_grant *grant, iya_gnap_error *err);
iya_gnap_grant *iya_gnap_ensure_fresh(iya_gnap_client *client, const iya_gnap_grant *grant, iya_gnap_error *err);
int iya_gnap_call(iya_gnap_client *client, const iya_gnap_grant *grant, const char *method, const char *url,
                  int *status, char **body, iya_gnap_error *err);

int iya_gnap_person_json(const char *subject_json, const char *issuer, char **out, iya_gnap_error *err);
int iya_gnap_verify_jws(const char *token, const char *jwks_json, char **payload_json, iya_gnap_error *err);
int iya_gnap_subject_of(const char *sub_id_json, const char *issuer, char **out, iya_gnap_error *err);

typedef void (*iya_gnap_on_end)(const char *const *ids, size_t count, void *user);
typedef void (*iya_gnap_on_event)(const char *type, int ended, void *user);
typedef char *(*iya_gnap_headers_fn)(const char *method, const char *url, const char *body, void *user);

typedef struct iya_gnap_receiver iya_gnap_receiver;
iya_gnap_receiver *iya_gnap_receiver_new(const char *transmitter, iya_gnap_on_end on_end, void *end_user,
                                         iya_gnap_headers_fn headers, void *header_user, int poll_interval_ms,
                                         iya_gnap_error *err);
int iya_gnap_receiver_on(iya_gnap_receiver *receiver, const char *type, iya_gnap_on_event fn, void *user,
                         iya_gnap_error *err);
int iya_gnap_receiver_start(iya_gnap_receiver *receiver, iya_gnap_error *err);
void iya_gnap_receiver_stop(iya_gnap_receiver *receiver);
int iya_gnap_receiver_poll(iya_gnap_receiver *receiver, iya_gnap_error *err);
int iya_gnap_receiver_track(iya_gnap_receiver *receiver, const char *local_id, const char *person, const char *email,
                            const char *idp_session, iya_gnap_error *err);
int iya_gnap_receiver_verify(iya_gnap_receiver *receiver, const char *state, iya_gnap_error *err);
const char *iya_gnap_receiver_stream_id(const iya_gnap_receiver *receiver);
void iya_gnap_receiver_free(iya_gnap_receiver *receiver);

#ifdef __cplusplus
}
#endif

#endif
