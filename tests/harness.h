// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

#ifndef IYA_GNAP_HARNESS_H
#define IYA_GNAP_HARNESS_H

#ifdef __cplusplus
extern "C" {
#endif

int harness_auth_start(void);
void harness_auth_reset(void);
void harness_auth_stop(void);
const char* harness_auth_base(void);
const char* harness_auth_server_cert(void);
const char* harness_auth_client_key(void);
const char* harness_auth_client_cert(void);
const char* harness_auth_fingerprint(void);
void harness_set_foreign(int value);
void harness_set_bearer(int value);
void harness_set_too_fast(int value);
void harness_set_aud(const char* value);
void harness_set_sub(const char* value);
void harness_set_iss_sub(const char* value);
int harness_too_fast_sent(void);
void harness_clear_seen(void);
int harness_url_count(const char* url);
const char* harness_last_post_gnap_body(void);
int harness_last_has_signature(void);
const char* harness_first(const char* url, const char* field);
const char* harness_last_method(void);
const char* harness_last_authorization(void);
int harness_detached_contains_dot(const char* url);

int harness_tx_start(void);
void harness_tx_stop(void);
const char* harness_tx_base(void);
void harness_tx_deliver(const char* event_type, const char* sub_json, int other_key, char* jti, unsigned long jti_len);
int harness_tx_streams(void);
const char* harness_tx_authorization(void);
int harness_tx_acked_count(void);
const char* harness_tx_acked_at(int index);
const char* harness_tx_err(const char* jti);

int harness_sign_rs256(const char* header_json, const char* payload_json, int other_key, char* out, unsigned long out_len);
const char* harness_rsa_jwk(void);

#ifdef __cplusplus
}
#endif

#endif
