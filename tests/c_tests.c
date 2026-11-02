// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

#include "iya_gnap.h"
#include "harness.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static int g_failures = 0;

static void check(int cond, const char* file, int line, const char* text) {
  if (cond) return;
  fprintf(stderr, "%s:%d: %s\n", file, line, text);
  g_failures++;
}

#define CHECK(cond) check((cond), __FILE__, __LINE__, #cond)

static void wipe(iya_gnap_error* err) {
  if (err->code != NULL || err->message != NULL) iya_gnap_error_clear(err);
  err->failed = 0;
  err->code = NULL;
  err->message = NULL;
}

static int contains(const char* text, const char* part) {
  return text != NULL && part != NULL && strstr(text, part) != NULL;
}

static char* json_escape(const char* in) {
  size_t n = 0;
  const char* p;
  char* out;
  char* w;
  if (in == NULL) in = "";
  for (p = in; *p != '\0'; p++) {
    n += (*p == '"' || *p == '\\' || *p == '\n' || *p == '\r') ? 2 : 1;
  }
  out = (char*)malloc(n + 1);
  if (out == NULL) return NULL;
  w = out;
  for (p = in; *p != '\0'; p++) {
    if (*p == '"' || *p == '\\') {
      *w++ = '\\';
      *w++ = *p;
    } else if (*p == '\n') {
      *w++ = '\\';
      *w++ = 'n';
    } else if (*p == '\r') {
      *w++ = '\\';
      *w++ = 'r';
    } else {
      *w++ = *p;
    }
  }
  *w = '\0';
  return out;
}

static int count_text(const char* text, const char* part) {
  int n = 0;
  const char* p;
  size_t len;
  if (text == NULL || part == NULL || part[0] == '\0') return 0;
  len = strlen(part);
  for (p = text; (p = strstr(p, part)) != NULL; p += len) n++;
  return n;
}

static char* self_key(iya_gnap_error* err) {
  char* key = NULL;
  char* cert = NULL;
  char* fp = NULL;
  wipe(err);
  if (iya_gnap_create_self_signed("app", NULL, 0, NULL, 0, &key, &cert, &fp, err) != 0) return NULL;
  iya_gnap_free(cert);
  iya_gnap_free(fp);
  return key;
}

static int resolve_extra(const char* extra, char** access, int* signals, char** transmitter, int* poll, iya_gnap_error* err) {
  char* key = self_key(err);
  char* escaped;
  char* json;
  size_t cap;
  int wrote;
  int rc;
  if (key == NULL) return -1;
  escaped = json_escape(key);
  iya_gnap_free(key);
  cap = strlen(escaped) + strlen(extra) + 512;
  json = (char*)malloc(cap);
  wrote = snprintf(json, cap,
                   "{\"grantEndpoint\":\"https://idp.example/gnap\",\"application\":\"app\","
                   "\"privateKey\":\"%s\",\"keyProof\":\"httpsig\"%s}",
                   escaped, extra);
  free(escaped);
  if (wrote < 0 || (size_t)wrote >= cap) {
    free(json);
    return -1;
  }
  wipe(err);
  rc = iya_gnap_resolve(json, ".", access, signals, transmitter, poll, err);
  free(json);
  return rc;
}

static int test_defaults(void) {
  iya_gnap_error err;
  char* access = NULL;
  char* transmitter = NULL;
  int signals = 99;
  int poll = -1;
  memset(&err, 0, sizeof(err));
  CHECK(resolve_extra(",\"transmitterIssuer\":\"https://idp.example/issuer/\"", &access, &signals, &transmitter, &poll, &err) == 0);
  CHECK(access != NULL && strcmp(access, "[\"ssf.read\",\"ssf.manage\"]") == 0);
  CHECK(transmitter != NULL && strcmp(transmitter, "https://idp.example/issuer") == 0);
  CHECK(signals == -1);
  iya_gnap_free(access);
  iya_gnap_free(transmitter);
  access = NULL;
  transmitter = NULL;
  signals = 99;
  CHECK(resolve_extra(",\"signals\":true,\"transmitterIssuer\":\"https://idp.example/issuer\"", &access, &signals, &transmitter, &poll, &err) == 0);
  CHECK(signals == -1);
  CHECK(transmitter != NULL && transmitter[0] != '\0');
  iya_gnap_free(access);
  iya_gnap_free(transmitter);
  wipe(&err);
  return g_failures ? 1 : 0;
}

static int test_drops(void) {
  iya_gnap_error err;
  char* access = NULL;
  char* transmitter = NULL;
  int signals = -1;
  int poll = -1;
  memset(&err, 0, sizeof(err));
  CHECK(resolve_extra(",\"signals\":false,\"access\":[\"openid\",\"ssf.read\"],\"transmitterIssuer\":\"https://idp.example\","
                      "\"ssf\":{\"transmitter\":\"https://idp.example/tx\",\"pollIntervalMs\":3000}",
                      &access, &signals, &transmitter, &poll, &err) == 0);
  CHECK(access != NULL && strcmp(access, "[\"openid\"]") == 0);
  CHECK(transmitter != NULL && transmitter[0] == '\0');
  CHECK(signals == 0);
  CHECK(poll == 0);
  iya_gnap_free(access);
  iya_gnap_free(transmitter);
  access = NULL;
  transmitter = NULL;
  CHECK(resolve_extra(",\"signals\":false,\"access\":[\"openid\",\" ssf.read \",{\"type\":\"ssf.manage\",\"actions\":[\"read\"]},"
                      "{\"type\":\"api\"},{\"type\":\" ssf.read \"}],\"ssf\":{\"transmitter\":\"not a url\"}",
                      &access, &signals, &transmitter, &poll, &err) == 0);
  CHECK(access != NULL && strcmp(access, "[\"openid\",{\"type\":\"api\"},{\"type\":\" ssf.read \"}]") == 0);
  CHECK(transmitter != NULL && transmitter[0] == '\0');
  iya_gnap_free(access);
  iya_gnap_free(transmitter);
  wipe(&err);
  return g_failures ? 1 : 0;
}

static int refuses_one(const char* extra) {
  iya_gnap_error err;
  char* access = NULL;
  char* transmitter = NULL;
  int signals = 0;
  int poll = 0;
  int rc;
  memset(&err, 0, sizeof(err));
  rc = resolve_extra(extra, &access, &signals, &transmitter, &poll, &err);
  CHECK(rc != 0);
  CHECK(err.code != NULL && strcmp(err.code, "config") == 0);
  CHECK(contains(err.message, "signals is false and access has no rights left after ssf.read and ssf.manage were removed"));
  CHECK(contains(err.message, "must name a right this authorization server grants"));
  iya_gnap_free(access);
  iya_gnap_free(transmitter);
  wipe(&err);
  return 0;
}

static int test_refuses_only(void) {
  refuses_one(",\"signals\":false,\"access\":[\"ssf.read\",\"ssf.manage\"]");
  refuses_one(",\"signals\":false,\"transmitterIssuer\":\"https://idp.example\"");
  refuses_one(",\"signals\":false,\"access\":[{\"type\":\"ssf.read\"},{\"type\":\"ssf.manage\"}]");
  return g_failures ? 1 : 0;
}

static int test_refuses_value(void) {
  iya_gnap_error err;
  char* access = NULL;
  char* transmitter = NULL;
  int signals = 0;
  int poll = 0;
  memset(&err, 0, sizeof(err));
  CHECK(resolve_extra(",\"signals\":\"no\"", &access, &signals, &transmitter, &poll, &err) != 0);
  CHECK(err.code != NULL && strcmp(err.code, "config") == 0);
  CHECK(err.message != NULL && strcmp(err.message, "signals must be true or false") == 0);
  iya_gnap_free(access);
  iya_gnap_free(transmitter);
  wipe(&err);
  return g_failures ? 1 : 0;
}

static int test_hash(void) {
  iya_gnap_error err;
  char* out = NULL;
  memset(&err, 0, sizeof(err));
  CHECK(iya_gnap_interaction_hash("abc", "def", "xyz", "https://as.example/gnap", &out, &err) == 0);
  CHECK(out != NULL && strcmp(out, "2o3b9NeEcvp0At5d-71yCgybP45eTGm1_pTNMmjv_V0") == 0);
  iya_gnap_free(out);
  wipe(&err);
  return g_failures ? 1 : 0;
}

static char* client_json(const char* proof) {
  char* key = json_escape(harness_auth_client_key());
  char* cert = json_escape(harness_auth_client_cert());
  char* ca = json_escape(harness_auth_server_cert());
  const char* base = harness_auth_base();
  size_t cap = strlen(key) + strlen(cert) + strlen(ca) + strlen(base) * 2 + 2048;
  char* json = (char*)malloc(cap);
  int wrote = snprintf(json, cap,
                       "{\"grantEndpoint\":\"%s/gnap\",\"idTokenIssuer\":\"%s\","
                       "\"application\":\"gnap-caep-risc-demo\","
                       "\"display\":{\"name\":\"GNAP CAEP RISC demo\",\"uri\":\"http://127.0.0.1:3000/\"},"
                       "\"access\":[\"ssf.read\",\"ssf.manage\"],"
                       "\"subIdFormats\":[\"iss_sub\",\"account\",\"opaque\"],"
                       "\"assertionFormats\":[\"id_token\"],"
                       "\"keyProof\":\"%s\",\"privateKey\":\"%s\",\"certificate\":\"%s\","
                       "\"finishUri\":\"http://127.0.0.1:3000/callback\",\"finishMethod\":\"redirect\","
                       "\"tlsCa\":\"%s\"}",
                       base, base, proof, key, cert, ca);
  free(key);
  free(cert);
  free(ca);
  if (wrote < 0 || (size_t)wrote >= cap) {
    free(json);
    return NULL;
  }
  return json;
}

static iya_gnap_client* open_client(const char* proof, iya_gnap_error* err) {
  char* json = client_json(proof);
  iya_gnap_client* client;
  wipe(err);
  client = iya_gnap_client_from_json(json, ".", err);
  free(json);
  if (client == NULL) fprintf(stderr, "client: %s\n", err->message ? err->message : "");
  return client;
}

static int nonce_of(const char* body, char* nonce, size_t n) {
  const char* p = strstr(body, "\"nonce\":\"");
  size_t i = 0;
  if (p == NULL) return -1;
  p += 9;
  while (p[i] != '\0' && p[i] != '"' && i + 1 < n) {
    nonce[i] = p[i];
    i++;
  }
  nonce[i] = '\0';
  return i == 0 ? -1 : 0;
}

static int started(iya_gnap_client* client, char* pending, size_t pending_n, char* nonce, size_t nonce_n, iya_gnap_error* err) {
  iya_gnap_result* result;
  const char* id;
  char body[65536];
  wipe(err);
  result = iya_gnap_request_grant(client, err);
  if (result == NULL) {
    fprintf(stderr, "grant: %s\n", err->message ? err->message : "");
    return -1;
  }
  id = iya_gnap_result_pending_id(result);
  if (id == NULL) {
    fprintf(stderr, "missing pending\n");
    iya_gnap_result_free(result);
    return -1;
  }
  snprintf(pending, pending_n, "%s", id);
  iya_gnap_result_free(result);
  snprintf(body, sizeof(body), "%s", harness_last_post_gnap_body());
  if (nonce_of(body, nonce, nonce_n) != 0) {
    fprintf(stderr, "no nonce\n");
    return -1;
  }
  return 0;
}

static int digest_for(const char* nonce, const char* ref, char* out, size_t n, iya_gnap_error* err) {
  char endpoint[768];
  char* hash = NULL;
  snprintf(endpoint, sizeof(endpoint), "%s/gnap", harness_auth_base());
  wipe(err);
  if (iya_gnap_interaction_hash(nonce, "server-nonce", ref, endpoint, &hash, err) != 0) return -1;
  snprintf(out, n, "%s", hash ? hash : "");
  iya_gnap_free(hash);
  return 0;
}

static int test_front(void) {
  iya_gnap_error err;
  iya_gnap_client* client;
  iya_gnap_grant* grant;
  char pending[256];
  char nonce[256];
  char digest[256];
  char query[1024];
  char body[65536];
  const char* allowed_wrong[] = {"somebody-else"};
  const char* allowed_real[1];
  memset(&err, 0, sizeof(err));
  CHECK(harness_auth_start() == 0);
  harness_auth_reset();
  client = open_client("httpsig", &err);
  CHECK(client != NULL);
  harness_set_foreign(1);
  wipe(&err);
  CHECK(iya_gnap_request_grant(client, &err) == NULL);
  CHECK(contains(err.message, "not on the grant endpoint"));
  CHECK(harness_url_count("/continue") == 0);
  iya_gnap_client_free(client);
  harness_set_foreign(0);
  harness_clear_seen();
  client = open_client("httpsig", &err);
  CHECK(client != NULL);
  CHECK(started(client, pending, sizeof(pending), nonce, sizeof(nonce), &err) == 0);
  snprintf(body, sizeof(body), "%s", harness_last_post_gnap_body());
  CHECK(contains(body, "\"proof\":\"httpsig\""));
  CHECK(!contains(body, "class_id"));
  CHECK(contains(body, "\"sub_id_formats\":[\"iss_sub\",\"opaque\"]"));
  CHECK(harness_last_has_signature() == 1);
  CHECK(digest_for(nonce, "ref-1", digest, sizeof(digest), &err) == 0);
  allowed_real[0] = pending;
  snprintf(query, sizeof(query), "hash=%s&interact_ref=ref-1&access_token=no", digest);
  wipe(&err);
  grant = iya_gnap_finish_redirect(client, query, allowed_real, 1, &err);
  CHECK(grant == NULL);
  CHECK(contains(err.message, "tokens through the browser"));
  CHECK(!contains(err.message, "front"));
  snprintf(query, sizeof(query), "hash=%s&interact_ref=ref-1", digest);
  wipe(&err);
  grant = iya_gnap_finish_redirect(client, query, allowed_wrong, 1, &err);
  CHECK(grant == NULL);
  CHECK(contains(err.message, "this browser"));
  CHECK(harness_url_count("/continue") == 0);
  snprintf(query, sizeof(query), "hash=nope&interact_ref=ref-1");
  wipe(&err);
  grant = iya_gnap_finish_redirect(client, query, allowed_real, 1, &err);
  CHECK(grant == NULL);
  CHECK(contains(err.message, "this browser"));
  iya_gnap_client_free(client);
  wipe(&err);
  return g_failures ? 1 : 0;
}

static int test_finish_rotate(void) {
  iya_gnap_error err;
  iya_gnap_client* client;
  iya_gnap_grant* done;
  iya_gnap_grant* rotated;
  char pending[256];
  char nonce[256];
  char digest[256];
  char cont[768];
  char body[65536];
  char method[32];
  const char* keys[] = {"hash", "interact_ref"};
  const char* values[2];
  const char* allowed[1];
  memset(&err, 0, sizeof(err));
  CHECK(harness_auth_start() == 0);
  harness_auth_reset();
  harness_set_too_fast(1);
  client = open_client("httpsig", &err);
  CHECK(client != NULL);
  CHECK(started(client, pending, sizeof(pending), nonce, sizeof(nonce), &err) == 0);
  CHECK(digest_for(nonce, "ref-1", digest, sizeof(digest), &err) == 0);
  values[0] = digest;
  values[1] = "ref-1";
  allowed[0] = pending;
  wipe(&err);
  done = iya_gnap_finish_redirect_pairs(client, keys, values, 2, allowed, 1, &err);
  if (done == NULL) fprintf(stderr, "finish: %s\n", err.message ? err.message : "");
  CHECK(done != NULL);
  CHECK(strcmp(iya_gnap_grant_access_token(done), "access-1") == 0);
  CHECK(iya_gnap_grant_bearer(done) == 0);
  CHECK(iya_gnap_grant_subject_sub(done) != NULL && strcmp(iya_gnap_grant_subject_sub(done), "user-1") == 0);
  CHECK(strcmp(iya_gnap_grant_subject_email(done), "user-1@example.com") == 0);
  CHECK(strcmp(iya_gnap_grant_subject_sid(done), "sess-1") == 0);
  CHECK(iya_gnap_grant_assertion_verified(done) == 1);
  CHECK(strcmp(iya_gnap_grant_id(done), "grant-9") == 0);
  CHECK(harness_too_fast_sent() == 1);
  CHECK(started(client, pending, sizeof(pending), nonce, sizeof(nonce), &err) == 0);
  snprintf(body, sizeof(body), "%s", harness_last_post_gnap_body());
  CHECK(contains(body, "\"client\":\"instance-1\""));
  snprintf(cont, sizeof(cont), "%s", iya_gnap_grant_continuation_uri(done));
  wipe(&err);
  rotated = iya_gnap_rotate(client, done, &err);
  if (rotated == NULL) fprintf(stderr, "rotate: %s\n", err.message ? err.message : "");
  CHECK(rotated != NULL);
  CHECK(strcmp(iya_gnap_grant_access_token(rotated), "access-2") == 0);
  CHECK(iya_gnap_grant_subject_sub(rotated) != NULL && strcmp(iya_gnap_grant_subject_sub(rotated), "user-1") == 0);
  CHECK(strcmp(iya_gnap_grant_continuation_uri(rotated), cont) == 0);
  wipe(&err);
  CHECK(iya_gnap_revoke(client, rotated, &err) == 0);
  snprintf(method, sizeof(method), "%s", harness_last_method());
  CHECK(strcmp(method, "DELETE") == 0);
  values[0] = digest;
  allowed[0] = pending;
  wipe(&err);
  CHECK(iya_gnap_finish_redirect_pairs(client, keys, values, 2, allowed, 1, &err) == NULL);
  CHECK(contains(err.message, "already used"));
  iya_gnap_grant_free(done);
  iya_gnap_grant_free(rotated);
  iya_gnap_client_free(client);
  wipe(&err);
  return g_failures ? 1 : 0;
}

static int test_proofs(void) {
  iya_gnap_error err;
  iya_gnap_client* client;
  iya_gnap_grant* done;
  char pending[256];
  char nonce[256];
  char digest[256];
  char query[1024];
  char body[65536];
  char push[1024];
  char url[768];
  char cert[512];
  char sig[32];
  char detached[32];
  char authz[128];
  const char* allowed[1];
  int status = 0;
  char* answer = NULL;
  memset(&err, 0, sizeof(err));
  CHECK(harness_auth_start() == 0);
  harness_auth_reset();
  client = open_client("jwsd", &err);
  CHECK(client != NULL);
  CHECK(started(client, pending, sizeof(pending), nonce, sizeof(nonce), &err) == 0);
  snprintf(body, sizeof(body), "%s", harness_last_post_gnap_body());
  CHECK(contains(body, "\"proof\":\"jwsd\""));
  CHECK(digest_for(nonce, "ref-j", digest, sizeof(digest), &err) == 0);
  snprintf(query, sizeof(query), "?hash=%s&interact_ref=ref-j", digest);
  allowed[0] = pending;
  wipe(&err);
  done = iya_gnap_finish_redirect(client, query, allowed, 1, &err);
  if (done == NULL) fprintf(stderr, "jwsd finish: %s\n", err.message ? err.message : "");
  CHECK(done != NULL);
  CHECK(iya_gnap_grant_subject_name(done) != NULL && strcmp(iya_gnap_grant_subject_name(done), "Ada") == 0);
  CHECK(harness_detached_contains_dot("/continue") == 1);
  snprintf(sig, sizeof(sig), "%s", harness_first("/continue", "signature"));
  CHECK(sig[0] == '\0');
  iya_gnap_grant_free(done);
  iya_gnap_client_free(client);
  harness_clear_seen();
  client = open_client("mtls", &err);
  CHECK(client != NULL);
  CHECK(started(client, pending, sizeof(pending), nonce, sizeof(nonce), &err) == 0);
  snprintf(body, sizeof(body), "%s", harness_last_post_gnap_body());
  CHECK(contains(body, "\"proof\":\"mtls\""));
  CHECK(pending[0] != '\0');
  snprintf(cert, sizeof(cert), "%s", harness_first("/gnap", "cert"));
  snprintf(sig, sizeof(sig), "%s", harness_first("/gnap", "signature"));
  snprintf(detached, sizeof(detached), "%s", harness_first("/gnap", "detached"));
  CHECK(strcmp(cert, harness_auth_fingerprint()) == 0);
  CHECK(sig[0] == '\0');
  CHECK(detached[0] == '\0');
  CHECK(digest_for(nonce, "ref-m", digest, sizeof(digest), &err) == 0);
  snprintf(push, sizeof(push), "{\"hash\":\"%s\",\"interact_ref\":\"ref-m\"}", digest);
  wipe(&err);
  done = iya_gnap_finish_push_json(client, push, &err);
  if (done == NULL) fprintf(stderr, "push: %s\n", err.message ? err.message : "");
  CHECK(done != NULL);
  CHECK(strcmp(iya_gnap_grant_access_token(done), "access-1") == 0);
  snprintf(url, sizeof(url), "%s/jwks", harness_auth_base());
  wipe(&err);
  CHECK(iya_gnap_call(client, done, "GET", url, &status, &answer, &err) == 0);
  CHECK(status == 200);
  snprintf(authz, sizeof(authz), "%s", harness_last_authorization());
  CHECK(strcmp(authz, "GNAP access-1") == 0);
  iya_gnap_free(answer);
  iya_gnap_grant_free(done);
  iya_gnap_client_free(client);
  wipe(&err);
  return g_failures ? 1 : 0;
}

static int test_bearer(void) {
  iya_gnap_error err;
  iya_gnap_client* client;
  iya_gnap_client* audience;
  iya_gnap_grant* grant;
  char pending[256];
  char nonce[256];
  char digest[256];
  char query[1024];
  const char* allowed[1];
  memset(&err, 0, sizeof(err));
  CHECK(harness_auth_start() == 0);
  harness_auth_reset();
  harness_set_bearer(1);
  client = open_client("httpsig", &err);
  CHECK(client != NULL);
  CHECK(started(client, pending, sizeof(pending), nonce, sizeof(nonce), &err) == 0);
  CHECK(digest_for(nonce, "ref-b", digest, sizeof(digest), &err) == 0);
  snprintf(query, sizeof(query), "hash=%s&interact_ref=ref-b", digest);
  allowed[0] = pending;
  wipe(&err);
  grant = iya_gnap_finish_redirect(client, query, allowed, 1, &err);
  CHECK(grant == NULL);
  CHECK(err.code != NULL && strcmp(err.code, "validation") == 0);
  CHECK(contains(err.message, "bearer"));
  harness_set_bearer(0);
  harness_set_aud("someone-else");
  audience = open_client("httpsig", &err);
  CHECK(audience != NULL);
  CHECK(started(audience, pending, sizeof(pending), nonce, sizeof(nonce), &err) == 0);
  CHECK(digest_for(nonce, "ref-a", digest, sizeof(digest), &err) == 0);
  snprintf(query, sizeof(query), "hash=%s&interact_ref=ref-a", digest);
  allowed[0] = pending;
  wipe(&err);
  grant = iya_gnap_finish_redirect(audience, query, allowed, 1, &err);
  CHECK(grant == NULL);
  CHECK(contains(err.message, "id_token is for"));
  harness_set_aud("gnap-caep-risc-demo");
  harness_set_iss_sub("other-user");
  harness_set_sub("user-1");
  CHECK(started(client, pending, sizeof(pending), nonce, sizeof(nonce), &err) == 0);
  CHECK(digest_for(nonce, "ref-s", digest, sizeof(digest), &err) == 0);
  snprintf(query, sizeof(query), "hash=%s&interact_ref=ref-s", digest);
  allowed[0] = pending;
  wipe(&err);
  grant = iya_gnap_finish_redirect(client, query, allowed, 1, &err);
  CHECK(grant == NULL);
  CHECK(contains(err.message, "somebody other"));
  iya_gnap_client_free(audience);
  iya_gnap_client_free(client);
  wipe(&err);
  return g_failures ? 1 : 0;
}

static double now_ms(void) {
  struct timespec ts;
  clock_gettime(CLOCK_REALTIME, &ts);
  return (double)ts.tv_sec * 1000.0 + (double)ts.tv_nsec / 1000000.0;
}

static int test_app_aud(void) {
  iya_gnap_error err;
  iya_gnap_client* client;
  iya_gnap_grant* done;
  iya_gnap_grant* fresh;
  iya_gnap_grant* held;
  char pending[256];
  char nonce[256];
  char digest[256];
  char query[1024];
  const char* allowed[1];
  memset(&err, 0, sizeof(err));
  CHECK(harness_auth_start() == 0);
  harness_auth_reset();
  harness_set_aud("gnap-caep-risc-demo");
  harness_set_sub("user-2");
  client = open_client("httpsig", &err);
  CHECK(client != NULL);
  CHECK(started(client, pending, sizeof(pending), nonce, sizeof(nonce), &err) == 0);
  CHECK(digest_for(nonce, "ref-app", digest, sizeof(digest), &err) == 0);
  snprintf(query, sizeof(query), "hash=%s&interact_ref=ref-app", digest);
  allowed[0] = pending;
  wipe(&err);
  done = iya_gnap_finish_redirect(client, query, allowed, 1, &err);
  if (done == NULL) fprintf(stderr, "app aud: %s\n", err.message ? err.message : "");
  CHECK(done != NULL);
  CHECK(iya_gnap_grant_subject_sub(done) != NULL && strcmp(iya_gnap_grant_subject_sub(done), "user-2") == 0);
  iya_gnap_grant_set_expires_at(done, now_ms() + 10000.0);
  wipe(&err);
  fresh = iya_gnap_ensure_fresh(client, done, &err);
  if (fresh == NULL) fprintf(stderr, "fresh: %s\n", err.message ? err.message : "");
  CHECK(fresh != NULL);
  CHECK(strcmp(iya_gnap_grant_access_token(fresh), "access-2") == 0);
  iya_gnap_grant_set_expires_at(fresh, now_ms() + 3600000.0);
  wipe(&err);
  held = iya_gnap_ensure_fresh(client, fresh, &err);
  CHECK(held != NULL);
  CHECK(strcmp(iya_gnap_grant_access_token(held), "access-2") == 0);
  iya_gnap_grant_free(done);
  iya_gnap_grant_free(fresh);
  iya_gnap_grant_free(held);
  iya_gnap_client_free(client);
  wipe(&err);
  return g_failures ? 1 : 0;
}

static int test_chain(void) {
  iya_gnap_error err;
  char* leaf_key = NULL;
  char* leaf_cert = NULL;
  char* leaf_fp = NULL;
  char* issuer_key = NULL;
  char* issuer_cert = NULL;
  char* issuer_fp = NULL;
  char* published = NULL;
  char* chain_out = NULL;
  char* fp = NULL;
  char* ek = NULL;
  char* ec = NULL;
  char* json = NULL;
  iya_gnap_client* client;
  size_t cap;
  int wrote;
  memset(&err, 0, sizeof(err));
  CHECK(iya_gnap_create_self_signed("leaf.example", NULL, 0, NULL, 0, &leaf_key, &leaf_cert, &leaf_fp, &err) == 0);
  wipe(&err);
  CHECK(iya_gnap_create_self_signed("issuer.example", NULL, 0, NULL, 0, &issuer_key, &issuer_cert, &issuer_fp, &err) == 0);
  cap = strlen(leaf_cert) + strlen(issuer_cert) + 8;
  {
    char* chain = (char*)malloc(cap);
    snprintf(chain, cap, "%s%s", leaf_cert, issuer_cert);
    wipe(&err);
    CHECK(iya_gnap_mtls_published_cert(leaf_key, chain, &published, &err) == 0);
    CHECK(count_text(published, "BEGIN CERTIFICATE") == 1);
    wipe(&err);
    CHECK(iya_gnap_cert_fingerprint(published, &fp, &err) == 0);
    CHECK(fp != NULL && leaf_fp != NULL && strcmp(fp, leaf_fp) == 0);
    wipe(&err);
    CHECK(iya_gnap_mtls_tls_chain(leaf_key, chain, &chain_out, &err) == 0);
    CHECK(count_text(chain_out, "BEGIN CERTIFICATE") == 2);
    ek = json_escape(leaf_key);
    ec = json_escape(chain);
    free(chain);
  }
  cap = strlen(ek) + strlen(ec) + 512;
  json = (char*)malloc(cap);
  wrote = snprintf(json, cap,
                   "{\"grantEndpoint\":\"https://as.example/gnap\",\"application\":\"chain-demo\","
                   "\"keyProof\":\"mtls\",\"privateKey\":\"%s\",\"certificate\":\"%s\","
                   "\"finishUri\":\"http://127.0.0.1:9/callback\"}",
                   ek, ec);
  CHECK(wrote > 0 && (size_t)wrote < cap);
  wipe(&err);
  client = iya_gnap_client_from_json(json, ".", &err);
  if (client == NULL) fprintf(stderr, "chain client: %s\n", err.message ? err.message : "");
  CHECK(client != NULL);
  iya_gnap_client_free(client);
  free(json);
  free(ek);
  free(ec);
  iya_gnap_free(published);
  iya_gnap_free(chain_out);
  iya_gnap_free(fp);
  iya_gnap_free(leaf_key);
  iya_gnap_free(leaf_cert);
  iya_gnap_free(leaf_fp);
  iya_gnap_free(issuer_key);
  iya_gnap_free(issuer_cert);
  iya_gnap_free(issuer_fp);
  wipe(&err);
  return g_failures ? 1 : 0;
}

static int person_has(const char* subject, const char* needle) {
  iya_gnap_error err;
  char* out = NULL;
  int ok;
  memset(&err, 0, sizeof(err));
  if (iya_gnap_person_json(subject, "https://as.example", &out, &err) != 0) {
    fprintf(stderr, "person: %s\n", err.message ? err.message : "");
    wipe(&err);
    return 0;
  }
  ok = contains(out, needle);
  if (!ok) fprintf(stderr, "person json %s\n", out ? out : "");
  iya_gnap_free(out);
  wipe(&err);
  return ok;
}

static int test_uid_account(void) {
  const char* subject =
      "{\"sub_ids\":[{\"format\":\"iss_sub\",\"iss\":\"https://as.example\",\"sub\":\"urn:uuid:abc\"},"
      "{\"format\":\"account\",\"uri\":\"acct:gnap-demo-user@localhost:8081\"}]}";
  CHECK(person_has(subject, "\"sub\":\"urn:uuid:abc\""));
  CHECK(person_has(subject, "\"iss\":\"https://as.example\""));
  CHECK(person_has(subject, "\"uid\":\"gnap-demo-user\""));
  return g_failures ? 1 : 0;
}

static int test_uid_percent(void) {
  const char* decoded = "{\"sub_ids\":[{\"format\":\"account\",\"uri\":\"acct:ada%20lovelace@idp.example\"}]}";
  const char* kept = "{\"sub_ids\":[{\"format\":\"account\",\"uri\":\"acct:%E0%A4%A@idp.example\"}]}";
  CHECK(person_has(decoded, "\"sub\":\"acct:ada%20lovelace@idp.example\""));
  CHECK(person_has(decoded, "\"uid\":\"ada lovelace\""));
  CHECK(person_has(kept, "\"uid\":\"%E0%A4%A\""));
  return g_failures ? 1 : 0;
}

static int test_uid_unset(void) {
  const char* subject = "{\"sub_ids\":[{\"format\":\"iss_sub\",\"iss\":\"https://as.example\",\"sub\":\"urn:uuid:abc\"}]}";
  CHECK(person_has(subject, "\"uid\":null"));
  CHECK(person_has(subject, "\"sub\":\"urn:uuid:abc\""));
  return g_failures ? 1 : 0;
}

static int test_set(void) {
  iya_gnap_error err;
  char good[8192];
  char bad[8192];
  char kid[8192];
  char none[8192];
  char jwks[8192];
  char* payload = NULL;
  const char* jwk;
  memset(&err, 0, sizeof(err));
  CHECK(harness_sign_rs256("{\"alg\":\"RS256\",\"kid\":\"k1\",\"typ\":\"secevent+jwt\"}", "{\"a\":1}", 0, good, sizeof(good)) == 0);
  jwk = harness_rsa_jwk();
  snprintf(jwks, sizeof(jwks), "{\"keys\":[%s]}", jwk);
  wipe(&err);
  CHECK(iya_gnap_verify_jws(good, jwks, &payload, &err) == 0);
  CHECK(contains(payload, "\"a\":1"));
  iya_gnap_free(payload);
  payload = NULL;
  CHECK(harness_sign_rs256("{\"alg\":\"RS256\",\"kid\":\"k1\",\"typ\":\"secevent+jwt\"}", "{\"a\":1}", 1, bad, sizeof(bad)) == 0);
  wipe(&err);
  CHECK(iya_gnap_verify_jws(bad, jwks, &payload, &err) != 0);
  CHECK(contains(err.message, "does not verify"));
  CHECK(harness_sign_rs256("{\"alg\":\"RS256\",\"kid\":\"nope\"}", "{\"a\":1}", 0, kid, sizeof(kid)) == 0);
  wipe(&err);
  CHECK(iya_gnap_verify_jws(kid, jwks, &payload, &err) != 0);
  CHECK(contains(err.message, "kid nope"));
  CHECK(harness_sign_rs256("{\"alg\":\"none\"}", "{\"a\":1}", 0, none, sizeof(none)) == 0);
  wipe(&err);
  CHECK(iya_gnap_verify_jws(none, jwks, &payload, &err) != 0);
  CHECK(contains(err.message, "does not verify"));
  wipe(&err);
  return g_failures ? 1 : 0;
}

static int test_subjects(void) {
  iya_gnap_error err;
  char* out = NULL;
  memset(&err, 0, sizeof(err));
  CHECK(strcmp(IYA_GNAP_EVENT_SESSION_REVOKED, "https://schemas.openid.net/secevent/caep/event-type/session-revoked") == 0);
  CHECK(strcmp(IYA_GNAP_EVENT_CREDENTIAL_COMPROMISE, "https://schemas.openid.net/secevent/risc/event-type/credential-compromise") == 0);
  CHECK(iya_gnap_subject_of("{\"format\":\"complex\",\"user\":{\"format\":\"iss_sub\",\"iss\":\"https://i\",\"sub\":\"urn:uuid:a\"},"
                            "\"session\":{\"format\":\"opaque\",\"id\":\"S1\"}}",
                            "https://i", &out, &err) == 0);
  CHECK(out != NULL && strcmp(out, "{\"idp_session\":\"S1\",\"person\":\"urn:uuid:a\"}") == 0);
  iya_gnap_free(out);
  out = NULL;
  wipe(&err);
  CHECK(iya_gnap_subject_of("{\"format\":\"iss_sub\",\"iss\":\"https://other\",\"sub\":\"urn:uuid:a\"}", "https://i", &out, &err) == 0);
  CHECK(out != NULL && strcmp(out, "{}") == 0);
  iya_gnap_free(out);
  out = NULL;
  wipe(&err);
  CHECK(iya_gnap_subject_of("{\"format\":\"email\",\"email\":\"A@x.com\"}", "https://i", &out, &err) == 0);
  CHECK(out != NULL && strcmp(out, "{\"email\":\"A@x.com\"}") == 0);
  iya_gnap_free(out);
  wipe(&err);
  return g_failures ? 1 : 0;
}

enum { kRec = 48, kBody = 12288 };

static pthread_mutex_t rec_mu = PTHREAD_MUTEX_INITIALIZER;
static char rec_method[kRec][16];
static char rec_url[kRec][768];
static char rec_body[kRec][kBody];
static int rec_n;
static char seen_type[8][320];
static int seen_ended[8];
static int seen_n;
static char ended_id[8][64];
static int ended_count[8];
static int ended_n;

static void reset_rec(void) {
  pthread_mutex_lock(&rec_mu);
  rec_n = 0;
  seen_n = 0;
  ended_n = 0;
  pthread_mutex_unlock(&rec_mu);
}

static char* poll_headers(const char* method, const char* url, const char* body, void* user) {
  const char* literal = "{\"authorization\":\"GNAP app-token\"}";
  char* out;
  (void)user;
  pthread_mutex_lock(&rec_mu);
  if (rec_n < kRec) {
    snprintf(rec_method[rec_n], sizeof(rec_method[rec_n]), "%s", method ? method : "");
    snprintf(rec_url[rec_n], sizeof(rec_url[rec_n]), "%s", url ? url : "");
    snprintf(rec_body[rec_n], kBody, "%s", body ? body : "");
    rec_n++;
  }
  pthread_mutex_unlock(&rec_mu);
  out = (char*)malloc(strlen(literal) + 1);
  memcpy(out, literal, strlen(literal) + 1);
  return out;
}

static void on_end(const char* const* ids, size_t count, void* user) {
  (void)user;
  pthread_mutex_lock(&rec_mu);
  if (ended_n < 8) {
    ended_count[ended_n] = (int)count;
    if (count > 0 && ids != NULL && ids[0] != NULL) snprintf(ended_id[ended_n], sizeof(ended_id[ended_n]), "%s", ids[0]);
    else ended_id[ended_n][0] = '\0';
    ended_n++;
  }
  pthread_mutex_unlock(&rec_mu);
}

static void on_event(const char* type, int ended, void* user) {
  (void)user;
  pthread_mutex_lock(&rec_mu);
  if (seen_n < 8) {
    snprintf(seen_type[seen_n], sizeof(seen_type[seen_n]), "%s", type ? type : "");
    seen_ended[seen_n] = ended;
    seen_n++;
  }
  pthread_mutex_unlock(&rec_mu);
}

static int test_poll(void) {
  iya_gnap_error err;
  iya_gnap_receiver* receiver;
  char base[256];
  char sub[1024];
  char revoked[128];
  char changed[128];
  char bad[128];
  char authz[128];
  char stream[64];
  char first_ack[128];
  char err_text[64];
  char create_body[kBody];
  char poll_body[kBody];
  char poll_method[16];
  int i;
  int revoked_count = 0;
  int nack;
  memset(&err, 0, sizeof(err));
  reset_rec();
  CHECK(harness_tx_start() == 0);
  snprintf(base, sizeof(base), "%s", harness_tx_base());
  wipe(&err);
  receiver = iya_gnap_receiver_new(base, on_end, NULL, poll_headers, NULL, 60000, &err);
  if (receiver == NULL) fprintf(stderr, "receiver: %s\n", err.message ? err.message : "");
  CHECK(receiver != NULL);
  wipe(&err);
  CHECK(iya_gnap_receiver_on(receiver, "*", on_event, NULL, &err) == 0);
  wipe(&err);
  CHECK(iya_gnap_receiver_start(receiver, &err) == 0);
  iya_gnap_receiver_stop(receiver);
  snprintf(authz, sizeof(authz), "%s", harness_tx_authorization());
  snprintf(stream, sizeof(stream), "%s", iya_gnap_receiver_stream_id(receiver) ? iya_gnap_receiver_stream_id(receiver) : "");
  CHECK(harness_tx_streams() == 1);
  CHECK(strcmp(authz, "GNAP app-token") == 0);
  CHECK(strcmp(stream, "s1") == 0);
  create_body[0] = '\0';
  pthread_mutex_lock(&rec_mu);
  for (i = 0; i < rec_n; i++) {
    size_t len = strlen(rec_url[i]);
    if (strcmp(rec_method[i], "POST") == 0 && len >= 11 && strcmp(rec_url[i] + len - 11, "/ssf/stream") == 0) {
      snprintf(create_body, sizeof(create_body), "%s", rec_body[i]);
    }
  }
  pthread_mutex_unlock(&rec_mu);
  CHECK(contains(create_body, "\"delivery\""));
  wipe(&err);
  CHECK(iya_gnap_receiver_track(receiver, "L-a1", "urn:uuid:alice", "alice@example.com", "IDP-A1", &err) == 0);
  CHECK(iya_gnap_receiver_track(receiver, "L-a2", "urn:uuid:alice", "alice@example.com", "IDP-A2", &err) == 0);
  CHECK(iya_gnap_receiver_track(receiver, "L-b1", "urn:uuid:bob", "bob@example.com", "IDP-B1", &err) == 0);
  snprintf(sub, sizeof(sub),
           "{\"format\":\"complex\",\"user\":{\"format\":\"iss_sub\",\"iss\":\"%s\",\"sub\":\"urn:uuid:alice\"},"
           "\"session\":{\"format\":\"opaque\",\"id\":\"IDP-A1\"}}",
           base);
  harness_tx_deliver(IYA_GNAP_EVENT_SESSION_REVOKED, sub, 0, revoked, sizeof(revoked));
  snprintf(sub, sizeof(sub), "{\"format\":\"iss_sub\",\"iss\":\"%s\",\"sub\":\"urn:uuid:bob\"}", base);
  harness_tx_deliver(IYA_GNAP_EVENT_CREDENTIAL_CHANGE, sub, 0, changed, sizeof(changed));
  wipe(&err);
  CHECK(iya_gnap_receiver_poll(receiver, &err) == 0);
  CHECK(ended_n == 1);
  CHECK(ended_count[0] == 1);
  CHECK(strcmp(ended_id[0], "L-a1") == 0);
  CHECK(seen_n == 2);
  CHECK(seen_ended[0] == 1);
  CHECK(strcmp(seen_type[1], IYA_GNAP_EVENT_CREDENTIAL_CHANGE) == 0);
  CHECK(seen_ended[1] == 0);
  poll_method[0] = '\0';
  poll_body[0] = '\0';
  pthread_mutex_lock(&rec_mu);
  for (i = 0; i < rec_n; i++) {
    if (strstr(rec_url[i], "/ssf/poll/") != NULL) {
      snprintf(poll_method, sizeof(poll_method), "%s", rec_method[i]);
      snprintf(poll_body, sizeof(poll_body), "%s", rec_body[i]);
      break;
    }
  }
  pthread_mutex_unlock(&rec_mu);
  CHECK(strcmp(poll_method, "POST") == 0);
  CHECK(contains(poll_body, "maxEvents"));
  wipe(&err);
  CHECK(iya_gnap_receiver_poll(receiver, &err) == 0);
  nack = harness_tx_acked_count();
  snprintf(first_ack, sizeof(first_ack), "%s", harness_tx_acked_at(0));
  CHECK(nack > 0);
  CHECK(strcmp(first_ack, revoked) == 0);
  for (i = 0; i < nack; i++) {
    char item[128];
    snprintf(item, sizeof(item), "%s", harness_tx_acked_at(i));
    if (strcmp(item, revoked) == 0) revoked_count++;
  }
  CHECK(revoked_count == 1);
  harness_tx_deliver(IYA_GNAP_EVENT_ACCOUNT_DISABLED, "{\"format\":\"email\",\"email\":\"alice@example.com\"}", 1, bad, sizeof(bad));
  wipe(&err);
  CHECK(iya_gnap_receiver_poll(receiver, &err) == 0);
  wipe(&err);
  CHECK(iya_gnap_receiver_poll(receiver, &err) == 0);
  snprintf(err_text, sizeof(err_text), "%s", harness_tx_err(bad));
  CHECK(strcmp(err_text, "invalid_key") == 0);
  wipe(&err);
  CHECK(iya_gnap_receiver_verify(receiver, "abc", &err) == 0);
  iya_gnap_receiver_stop(receiver);
  iya_gnap_receiver_free(receiver);
  wipe(&err);
  return g_failures ? 1 : 0;
}

int main(int argc, char** argv) {
  const char* name;
  int rc = 2;
  if (argc < 2) return 2;
  name = argv[1];
  g_failures = 0;
  if (strcmp(name, "TestDefaultsAccessAndFillsTransmitter") == 0) rc = test_defaults();
  else if (strcmp(name, "TestDropsSSFRightsAndTransmitterWhenSignalsIsFalse") == 0) rc = test_drops();
  else if (strcmp(name, "TestRefusesSignalsOffWhenSSFRightsWereTheOnlyOnes") == 0) rc = test_refuses_only();
  else if (strcmp(name, "TestRefusesASignalsValueThatIsNotTrueOrFalse") == 0) rc = test_refuses_value();
  else if (strcmp(name, "TestInteractionHashVector") == 0) rc = test_hash();
  else if (strcmp(name, "TestRefusesFrontChannelForeignAndAHashThatIsNotOurs") == 0) rc = test_front();
  else if (strcmp(name, "TestFinishesARedirectChecksTheIDTokenAndRotates") == 0) rc = test_finish_rotate();
  else if (strcmp(name, "TestProvesTheKeyWithDetachedJWSAndMutualTLS") == 0) rc = test_proofs();
  else if (strcmp(name, "TestRefusesBearerBadAudienceAndASubjectThatDoesNotMatch") == 0) rc = test_bearer();
  else if (strcmp(name, "TestAcceptsTheApplicationIdentifierAsTheIDTokenAudience") == 0) rc = test_app_aud();
  else if (strcmp(name, "TestCertificateChainPutsTheLeafInTheKeyAndTheChainOnTLS") == 0) rc = test_chain();
  else if (strcmp(name, "TestUIDFromAccountKeepsTheProtocolSubject") == 0) rc = test_uid_account();
  else if (strcmp(name, "TestPercentDecodesTheUserPartAndKeepsInvalidEncoding") == 0) rc = test_uid_percent();
  else if (strcmp(name, "TestUIDStaysUnsetWithoutAnAccountIdentifier") == 0) rc = test_uid_unset();
  else if (strcmp(name, "TestVerifiesASETAndRefusesAnotherKey") == 0) rc = test_set();
  else if (strcmp(name, "TestReadsSubjectForms") == 0) rc = test_subjects();
  else if (strcmp(name, "TestPollsWithTheGNAPTokenAndAcknowledges") == 0) rc = test_poll();
  harness_auth_stop();
  harness_tx_stop();
  if (g_failures != 0) return 1;
  return rc;
}
