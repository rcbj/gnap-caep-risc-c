// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

#include "http.hpp"

#include "url.hpp"
#include "util.hpp"

#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <memory>
#include <sstream>
#include <vector>

namespace iya::gnap {
namespace {

constexpr size_t kMaxBytes = 2 * 1024 * 1024;
constexpr int kTimeoutSec = 15;

struct AddrInfoFree {
  void operator()(addrinfo* info) const { freeaddrinfo(info); }
};
struct SslCtxFree {
  void operator()(SSL_CTX* ctx) const { SSL_CTX_free(ctx); }
};
struct SslFree {
  void operator()(SSL* ssl) const { SSL_free(ssl); }
};

class Fd {
 public:
  explicit Fd(int fd = -1) : fd_(fd) {}
  ~Fd() {
    if (fd_ >= 0) close(fd_);
  }
  Fd(const Fd&) = delete;
  Fd& operator=(const Fd&) = delete;
  Fd(Fd&& other) noexcept : fd_(other.fd_) { other.fd_ = -1; }
  Fd& operator=(Fd&& other) noexcept {
    if (this != &other) {
      if (fd_ >= 0) close(fd_);
      fd_ = other.fd_;
      other.fd_ = -1;
    }
    return *this;
  }
  int get() const { return fd_; }
  int release() {
    int value = fd_;
    fd_ = -1;
    return value;
  }

 private:
  int fd_;
};

void set_timeouts(int fd) {
  timeval tv{};
  tv.tv_sec = kTimeoutSec;
  setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
  setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
}

bool timed_out(int err) { return err == EAGAIN || err == EWOULDBLOCK || err == ETIMEDOUT; }

void send_all(int fd, SSL* ssl, const std::string& data, const std::string& url, const std::string& code) {
  size_t sent = 0;
  while (sent < data.size()) {
    int n = 0;
    if (ssl != nullptr) {
      n = SSL_write(ssl, data.data() + sent, static_cast<int>(data.size() - sent));
      if (n <= 0) {
        int err = SSL_get_error(ssl, n);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE || timed_out(errno)) {
          throw Error(code, url + " did not answer within 15 s");
        }
        throw Error(code, url + ": TLS write failed");
      }
    } else {
      n = static_cast<int>(::send(fd, data.data() + sent, data.size() - sent, MSG_NOSIGNAL));
      if (n < 0) {
        if (timed_out(errno)) throw Error(code, url + " did not answer within 15 s");
        throw Error(code, url + ": " + std::strerror(errno));
      }
    }
    sent += static_cast<size_t>(n);
  }
}

std::string recv_some(int fd, SSL* ssl, bool& closed, bool& timeout, const std::string& url, const std::string& code) {
  char buf[8192];
  closed = false;
  timeout = false;
  int n = 0;
  if (ssl != nullptr) {
    n = SSL_read(ssl, buf, sizeof(buf));
    if (n <= 0) {
      int err = SSL_get_error(ssl, n);
      if (err == SSL_ERROR_ZERO_RETURN) {
        closed = true;
        return "";
      }
      if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE || timed_out(errno)) {
        timeout = true;
        return "";
      }
      if (n == 0) {
        closed = true;
        return "";
      }
      throw Error(code, url + ": TLS read failed");
    }
  } else {
    n = static_cast<int>(::recv(fd, buf, sizeof(buf), 0));
    if (n == 0) {
      closed = true;
      return "";
    }
    if (n < 0) {
      if (timed_out(errno)) {
        timeout = true;
        return "";
      }
      throw Error(code, url + ": " + std::strerror(errno));
    }
  }
  return std::string(buf, static_cast<size_t>(n));
}

std::vector<unsigned char> der_of(X509* cert) {
  int len = i2d_X509(cert, nullptr);
  std::vector<unsigned char> out(static_cast<size_t>(len));
  unsigned char* p = out.data();
  i2d_X509(cert, &p);
  return out;
}

bool same_der(X509* a, X509* b) {
  auto left = der_of(a);
  auto right = der_of(b);
  if (left.size() != right.size()) return false;
  return CRYPTO_memcmp(left.data(), right.data(), left.size()) == 0;
}

bool host_matches(X509* cert, const std::string& host) {
  in_addr ipv4{};
  in6_addr ipv6{};
  if (inet_pton(AF_INET, host.c_str(), &ipv4) == 1) return X509_check_ip_asc(cert, host.c_str(), 0) == 1;
  if (inet_pton(AF_INET6, host.c_str(), &ipv6) == 1) return X509_check_ip_asc(cert, host.c_str(), 0) == 1;
  return X509_check_host(cert, host.c_str(), host.size(), 0, nullptr) == 1;
}

std::vector<X509*> pinned_certs(const std::string& pem) {
  std::vector<X509*> out;
  BIO* bio = BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size()));
  if (bio == nullptr) return out;
  while (true) {
    X509* cert = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
    if (cert == nullptr) break;
    out.push_back(cert);
  }
  BIO_free(bio);
  ERR_clear_error();
  return out;
}

void verify_pinned(SSL* ssl, const std::string& ca_pem, const std::string& host, const std::string& url,
                   const std::string& code) {
  X509* leaf = SSL_get1_peer_certificate(ssl);
  if (leaf == nullptr) throw Error(code, url + ": no certificate");
  STACK_OF(X509)* chain = SSL_get_peer_cert_chain(ssl);
  auto pinned = pinned_certs(ca_pem);
  if (pinned.empty()) {
    X509_free(leaf);
    throw Error(code, url + ": no certificate");
  }
  X509_STORE* store = X509_STORE_new();
  for (X509* cert : pinned) X509_STORE_add_cert(store, cert);
  X509_STORE_CTX* ctx = X509_STORE_CTX_new();
  STACK_OF(X509)* untrusted = sk_X509_new_null();
  if (chain != nullptr) {
    for (int i = 0; i < sk_X509_num(chain); i++) {
      X509* item = sk_X509_value(chain, i);
      if (!same_der(item, leaf)) sk_X509_push(untrusted, X509_dup(item));
    }
  }
  X509_STORE_CTX_init(ctx, store, leaf, untrusted);
  X509_VERIFY_PARAM* param = X509_STORE_CTX_get0_param(ctx);
  in_addr ipv4{};
  in6_addr ipv6{};
  if (inet_pton(AF_INET, host.c_str(), &ipv4) == 1 || inet_pton(AF_INET6, host.c_str(), &ipv6) == 1) {
    X509_VERIFY_PARAM_set1_ip_asc(param, host.c_str());
  } else {
    X509_VERIFY_PARAM_set1_host(param, host.c_str(), 0);
  }
  bool verified = X509_verify_cert(ctx) == 1;
  X509_STORE_CTX_free(ctx);
  sk_X509_pop_free(untrusted, X509_free);
  if (!verified) {
    bool raw_match = false;
    for (X509* cert : pinned) {
      if (same_der(cert, leaf)) {
        raw_match = true;
        break;
      }
    }
    if (raw_match) {
      if (!host_matches(leaf, host)) {
        X509_free(leaf);
        for (X509* cert : pinned) X509_free(cert);
        X509_STORE_free(store);
        throw Error(code, url + ": certificate name does not match");
      }
    } else {
      X509_STORE* bare = X509_STORE_new();
      for (X509* cert : pinned) X509_STORE_add_cert(bare, cert);
      X509_STORE_CTX* again = X509_STORE_CTX_new();
      STACK_OF(X509)* extra = sk_X509_new_null();
      if (chain != nullptr) {
        for (int i = 0; i < sk_X509_num(chain); i++) {
          X509* item = sk_X509_value(chain, i);
          if (!same_der(item, leaf)) sk_X509_push(extra, X509_dup(item));
        }
      }
      X509_STORE_CTX_init(again, bare, leaf, extra);
      bool chain_ok = X509_verify_cert(again) == 1;
      X509_STORE_CTX_free(again);
      sk_X509_pop_free(extra, X509_free);
      X509_STORE_free(bare);
      if (!chain_ok || !host_matches(leaf, host)) {
        X509_free(leaf);
        for (X509* cert : pinned) X509_free(cert);
        X509_STORE_free(store);
        throw Error(code, url + ": certificate verify failed");
      }
    }
  }
  X509_free(leaf);
  for (X509* cert : pinned) X509_free(cert);
  X509_STORE_free(store);
}

void use_client_cert(SSL* ssl, const TlsOpt& tls, const std::string& url, const std::string& code) {
  if (tls.cert.empty() || tls.key.empty()) return;
  BIO* cert_bio = BIO_new_mem_buf(tls.cert.data(), static_cast<int>(tls.cert.size()));
  X509* leaf = PEM_read_bio_X509(cert_bio, nullptr, nullptr, nullptr);
  if (leaf == nullptr || SSL_use_certificate(ssl, leaf) != 1) {
    X509_free(leaf);
    BIO_free(cert_bio);
    throw Error(code, url + ": the client certificate could not be read");
  }
  X509_free(leaf);
  while (true) {
    X509* extra = PEM_read_bio_X509(cert_bio, nullptr, nullptr, nullptr);
    if (extra == nullptr) break;
    SSL_add1_chain_cert(ssl, extra);
    X509_free(extra);
  }
  BIO_free(cert_bio);
  ERR_clear_error();
  BIO* key_bio = BIO_new_mem_buf(tls.key.data(), static_cast<int>(tls.key.size()));
  EVP_PKEY* key = PEM_read_bio_PrivateKey(key_bio, nullptr, nullptr, nullptr);
  BIO_free(key_bio);
  if (key == nullptr || SSL_use_PrivateKey(ssl, key) != 1) {
    EVP_PKEY_free(key);
    throw Error(code, url + ": the client key could not be read");
  }
  EVP_PKEY_free(key);
}

std::string header_value(const std::string& headers, const std::string& name) {
  std::string want = name;
  for (char& c : want)
    if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
  size_t at = 0;
  while (at < headers.size()) {
    auto end = headers.find("\r\n", at);
    if (end == std::string::npos) end = headers.size();
    std::string line = headers.substr(at, end - at);
    auto colon = line.find(':');
    if (colon != std::string::npos) {
      std::string key = line.substr(0, colon);
      for (char& c : key)
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
      if (key == want) return trim_copy(line.substr(colon + 1));
    }
    if (end == headers.size()) break;
    at = end + 2;
  }
  return "";
}

}  // namespace

Answer http_send(const std::string& url, const std::string& method, const std::map<std::string, std::string>& headers,
                 const std::string* body, const TlsOpt& tls, const std::string& code) {
  Url parsed;
  if (!parse_absolute(url, parsed)) throw Error(code, url + " is not an http(s) URL");
  std::string host = parsed.host;
  std::string port = parsed.port.empty() ? (parsed.scheme == "https" ? "443" : "80") : parsed.port;
  addrinfo hints{};
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_family = AF_UNSPEC;
  addrinfo* raw = nullptr;
  if (getaddrinfo(host.c_str(), port.c_str(), &hints, &raw) != 0 || raw == nullptr) {
    throw Error(code, url + ": name lookup failed");
  }
  std::unique_ptr<addrinfo, AddrInfoFree> info(raw);
  Fd fd;
  for (addrinfo* it = info.get(); it != nullptr; it = it->ai_next) {
    int sock = ::socket(it->ai_family, it->ai_socktype, it->ai_protocol);
    if (sock < 0) continue;
    set_timeouts(sock);
    if (::connect(sock, it->ai_addr, it->ai_addrlen) == 0) {
      fd = Fd(sock);
      break;
    }
    close(sock);
  }
  if (fd.get() < 0) throw Error(code, url + ": connection failed");
  std::unique_ptr<SSL_CTX, SslCtxFree> ctx;
  std::unique_ptr<SSL, SslFree> ssl;
  if (parsed.scheme == "https") {
    ctx.reset(SSL_CTX_new(TLS_client_method()));
    if (!ctx) throw Error(code, url + ": TLS failed");
    SSL_CTX_set_min_proto_version(ctx.get(), TLS1_2_VERSION);
    unsigned char alpn[] = {8, 'h', 't', 't', 'p', '/', '1', '.', '1'};
    SSL_CTX_set_alpn_protos(ctx.get(), alpn, sizeof(alpn));
    if (tls.insecure) {
      SSL_CTX_set_verify(ctx.get(), SSL_VERIFY_NONE, nullptr);
    } else if (tls.ca.empty()) {
      SSL_CTX_set_default_verify_paths(ctx.get());
      SSL_CTX_set_verify(ctx.get(), SSL_VERIFY_PEER, nullptr);
    } else {
      SSL_CTX_set_verify(ctx.get(), SSL_VERIFY_NONE, nullptr);
    }
    ssl.reset(SSL_new(ctx.get()));
    SSL_set_fd(ssl.get(), fd.get());
    in_addr ipv4{};
    in6_addr ipv6{};
    bool ip_literal = inet_pton(AF_INET, host.c_str(), &ipv4) == 1 || inet_pton(AF_INET6, host.c_str(), &ipv6) == 1;
    // RFC 6066 sends no server name for an IP literal.
    if (!ip_literal) SSL_set_tlsext_host_name(ssl.get(), host.c_str());
    if (!tls.insecure && tls.ca.empty()) {
      // The system roots: a chain to one of them is not enough on its own. The certificate must
      // also name the host in the URL, a DNS name against a DNS SAN and an IP literal against an
      // IP SAN. With tlsCa set, verify_pinned checks the name.
      bool named = false;
      if (ip_literal) {
        named = X509_VERIFY_PARAM_set1_ip_asc(SSL_get0_param(ssl.get()), host.c_str()) == 1;
      } else {
        SSL_set_hostflags(ssl.get(), X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
        named = SSL_set1_host(ssl.get(), host.c_str()) == 1;
      }
      if (!named) throw Error(code, url + ": cannot check the host name " + host);
    }
    use_client_cert(ssl.get(), tls, url, code);
    if (SSL_connect(ssl.get()) != 1) {
      if (timed_out(errno)) throw Error(code, url + " did not answer within 15 s");
      throw Error(code, url + ": TLS handshake failed");
    }
    if (!tls.insecure && !tls.ca.empty()) verify_pinned(ssl.get(), tls.ca, host, url, code);
    if (!tls.insecure && tls.ca.empty()) {
      long verify = SSL_get_verify_result(ssl.get());
      if (verify != X509_V_OK) throw Error(code, url + ": certificate verify failed");
    }
  }
  std::string path = parsed.path.empty() ? "/" : parsed.path;
  if (!parsed.query.empty()) path += "?" + parsed.query;
  std::ostringstream request;
  request << method << " " << path << " HTTP/1.1\r\n";
  request << "Host: " << hostport_of(parsed) << "\r\n";
  request << "Connection: close\r\n";
  for (const auto& item : headers) {
    std::string name = item.first;
    if (name == "host" || name == "Host" || name == "connection" || name == "Connection" || name == "content-length" ||
        name == "Content-Length") {
      continue;
    }
    request << item.first << ": " << item.second << "\r\n";
  }
  if (body != nullptr) request << "Content-Length: " << body->size() << "\r\n";
  request << "\r\n";
  if (body != nullptr) request << *body;
  send_all(fd.get(), ssl.get(), request.str(), url, code);
  std::string inbound;
  bool saw_timeout = false;
  while (inbound.size() <= kMaxBytes + 1) {
    bool closed = false;
    bool timeout = false;
    std::string chunk = recv_some(fd.get(), ssl.get(), closed, timeout, url, code);
    if (timeout) {
      saw_timeout = true;
      break;
    }
    if (closed) break;
    inbound += chunk;
  }
  if (inbound.size() > kMaxBytes) throw Error(code, url + " answered more than " + std::to_string(kMaxBytes) + " bytes");
  auto split = inbound.find("\r\n\r\n");
  if (split == std::string::npos) {
    if (saw_timeout) throw Error(code, url + " did not answer within 15 s");
    throw Error(code, url + ": the response was incomplete");
  }
  std::string head = inbound.substr(0, split);
  std::string rest = inbound.substr(split + 4);
  auto line_end = head.find("\r\n");
  std::string status_line = line_end == std::string::npos ? head : head.substr(0, line_end);
  std::string header_block = line_end == std::string::npos ? "" : head.substr(line_end + 2);
  int status = 0;
  auto first_space = status_line.find(' ');
  if (first_space != std::string::npos) status = std::atoi(status_line.c_str() + first_space + 1);
  std::string length_text = header_value(header_block, "content-length");
  std::string transfer = header_value(header_block, "transfer-encoding");
  std::string body_out = rest;
  if (!length_text.empty()) {
    long need = std::strtol(length_text.c_str(), nullptr, 10);
    if (need < 0) need = 0;
    while (static_cast<long>(body_out.size()) < need) {
      bool closed = false;
      bool timeout = false;
      std::string chunk = recv_some(fd.get(), ssl.get(), closed, timeout, url, code);
      if (timeout) throw Error(code, url + " did not answer within 15 s");
      if (closed) break;
      body_out += chunk;
      if (body_out.size() > kMaxBytes) throw Error(code, url + " answered more than " + std::to_string(kMaxBytes) + " bytes");
    }
    if (static_cast<long>(body_out.size()) > need) body_out.resize(static_cast<size_t>(need));
  } else if (transfer.find("chunked") != std::string::npos) {
    std::string decoded;
    std::string pending = body_out;
    while (true) {
      auto nl = pending.find("\r\n");
      while (nl == std::string::npos) {
        bool closed = false;
        bool timeout = false;
        std::string chunk = recv_some(fd.get(), ssl.get(), closed, timeout, url, code);
        if (timeout) throw Error(code, url + " did not answer within 15 s");
        if (closed) throw Error(code, url + ": the response was incomplete");
        pending += chunk;
        nl = pending.find("\r\n");
      }
      long size = std::strtol(pending.substr(0, nl).c_str(), nullptr, 16);
      pending = pending.substr(nl + 2);
      if (size == 0) break;
      while (static_cast<long>(pending.size()) < size + 2) {
        bool closed = false;
        bool timeout = false;
        std::string chunk = recv_some(fd.get(), ssl.get(), closed, timeout, url, code);
        if (timeout) throw Error(code, url + " did not answer within 15 s");
        if (closed) throw Error(code, url + ": the response was incomplete");
        pending += chunk;
      }
      decoded.append(pending, 0, static_cast<size_t>(size));
      pending = pending.substr(static_cast<size_t>(size + 2));
      if (decoded.size() > kMaxBytes) throw Error(code, url + " answered more than " + std::to_string(kMaxBytes) + " bytes");
    }
    body_out = decoded;
  } else if (saw_timeout && body_out.empty()) {
    throw Error(code, url + " did not answer within 15 s");
  }
  if (body_out.size() > kMaxBytes) throw Error(code, url + " answered more than " + std::to_string(kMaxBytes) + " bytes");
  Answer answer;
  answer.status = status;
  answer.content_type = header_value(header_block, "content-type");
  answer.body = body_out;
  return answer;
}

}  // namespace iya::gnap
