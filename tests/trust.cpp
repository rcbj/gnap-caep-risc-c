// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

// tlsCa is iya-sts's listener CA trust chain. These tests serve HTTPS from a
// four-certificate chain shaped like iya-sts's (Root, Intermediate, TLS Issuing
// CA, leaf with DNS and IP SANs), presented whole in the handshake and published
// at GET /tls/server-certificate, and call the library's one HTTP client
// (http_send, which the grant client and the Shared Signals receiver both use).
//
// - The whole chain file is the trust store: the path ends at the self-signed
//   Root. A file holding exactly the presented leaf pins it. Another root is refused.
// - A forged leaf followed by the real (public) CA certificates is refused.
// - The host name is verified, with tlsCa and with the system roots (no tlsCa):
//   a leaf that chains to a trusted root but does not name the host is refused;
//   127.0.0.1 matches an IP SAN only.
// - The mtls proof presents the registered self-signed certificate even when the
//   CertificateRequest names only the server's own CA, as iya-sts's does.
// - scripts/trust_chain.py, which scripts/configure_iya_sts.py calls, writes the
//   whole chain to the file tlsCa names, from GET /tls/server-certificate and,
//   when that is missing, from the handshake; the library trusts that file.

#include "http.hpp"
#include "iya/gnap.hpp"

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#include <atomic>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

namespace {

using iya::gnap::TlsOpt;

int fail(const std::string& message) {
  std::fprintf(stderr, "FAIL: %s\n", message.c_str());
  return 1;
}

EVP_PKEY* rsa_key() { return EVP_RSA_gen(2048); }

bool add_ext(X509* cert, X509* issuer, int nid, const char* value) {
  X509V3_CTX ctx;
  X509V3_set_ctx_nodb(&ctx);
  X509V3_set_ctx(&ctx, issuer, cert, nullptr, nullptr, 0);
  X509_EXTENSION* ext = X509V3_EXT_conf_nid(nullptr, &ctx, nid, value);
  if (ext == nullptr) return false;
  X509_add_ext(cert, ext, -1);
  X509_EXTENSION_free(ext);
  return true;
}

// issuer null: self-signed. san null: a CA.
X509* make_cert(const char* cn, EVP_PKEY* key, X509* issuer, EVP_PKEY* issuer_key, const char* san, long serial) {
  X509* cert = X509_new();
  X509_set_version(cert, 2);
  ASN1_INTEGER_set(X509_get_serialNumber(cert), serial);
  X509_gmtime_adj(X509_getm_notBefore(cert), -3600);
  X509_gmtime_adj(X509_getm_notAfter(cert), 86400);
  X509_set_pubkey(cert, key);
  X509_NAME* name = X509_get_subject_name(cert);
  X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, reinterpret_cast<const unsigned char*>(cn), -1, -1, 0);
  X509* signer = issuer != nullptr ? issuer : cert;
  X509_set_issuer_name(cert, X509_get_subject_name(signer));
  bool ok = true;
  if (san != nullptr) {
    ok &= add_ext(cert, signer, NID_basic_constraints, "critical,CA:FALSE");
    ok &= add_ext(cert, signer, NID_key_usage, "critical,digitalSignature,keyEncipherment");
    ok &= add_ext(cert, signer, NID_ext_key_usage, "serverAuth");
    ok &= add_ext(cert, signer, NID_subject_alt_name, san);
  } else {
    ok &= add_ext(cert, signer, NID_basic_constraints, "critical,CA:TRUE");
    ok &= add_ext(cert, signer, NID_key_usage, "critical,keyCertSign,cRLSign");
  }
  ok &= add_ext(cert, signer, NID_subject_key_identifier, "hash");
  if (!ok || X509_sign(cert, issuer_key != nullptr ? issuer_key : key, EVP_sha256()) == 0) {
    X509_free(cert);
    return nullptr;
  }
  return cert;
}

std::string pem_of(X509* cert) {
  BIO* bio = BIO_new(BIO_s_mem());
  PEM_write_bio_X509(bio, cert);
  char* data = nullptr;
  long n = BIO_get_mem_data(bio, &data);
  std::string out(data, static_cast<size_t>(n));
  BIO_free(bio);
  return out;
}

struct Chain {
  EVP_PKEY *root_key = nullptr, *mid_key = nullptr, *issuing_key = nullptr, *leaf_key = nullptr;
  X509 *root = nullptr, *mid = nullptr, *issuing = nullptr, *leaf = nullptr;
  std::string pem;  // leaf, TLS Issuing CA, Intermediate, Root: what iya-sts publishes
  std::string root_pem;
  std::string leaf_pem;
  std::string cas_pem;  // TLS Issuing CA, Intermediate, Root without the leaf
};

Chain* make_chain(const char* san) {
  auto* c = new Chain();
  c->root_key = rsa_key();
  c->mid_key = rsa_key();
  c->issuing_key = rsa_key();
  c->leaf_key = rsa_key();
  if (!c->root_key || !c->mid_key || !c->issuing_key || !c->leaf_key) return nullptr;
  c->root = make_cert("sts Root CA", c->root_key, nullptr, nullptr, nullptr, 1);
  c->mid = make_cert("sts Intermediate CA", c->mid_key, c->root, c->root_key, nullptr, 2);
  c->issuing = make_cert("sts TLS Issuing CA", c->issuing_key, c->mid, c->mid_key, nullptr, 3);
  c->leaf = make_cert("sts", c->leaf_key, c->issuing, c->issuing_key, san, 4);
  if (!c->root || !c->mid || !c->issuing || !c->leaf) return nullptr;
  c->leaf_pem = pem_of(c->leaf);
  c->root_pem = pem_of(c->root);
  c->cas_pem = pem_of(c->issuing) + pem_of(c->mid) + c->root_pem;
  c->pem = c->leaf_pem + c->cas_pem;
  return c;
}

class TlsServer {
 public:
  // leaf: the certificate the server presents; extra: the certificates after it in the handshake.
  // ask_client: request a client certificate, naming only this CA in the CertificateRequest.
  TlsServer(X509* leaf, EVP_PKEY* leaf_key, std::vector<X509*> extra, std::string published, bool publish,
            X509* ask_client = nullptr)
      : published_(std::move(published)), publish_(publish) {
    ctx_ = SSL_CTX_new(TLS_server_method());
    SSL_CTX_use_certificate(ctx_, leaf);
    SSL_CTX_use_PrivateKey(ctx_, leaf_key);
    for (X509* cert : extra) SSL_CTX_add1_chain_cert(ctx_, cert);
    if (ask_client != nullptr) {
      SSL_CTX_add_client_CA(ctx_, ask_client);
      // The server here only records what the client presented; it accepts any certificate.
      SSL_CTX_set_verify(ctx_, SSL_VERIFY_PEER, [](int, X509_STORE_CTX*) { return 1; });
    }
    fd_ = socket(AF_INET, SOCK_STREAM, 0);
    int yes = 1;
    setsockopt(fd_, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof yes);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    bind(fd_, reinterpret_cast<sockaddr*>(&addr), sizeof addr);
    listen(fd_, 16);
    socklen_t len = sizeof addr;
    getsockname(fd_, reinterpret_cast<sockaddr*>(&addr), &len);
    port_ = ntohs(addr.sin_port);
    thread_ = std::thread([this] { loop(); });
  }

  ~TlsServer() {
    stop_ = true;
    thread_.join();
    close(fd_);
    SSL_CTX_free(ctx_);
  }

  int port() const { return port_; }
  std::string client_pem() const { return client_pem_; }

 private:
  void loop() {
    while (!stop_) {
      pollfd pfd{fd_, POLLIN, 0};
      if (poll(&pfd, 1, 100) <= 0) continue;
      int fd = accept(fd_, nullptr, nullptr);
      if (fd >= 0) serve(fd);
    }
  }

  void serve(int fd) {
    timeval tv{5, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
    SSL* ssl = SSL_new(ctx_);
    SSL_set_fd(ssl, fd);
    if (SSL_accept(ssl) == 1) {
      X509* peer = SSL_get1_peer_certificate(ssl);
      if (peer != nullptr) {
        client_pem_ = pem_of(peer);
        X509_free(peer);
      }
      std::string request;
      char buf[8192];
      while (request.find("\r\n\r\n") == std::string::npos) {
        int n = SSL_read(ssl, buf, sizeof buf);
        if (n <= 0) break;
        request.append(buf, static_cast<size_t>(n));
      }
      int status = 404;
      std::string body = "not found";
      if (request.rfind("GET /tls/server-certificate ", 0) == 0 && publish_) {
        status = 200;
        body = published_;
      } else if (request.rfind("GET /ok ", 0) == 0) {
        status = 200;
        body = "ok";
      }
      std::ostringstream out;
      out << "HTTP/1.1 " << status << " X\r\nContent-Type: text/plain\r\nContent-Length: " << body.size()
          << "\r\nConnection: close\r\n\r\n"
          << body;
      std::string raw = out.str();
      SSL_write(ssl, raw.data(), static_cast<int>(raw.size()));
      SSL_shutdown(ssl);
    }
    SSL_free(ssl);
    ERR_clear_error();
    close(fd);
  }

  SSL_CTX* ctx_ = nullptr;
  int fd_ = -1;
  int port_ = 0;
  std::string published_;
  bool publish_ = false;
  std::atomic<bool> stop_{false};
  std::string client_pem_;
  std::thread thread_;
};

// The whole chain in the handshake, root included, as iya-sts presents it.
TlsServer* serve(Chain* c, bool publish = true) {
  return new TlsServer(c->leaf, c->leaf_key, {c->issuing, c->mid, c->root}, c->pem, publish);
}

std::string write_temp(const std::string& text) {
  char path[] = "/tmp/gnaptrustXXXXXX";
  int fd = mkstemp(path);
  if (fd < 0) return "";
  if (write(fd, text.data(), text.size()) != static_cast<ssize_t>(text.size())) {
    close(fd);
    return "";
  }
  close(fd);
  return path;
}

std::string read_file(const std::string& path) {
  std::ifstream in(path);
  std::stringstream out;
  out << in.rdbuf();
  return out.str();
}

// GET https://<host>:<port>/ok with tlsCa as `ca` (empty: the system roots). Empty string when it
// answered ok, else why it did not.
std::string get_ok(const std::string& host, int port, const std::string& ca, const TlsOpt* base = nullptr) {
  TlsOpt tls;
  if (base != nullptr) tls = *base;
  tls.ca = ca;
  try {
    auto answer = iya::gnap::http_send("https://" + host + ":" + std::to_string(port) + "/ok", "GET", {}, nullptr, tls, "tls");
    if (answer.status != 200 || answer.body != "ok") return "answered " + std::to_string(answer.status);
    return "";
  } catch (const std::exception& err) {
    std::string why = err.what();
    return why.empty() ? "refused" : why;
  }
}

// A refusal at TLS, not a socket that never connected.
bool refused_by_tls(const std::string& why) {
  return !why.empty() && why.find("connection failed") == std::string::npos &&
         (why.find("certificate") != std::string::npos || why.find("TLS handshake failed") != std::string::npos);
}

int test_chain_is_trust_store() {
  Chain* c = make_chain("DNS:localhost,DNS:sts,IP:127.0.0.1");
  Chain* other = make_chain("DNS:localhost,IP:127.0.0.1");
  if (c == nullptr || other == nullptr) return fail("chain");
  TlsServer* s = serve(c);
  std::string why;
  int rc = 0;
  // The whole chain file: the path ends at the Root.
  if (!(why = get_ok("localhost", s->port(), c->pem)).empty()) rc = fail("the chain file: " + why);
  else if (!(why = get_ok("127.0.0.1", s->port(), c->pem)).empty()) rc = fail("the chain file over 127.0.0.1: " + why);
  // The root alone is enough too.
  else if (!(why = get_ok("localhost", s->port(), c->root_pem)).empty()) rc = fail("the root: " + why);
  // A file holding exactly the presented leaf pins that leaf.
  else if (!(why = get_ok("localhost", s->port(), c->leaf_pem)).empty()) rc = fail("the pinned leaf: " + why);
  // A chain to some other root is refused, and so is another root's leaf pinned.
  else if (!refused_by_tls(why = get_ok("localhost", s->port(), other->pem))) rc = fail("another root's chain: " + why);
  else if (!refused_by_tls(why = get_ok("localhost", s->port(), other->leaf_pem))) rc = fail("another leaf: " + why);
  delete s;
  return rc;
}

int test_forged_leaf_is_refused() {
  // A server presents its own self-issued leaf for localhost followed by the
  // real (public) CA certificates. Nothing in the file is that leaf, and it does
  // not chain to the Root: refused. Matching ANY presented certificate against
  // ANY certificate in the file would accept it.
  Chain* real = make_chain("DNS:localhost,IP:127.0.0.1");
  if (real == nullptr) return fail("chain");
  EVP_PKEY* forged_key = rsa_key();
  X509* forged = make_cert("sts", forged_key, nullptr, nullptr, "DNS:localhost,IP:127.0.0.1", 99);
  if (forged == nullptr) return fail("forged");
  auto* s = new TlsServer(forged, forged_key, {real->issuing, real->mid, real->root}, real->pem, true);
  std::string why;
  int rc = 0;
  if (!refused_by_tls(why = get_ok("localhost", s->port(), real->pem)))
    rc = fail("a forged leaf followed by the real CA certificates: " + why);
  else if (!refused_by_tls(why = get_ok("127.0.0.1", s->port(), real->cas_pem)))
    rc = fail("a forged leaf against the CA certificates: " + why);
  else if (!refused_by_tls(why = get_ok("localhost", s->port(), real->root_pem)))
    rc = fail("a forged leaf against the root: " + why);
  delete s;
  return rc;
}

// The right chain, the wrong name, refused; the right name and the IP SAN accepted. ca empty: the
// system roots, which SSL_CERT_FILE points at the test root.
int host_name_cases(bool with_tls_ca) {
  std::string label = with_tls_ca ? "tlsCa: " : "system roots: ";
  auto anchor = [&](Chain* c) -> std::string {
    if (with_tls_ca) return c->root_pem;
    std::string path = write_temp(c->root_pem);
    setenv("SSL_CERT_FILE", path.c_str(), 1);
    setenv("SSL_CERT_DIR", "/nonexistent", 1);
    return "";
  };
  std::string why;
  int rc = 0;
  // The leaf names only sts.example.com.
  Chain* c = make_chain("DNS:sts.example.com");
  if (c == nullptr) return fail("chain");
  TlsServer* s = serve(c);
  std::string ca = anchor(c);
  if (!refused_by_tls(why = get_ok("localhost", s->port(), ca)))
    rc = fail(label + "localhost on a certificate for sts.example.com: " + why);
  else if (!refused_by_tls(why = get_ok("127.0.0.1", s->port(), ca)))
    rc = fail(label + "127.0.0.1 without an IP SAN: " + why);
  delete s;
  if (rc) return rc;
  // A DNS SAN of 127.0.0.1 is not an IP SAN; an IP literal is matched against IP SANs only.
  Chain* dns_ip = make_chain("DNS:127.0.0.1,DNS:localhost");
  if (dns_ip == nullptr) return fail("chain");
  s = serve(dns_ip);
  ca = anchor(dns_ip);
  if (!refused_by_tls(why = get_ok("127.0.0.1", s->port(), ca))) rc = fail(label + "127.0.0.1 on a DNS SAN: " + why);
  else if (!(why = get_ok("localhost", s->port(), ca)).empty()) rc = fail(label + "localhost: " + why);
  delete s;
  if (rc) return rc;
  // iya-sts's listener certificate names these.
  Chain* good = make_chain("DNS:localhost,DNS:sts,DNS:sts-mock,DNS:sts.example.com,IP:127.0.0.1");
  if (good == nullptr) return fail("chain");
  s = serve(good);
  ca = anchor(good);
  if (with_tls_ca) ca = good->pem;
  if (!(why = get_ok("localhost", s->port(), ca)).empty()) rc = fail(label + "localhost: " + why);
  else if (!(why = get_ok("127.0.0.1", s->port(), ca)).empty()) rc = fail(label + "127.0.0.1: " + why);
  delete s;
  if (rc || !with_tls_ca) return rc;
  // A pinned leaf still has to name the host.
  Chain* pinned = make_chain("DNS:sts.example.com");
  if (pinned == nullptr) return fail("chain");
  s = serve(pinned);
  if (!refused_by_tls(why = get_ok("localhost", s->port(), pinned->leaf_pem)))
    rc = fail(label + "a pinned leaf for sts.example.com on localhost: " + why);
  delete s;
  return rc;
}

int test_host_name_is_checked() { return host_name_cases(true); }

int test_host_name_is_checked_without_tls_ca() { return host_name_cases(false); }

int test_client_presents_its_self_signed_cert() {
  // iya-sts's CertificateRequest names only its own CA. The GNAP mtls proof registered a
  // self-signed certificate by value, which that CA did not issue; the client must present it anyway.
  Chain* c = make_chain("DNS:localhost,IP:127.0.0.1");
  if (c == nullptr) return fail("chain");
  auto key = iya::gnap::create_self_signed("gnap-caep-risc-demo", {}, {});
  auto* s = new TlsServer(c->leaf, c->leaf_key, {c->issuing, c->mid, c->root}, c->pem, true, c->root);
  TlsOpt tls;
  tls.cert = key.certificate_pem;
  tls.key = key.private_key_pem;
  std::string why = get_ok("localhost", s->port(), c->pem, &tls);
  std::string got = s->client_pem();
  delete s;
  if (!why.empty()) return fail("the mtls request: " + why);
  if (got.empty()) return fail("no client certificate was presented");
  if (got != key.certificate_pem) return fail("the client presented another certificate:\n" + got);
  return 0;
}

bool run_python(const std::string& script, const std::vector<std::string>& args) {
  pid_t pid = fork();
  if (pid == 0) {
    std::vector<char*> argv;
    argv.push_back(const_cast<char*>("python3"));
    argv.push_back(const_cast<char*>("-c"));
    argv.push_back(const_cast<char*>(script.c_str()));
    for (const auto& arg : args) argv.push_back(const_cast<char*>(arg.c_str()));
    argv.push_back(nullptr);
    execvp("python3", argv.data());
    _exit(127);
  }
  int status = 0;
  waitpid(pid, &status, 0);
  return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

int test_configure_writes_the_whole_chain() {
  Chain* c = make_chain("DNS:localhost,DNS:sts,IP:127.0.0.1");
  if (c == nullptr) return fail("chain");
  TlsServer* published = serve(c, true);
  TlsServer* handshake = serve(c, false);
  char dir[] = "/tmp/gnaptrustdirXXXXXX";
  if (mkdtemp(dir) == nullptr) return fail("mkdtemp");
  std::string config = std::string(dir) + "/gnap.json";
  {
    std::ofstream out(config);
    out << "{\"grantEndpoint\":\"https://127.0.0.1:" << published->port()
        << "/gnap\",\"application\":\"gnap-caep-risc-demo\",\"tlsCa\":\"generated/idp-ca.pem\"}\n";
  }
  std::string want = write_temp(c->pem);
  std::string handshake_url = "https://localhost:" + std::to_string(handshake->port());
  // The configure script's own path to the file, then the published chain through the command the
  // image's start-time refresh shares, then the handshake fallback.
  bool ok = run_python(
      "import importlib.util, sys, os, re, subprocess\n"
      "sys.path.insert(0, sys.argv[1])\n"
      "import trust_chain\n"
      "spec = importlib.util.spec_from_file_location('configure_iya_sts', os.path.join(sys.argv[1], 'configure_iya_sts.py'))\n"
      "mod = importlib.util.module_from_spec(spec)\n"
      "spec.loader.exec_module(mod)\n"
      "config, want, handshake = sys.argv[2:]\n"
      "blocks = lambda text: re.findall(r'-----BEGIN CERTIFICATE-----[\\s\\S]*?-----END CERTIFICATE-----', text)\n"
      "want = blocks(open(want).read())\n"
      "dest = os.path.join(os.path.dirname(config), 'generated', 'idp-ca.pem')\n"
      "assert mod.files_of(config, 'http://localhost:3000')['tlsCa'] == dest, mod.files_of(config, 'http://localhost:3000')\n"
      "out = subprocess.run([sys.executable, os.path.join(sys.argv[1], 'trust_chain.py'), '--config', config],\n"
      "                     capture_output=True, text=True, check=True).stdout\n"
      "assert 'sts Root CA' in out and 'sha256 ' in out and dest in out, out\n"
      "assert blocks(open(dest).read()) == want, 'the published chain was not written whole'\n"
      "assert len(want) == 4\n"
      "os.remove(dest)\n"
      "saved = trust_chain.save_trust_chain(handshake, dest)\n"
      "assert saved['count'] == 4, saved['count']\n"
      "assert blocks(open(dest).read()) == want, 'the handshake chain was not written whole'\n"
      "assert 'sts Root CA' in saved['anchor_subject'], saved['anchor_subject']\n",
      {"scripts", config, want, handshake_url});
  int rc = ok ? 0 : fail("trust_chain.py");
  // The file the script wrote is what the library trusts.
  std::string dest = std::string(dir) + "/generated/idp-ca.pem";
  std::string why;
  if (!rc && !(why = get_ok("localhost", published->port(), read_file(dest))).empty()) rc = fail("the saved chain: " + why);
  if (!rc && !(why = get_ok("127.0.0.1", published->port(), read_file(dest))).empty()) rc = fail("the saved chain: " + why);
  delete published;
  delete handshake;
  unlink(dest.c_str());
  unlink(want.c_str());
  unlink(config.c_str());
  rmdir((std::string(dir) + "/generated").c_str());
  rmdir(dir);
  return rc;
}

}  // namespace

int main(int argc, char** argv) {
  if (argc < 2) {
    std::fprintf(stderr, "test name required\n");
    return 2;
  }
  // A client that refuses the server's certificate after the handshake closes the socket while the
  // stub server is still writing its answer.
  std::signal(SIGPIPE, SIG_IGN);
  std::string name = argv[1];
  if (name == "TestTlsCaChainIsTheTrustStore") return test_chain_is_trust_store();
  if (name == "TestAForgedLeafBeforeTheRealCaIsRefused") return test_forged_leaf_is_refused();
  if (name == "TestHostNameIsChecked") return test_host_name_is_checked();
  if (name == "TestHostNameIsCheckedWithoutTlsCa") return test_host_name_is_checked_without_tls_ca();
  if (name == "TestClientPresentsItsSelfSignedCertWhenTheCaListNamesAnother") return test_client_presents_its_self_signed_cert();
  if (name == "TestConfigureWritesTheWholeChain") return test_configure_writes_the_whole_chain();
  std::fprintf(stderr, "unknown test %s\n", name.c_str());
  return 2;
}
