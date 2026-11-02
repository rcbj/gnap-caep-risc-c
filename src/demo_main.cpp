// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

#include "iya/gnap.hpp"

#include "codec.hpp"
#include "json.hpp"
#include "url.hpp"
#include "util.hpp"

#include <openssl/crypto.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <memory>
#include <mutex>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

namespace {

using iya::gnap::Client;
using iya::gnap::Error;
using iya::gnap::Grant;
using iya::gnap::Json;
using iya::gnap::Subject;
using iya::gnap::Type;
using iya::gnap::Url;
using iya::gnap::b64url_decode;
using iya::gnap::b64url_encode;
using iya::gnap::hostport_of;
using iya::gnap::jstr_key;
using iya::gnap::parse_absolute;
using iya::gnap::read_text_file_ok;

std::string lower_copy(std::string value) {
  for (char& c : value)
    if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
  return value;
}

std::string trim_copy(const std::string& value) {
  size_t begin = 0;
  while (begin < value.size() && std::isspace(static_cast<unsigned char>(value[begin]))) begin++;
  size_t end = value.size();
  while (end > begin && std::isspace(static_cast<unsigned char>(value[end - 1]))) end--;
  return value.substr(begin, end - begin);
}

std::string trim_right_slash(std::string value) {
  while (!value.empty() && value.back() == '/') value.pop_back();
  return value;
}

std::string html_escape(const std::string& value) {
  std::string out;
  for (char c : value) {
    if (c == '&') out += "&amp;";
    else if (c == '<') out += "&lt;";
    else if (c == '>') out += "&gt;";
    else if (c == '"') out += "&quot;";
    else if (c == '\'') out += "&#39;";
    else out.push_back(c);
  }
  return out;
}

std::string dir_of(const std::string& path) {
  auto slash = path.find_last_of('/');
  if (slash == std::string::npos) return ".";
  if (slash == 0) return "/";
  return path.substr(0, slash);
}

std::string hex_of(const unsigned char* data, size_t n) {
  static const char* kHex = "0123456789abcdef";
  std::string out(n * 2, '0');
  for (size_t i = 0; i < n; i++) {
    out[i * 2] = kHex[data[i] >> 4];
    out[i * 2 + 1] = kHex[data[i] & 0x0f];
  }
  return out;
}

std::string on_port(const std::string& raw, const std::string& port) {
  Url url;
  if (!parse_absolute(raw, url) || url.host.empty()) return raw;
  std::string host = lower_copy(url.host);
  if (host != "localhost" && host != "127.0.0.1" && host != "::1") return raw;
  std::string shown = url.host;
  if (shown.find(':') != std::string::npos && (shown.empty() || shown.front() != '[')) shown = "[" + shown + "]";
  std::string path = url.path.empty() ? "/" : url.path;
  std::string out = url.scheme + "://" + shown + ":" + port + path;
  if (!url.query.empty()) out += "?" + url.query;
  return out;
}

std::string move_origin(const std::string& value, const std::string& public_url) {
  if (value.empty()) return value;
  Url base;
  Url next;
  if (!parse_absolute(public_url + "/", base) || !parse_absolute(value, next)) return value;
  std::string path = next.path.empty() ? "/" : next.path;
  std::string out = base.scheme + "://" + hostport_of(base) + path;
  if (!next.query.empty()) out += "?" + next.query;
  return out;
}

struct Moved {
  std::string finish;
  std::string display;
};

Moved redirects_for(const std::string& finish, const std::string& display, const std::string& public_url, bool given,
                    const std::string& port) {
  Moved out;
  out.finish = finish;
  out.display = display;
  if (given && !public_url.empty()) {
    if (!finish.empty()) out.finish = move_origin(finish, public_url);
    if (!display.empty()) out.display = move_origin(display, public_url);
    return out;
  }
  if (!port.empty()) {
    if (!finish.empty()) out.finish = on_port(finish, port);
    if (!display.empty()) out.display = on_port(display, port);
  }
  return out;
}

struct Session {
  Subject person;
  Grant grant;
};

struct Header {
  std::string name;
  std::string value;
};

struct Request {
  std::string method;
  std::string path;
  std::string query;
  std::map<std::string, std::string> headers;
  std::string body;
};

bool read_request(int fd, Request& req) {
  std::string data;
  char buf[4096];
  while (data.find("\r\n\r\n") == std::string::npos) {
    ssize_t n = ::recv(fd, buf, sizeof(buf), 0);
    if (n <= 0) return false;
    data.append(buf, static_cast<size_t>(n));
    if (data.size() > 1024 * 1024) return false;
  }
  auto header_end = data.find("\r\n\r\n");
  std::string head = data.substr(0, header_end);
  std::string rest = data.substr(header_end + 4);
  auto line_end = head.find("\r\n");
  std::string start = line_end == std::string::npos ? head : head.substr(0, line_end);
  auto sp1 = start.find(' ');
  auto sp2 = sp1 == std::string::npos ? std::string::npos : start.find(' ', sp1 + 1);
  if (sp1 == std::string::npos || sp2 == std::string::npos) return false;
  req.method = start.substr(0, sp1);
  std::string target = start.substr(sp1 + 1, sp2 - sp1 - 1);
  auto q = target.find('?');
  req.path = q == std::string::npos ? target : target.substr(0, q);
  req.query = q == std::string::npos ? std::string() : target.substr(q + 1);
  std::string headers = line_end == std::string::npos ? std::string() : head.substr(line_end + 2);
  size_t at = 0;
  while (at < headers.size()) {
    auto nl = headers.find("\r\n", at);
    std::string line = headers.substr(at, nl == std::string::npos ? std::string::npos : nl - at);
    auto colon = line.find(':');
    if (colon != std::string::npos) {
      std::string name = lower_copy(trim_copy(line.substr(0, colon)));
      std::string value = trim_copy(line.substr(colon + 1));
      auto found = req.headers.find(name);
      if (found == req.headers.end()) req.headers.emplace(name, value);
      else found->second += ", " + value;
    }
    if (nl == std::string::npos) break;
    at = nl + 2;
  }
  long length = 0;
  auto cl = req.headers.find("content-length");
  if (cl != req.headers.end()) length = std::strtol(cl->second.c_str(), nullptr, 10);
  if (length < 0 || length > 1024 * 1024) return false;
  while (static_cast<long>(rest.size()) < length) {
    ssize_t n = ::recv(fd, buf, sizeof(buf), 0);
    if (n <= 0) return false;
    rest.append(buf, static_cast<size_t>(n));
  }
  req.body.assign(rest, 0, static_cast<size_t>(length));
  return true;
}

void send_all(int fd, const std::string& raw) {
  size_t sent = 0;
  while (sent < raw.size()) {
    ssize_t n = ::send(fd, raw.data() + sent, raw.size() - sent, MSG_NOSIGNAL);
    if (n <= 0) return;
    sent += static_cast<size_t>(n);
  }
}

void respond(int fd, int status, const char* reason, const std::string& type, const std::string& body,
             const std::vector<Header>& headers) {
  std::ostringstream out;
  out << "HTTP/1.1 " << status << " " << reason << "\r\n";
  bool has_type = false;
  for (const auto& header : headers) {
    out << header.name << ": " << header.value << "\r\n";
    if (lower_copy(header.name) == "content-type") has_type = true;
  }
  if (!has_type && !type.empty()) out << "Content-Type: " << type << "\r\n";
  out << "Content-Length: " << body.size() << "\r\nConnection: close\r\n\r\n" << body;
  send_all(fd, out.str());
}

const char* reason_of(int status) {
  if (status == 200) return "OK";
  if (status == 204) return "No Content";
  if (status == 302) return "Found";
  if (status == 303) return "See Other";
  if (status == 400) return "Bad Request";
  if (status == 404) return "Not Found";
  return "Error";
}

struct Demo {
  std::string config_path;
  std::string public_dir;
  std::string config_dir;
  std::string public_url;
  bool public_given = false;
  std::string port;
  std::string secret;
  std::mutex session_mu;
  std::mutex client_mu;
  std::unique_ptr<Client> client;
  std::string client_err;
  std::map<std::string, Session> sessions;
  std::unique_ptr<iya::gnap::SignalsReceiver> receiver;
  bool has_latest = false;
  Grant latest;
  // For GET /live-status: the receiver's state, and the type and jti of each event it accepted.
  // No tokens.
  std::string receiver_state = "not started (no sign-in yet)";
  std::vector<std::pair<std::string, std::string>> live_events;

  // The id the receiver knows a session by: the grant id, or the subject.
  static std::string tracked_id(const Grant& grant) {
    return grant.grant_id.empty() ? grant.subject.sub : grant.grant_id;
  }

  // Ends every cookie session whose grant the receiver tracks under one of ids. The cookie id and the
  // tracked id differ, so this looks the sessions up by grant. Call with session_mu held.
  void end_tracked(const std::vector<std::string>& ids) {
    for (auto it = sessions.begin(); it != sessions.end();) {
      std::string known = tracked_id(it->second.grant);
      bool drop = false;
      for (const auto& id : ids)
        if (!known.empty() && known == id) drop = true;
      if (drop) it = sessions.erase(it);
      else ++it;
    }
  }

  // Records an accepted event for /live-status. A session-revoked event that ended no tracked session
  // still ends this demo's one local session, if it has exactly one: the event can name the sign-on
  // session by an id the grant did not carry.
  void remember(const iya::gnap::SignalEvent& event) {
    std::string orphan;
    iya::gnap::SignalsReceiver* rx = nullptr;
    {
      std::lock_guard<std::mutex> lock(session_mu);
      live_events.emplace_back(event.type, event.jti);
      if (live_events.size() > 100) live_events.erase(live_events.begin());
      if (event.type == iya::gnap::kEventSessionRevoked && !event.ended && sessions.size() == 1) {
        orphan = tracked_id(sessions.begin()->second.grant);
        sessions.clear();
        rx = receiver.get();
      }
    }
    if (rx != nullptr) {
      std::printf("ssf: session-revoked matched no tracked session; ending this demo's one local session\n");
      std::fflush(stdout);
      if (!orphan.empty()) rx->untrack(orphan);
    }
  }

  std::string seal(const std::string& payload) const {
    std::string encoded = b64url_encode(payload);
    unsigned char mac[EVP_MAX_MD_SIZE];
    unsigned int len = 0;
    HMAC(EVP_sha256(), secret.data(), static_cast<int>(secret.size()), reinterpret_cast<const unsigned char*>(encoded.data()),
         encoded.size(), mac, &len);
    return encoded + "." + hex_of(mac, len);
  }

  bool unseal(const std::string& token, Json& doc) const {
    auto dot = token.rfind('.');
    if (token.empty() || dot == std::string::npos || dot == 0) return false;
    std::string raw = token.substr(0, dot);
    std::string mac_text = token.substr(dot + 1);
    unsigned char mac[EVP_MAX_MD_SIZE];
    unsigned int len = 0;
    HMAC(EVP_sha256(), secret.data(), static_cast<int>(secret.size()), reinterpret_cast<const unsigned char*>(raw.data()), raw.size(),
         mac, &len);
    std::string expect = hex_of(mac, len);
    if (expect.size() != mac_text.size() || CRYPTO_memcmp(expect.data(), mac_text.data(), expect.size()) != 0) return false;
    std::vector<unsigned char> decoded;
    if (!b64url_decode(raw, decoded, true)) return false;
    try {
      doc = Json::parse(std::string(decoded.begin(), decoded.end()));
    } catch (const std::exception&) {
      return false;
    }
    return doc.type == Type::Object;
  }

  std::string cookie_value(const Request& req, const std::string& name) const {
    auto found = req.headers.find("cookie");
    if (found == req.headers.end()) return "";
    std::string prefix = name + "=";
    size_t at = 0;
    const std::string& header = found->second;
    while (at < header.size()) {
      auto semi = header.find(';', at);
      std::string item = trim_copy(header.substr(at, semi == std::string::npos ? std::string::npos : semi - at));
      if (item.compare(0, prefix.size(), prefix) == 0) return item.substr(prefix.size());
      if (semi == std::string::npos) break;
      at = semi + 1;
    }
    return "";
  }

  void html(int fd, int status, const std::string& title, const std::string& body, const std::vector<Header>& extra) {
    std::string page = "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n<title>" + html_escape(title) +
                       "</title>\n<link rel=\"stylesheet\" href=\"/styles.css\">\n</head>\n<body>\n<main>\n" + body +
                       "\n</main>\n</body>\n</html>\n";
    std::vector<Header> headers = extra;
    bool typed = false;
    for (const auto& header : headers)
      if (lower_copy(header.name) == "content-type") typed = true;
    if (!typed) headers.push_back({"Content-Type", "text/html; charset=utf-8"});
    respond(fd, status, reason_of(status), "", page, headers);
  }

  Client* gnap(std::string& error) {
    {
      std::lock_guard<std::mutex> lock(session_mu);
      if (client) return client.get();
    }
    std::string text;
    std::string read_error;
    try {
      if (!read_text_file_ok(config_path, text, read_error)) throw Error("config", read_error);
      Json doc = Json::parse(text);
      std::string display_uri;
      Json* display = doc.get("display");
      if (display != nullptr && display->type == Type::Object) display_uri = jstr_key(*display, "uri");
      Moved moved = redirects_for(jstr_key(doc, "finishUri"), display_uri, public_url, public_given, port);
      if (display != nullptr && display->type == Type::Object && !moved.display.empty()) {
        display->set("uri", Json::str(moved.display));
      }
      if (!moved.finish.empty()) doc.set("finishUri", Json::str(moved.finish));
      auto created = std::make_unique<Client>(Client::from_json(doc.dump(), config_dir));
      std::lock_guard<std::mutex> lock(session_mu);
      if (!client) client = std::move(created);
      client_err.clear();
      return client.get();
    } catch (const std::exception& ex) {
      std::lock_guard<std::mutex> lock(session_mu);
      client_err = ex.what();
      error = client_err;
      return nullptr;
    }
  }

  bool signals_wanted(std::string& transmitter, int& interval) {
    std::string text;
    std::string read_error;
    if (!read_text_file_ok(config_path, text, read_error)) return false;
    Json doc;
    try {
      doc = Json::parse(text);
    } catch (const std::exception&) {
      return false;
    }
    if (const Json* signals = doc.get("signals"); signals != nullptr && signals->type == Type::Bool && !signals->b) return false;
    const Json* ssf = doc.get("ssf");
    if (ssf == nullptr || ssf->type != Type::Object) return false;
    transmitter = jstr_key(*ssf, "transmitter");
    if (transmitter.empty()) return false;
    interval = 5000;
    if (const Json* n = ssf->get("pollIntervalMs"); n != nullptr && n->type == Type::Number && n->as_float() != 0) {
      interval = static_cast<int>(n->as_float());
    }
    return true;
  }

  void watch(const Grant& grant, const Subject& person) {
    {
      std::lock_guard<std::mutex> lock(session_mu);
      latest = grant;
      has_latest = true;
      if (receiver) {
        // Every grant is tracked, not only the first.
        receiver->track(tracked_id(grant), person.sub, person.email, person.sid);
        return;
      }
    }
    std::string transmitter;
    int interval = 5000;
    if (!signals_wanted(transmitter, interval)) {
      std::lock_guard<std::mutex> lock(session_mu);
      receiver_state = "not configured (signals are off, or no ssf.transmitter)";
      return;
    }
    Client* current = nullptr;
    {
      std::lock_guard<std::mutex> lock(session_mu);
      current = client.get();
    }
    if (current == nullptr) return;
    try {
      iya::gnap::TlsOpt tls = current->tls();
      auto created = std::make_unique<iya::gnap::SignalsReceiver>(
          transmitter,
          [this](const std::vector<std::string>& ids, const iya::gnap::SignalEvent&) {
            std::lock_guard<std::mutex> lock(session_mu);
            end_tracked(ids);
          },
          [this](const std::string& method, const std::string& url, const std::string& body) {
            Grant copy;
            Client* signer = nullptr;
            bool has = false;
            {
              std::lock_guard<std::mutex> lock(session_mu);
              signer = client.get();
              if (has_latest) {
                copy = latest;
                has = true;
              }
            }
            std::map<std::string, std::string> headers;
            if (!has || signer == nullptr) return headers;
            const std::string* text = body.empty() ? nullptr : &body;
            std::lock_guard<std::mutex> lock(client_mu);
            return signer->authorization_headers(copy, method, url, text);
          },
          interval);
      created->set_tls(tls);
      created->on("*", [this](const iya::gnap::SignalEvent& event) { remember(event); });
      created->start();
      created->track(tracked_id(grant), person.sub, person.email, person.sid);
      std::lock_guard<std::mutex> lock(session_mu);
      if (receiver) {
        created->stop();
        return;
      }
      receiver_state = "polling stream " + created->stream_id() + " at " + transmitter;
      receiver = std::move(created);
    } catch (const std::exception& ex) {
      std::printf("ssf: not started: %s\n", ex.what());
      std::lock_guard<std::mutex> lock(session_mu);
      receiver_state = std::string("not running: ") + ex.what();
    }
  }

  bool session_of(const Request& req, Session& out) {
    Json opened;
    if (!unseal(cookie_value(req, "gsid"), opened)) return false;
    std::string id = jstr_key(opened, "id");
    std::lock_guard<std::mutex> lock(session_mu);
    auto found = sessions.find(id);
    if (found == sessions.end()) return false;
    out = found->second;
    return true;
  }

  void place(int fd, const Grant& grant, const std::string& extra) {
    unsigned char buf[12];
    RAND_bytes(buf, sizeof(buf));
    std::string local = b64url_encode(buf, sizeof(buf));
    {
      std::lock_guard<std::mutex> lock(session_mu);
      sessions[local] = Session{grant.subject, grant};
    }
    Json payload = Json::object();
    payload.set("id", Json::str(local));
    std::vector<Header> headers;
    headers.push_back({"Location", "/"});
    headers.push_back({"Cache-Control", "no-store"});
    headers.push_back({"Set-Cookie", "gsid=" + seal(payload.dump()) + "; Path=/; HttpOnly; SameSite=Lax"});
    if (!extra.empty()) headers.push_back({"Set-Cookie", extra});
    respond(fd, 303, "See Other", "", "", headers);
  }

  void home(int fd, const Request& req) {
    Session opened;
    if (session_of(req, opened)) {
      std::string who = opened.person.sub;
      if (!opened.person.email.empty()) who = opened.person.email;
      else if (!opened.person.name.empty()) who = opened.person.name;
      html(fd, 200, "Signed in",
           "<h1>Signed in</h1><p>" + html_escape(who) +
               "</p><form method=\"post\" action=\"/logout\"><button type=\"submit\">Sign out</button></form>",
           {});
      return;
    }
    std::string error;
    Client* current = gnap(error);
    std::string problem;
    std::string link;
    if (current == nullptr) {
      std::string msg;
      {
        std::lock_guard<std::mutex> lock(session_mu);
        msg = client_err;
      }
      if (msg.empty()) msg = "the key could not be read";
      problem = "<p>The GNAP client is not configured yet: " + html_escape(msg) +
                ". Generate the key at the privateKey path, then run scripts/configure_iya_sts.py.</p>";
    } else {
      link = "<p><a class=\"button\" href=\"/login\">Sign in with GNAP</a></p>";
    }
    html(fd, 200, "GNAP demo", "<h1>GNAP CAEP RISC demo</h1>" + problem + link, {});
  }

  void login(int fd) {
    std::string error;
    Client* current = gnap(error);
    if (current == nullptr) {
      html(fd, 400, "Sign-in failed",
           "<h1>Sign-in failed</h1><p>" + html_escape(error) + "</p><p><a href=\"/\">Start again</a></p>", {});
      return;
    }
    try {
      iya::gnap::GrantResult started;
      std::string finish;
      {
        std::lock_guard<std::mutex> lock(client_mu);
        started = current->request_grant();
        finish = current->config().finish_uri;
      }
      if (started.has_grant) {
        place(fd, started.grant, "");
        return;
      }
      Json payload = Json::object();
      Json ids = Json::array();
      ids.push(Json::str(started.pending_id));
      payload.set("ids", std::move(ids));
      std::string secure = finish.rfind("https:", 0) == 0 ? "; Secure" : "";
      std::vector<Header> headers;
      headers.push_back({"Location", started.redirect_url});
      headers.push_back({"Set-Cookie", "gpending=" + seal(payload.dump()) +
                                           "; Path=/callback; Max-Age=600; HttpOnly; SameSite=Lax" + secure});
      headers.push_back({"Cache-Control", "no-store"});
      respond(fd, 302, "Found", "", "", headers);
    } catch (const std::exception& ex) {
      html(fd, 400, "Sign-in failed",
           "<h1>Sign-in failed</h1><p>" + html_escape(ex.what()) + "</p><p><a href=\"/\">Start again</a></p>", {});
    }
  }

  void callback(int fd, const Request& req) {
    std::string clear = "gpending=; Path=/callback; Max-Age=0; HttpOnly; SameSite=Lax";
    std::vector<std::string> ids;
    Json opened;
    if (unseal(cookie_value(req, "gpending"), opened)) {
      if (const Json* list = opened.get("ids"); list != nullptr && list->type == Type::Array) {
        for (const auto& item : list->arr)
          if (item.type == Type::String) ids.push_back(item.text);
      }
    }
    std::string error;
    Client* current = gnap(error);
    if (current == nullptr) {
      html(fd, 400, "Sign-in failed",
           "<h1>Sign-in failed</h1><p>" + html_escape(error) + "</p><p><a href=\"/\">Start again</a></p>",
           {{"Set-Cookie", clear}});
      return;
    }
    try {
      iya::gnap::Finished done;
      {
        std::lock_guard<std::mutex> lock(client_mu);
        done = current->finish_redirect(req.query, ids);
      }
      if (!done.grant.subject.present) throw Error("validation", "the grant has no subject");
      place(fd, done.grant, clear);
      watch(done.grant, done.grant.subject);
    } catch (const std::exception& ex) {
      std::printf("sign-in refused: %s\n", ex.what());
      html(fd, 400, "Sign-in failed",
           "<h1>Sign-in failed</h1><p>" + html_escape(ex.what()) + "</p><p><a href=\"/\">Start again</a></p>",
           {{"Set-Cookie", clear}});
    }
  }

  void logout(int fd, const Request& req) {
    Json opened;
    if (unseal(cookie_value(req, "gsid"), opened)) {
      std::string id = jstr_key(opened, "id");
      Session session;
      bool found = false;
      iya::gnap::SignalsReceiver* rx = nullptr;
      {
        std::lock_guard<std::mutex> lock(session_mu);
        auto it = sessions.find(id);
        if (it != sessions.end()) {
          session = it->second;
          sessions.erase(it);
          found = true;
        }
        rx = receiver.get();
      }
      if (found && rx != nullptr && !session.grant.grant_id.empty()) rx->untrack(session.grant.grant_id);
      if (found && client) {
        try {
          std::lock_guard<std::mutex> lock(client_mu);
          client->revoke(session.grant);
        } catch (const std::exception& ex) {
          std::printf("revoke: %s\n", ex.what());
        }
      }
    }
    respond(fd, 303, "See Other", "", "",
            {{"Location", "/"}, {"Cache-Control", "no-store"}, {"Set-Cookie", "gsid=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax"}});
  }

  void push(int fd, const Request& req) {
    std::string error;
    Client* current = gnap(error);
    if (current == nullptr) {
      Json body = Json::object();
      body.set("error", Json::str(error));
      respond(fd, 400, "Bad Request", "application/json", body.dump(), {});
      return;
    }
    try {
      iya::gnap::Finished done;
      {
        std::lock_guard<std::mutex> lock(client_mu);
        done = current->finish_push_json(req.body.empty() ? "null" : req.body);
      }
      if (done.grant.subject.present) watch(done.grant, done.grant.subject);
      respond(fd, 204, "No Content", "", "", {{"Cache-Control", "no-store"}});
    } catch (const std::exception& ex) {
      Json body = Json::object();
      body.set("error", Json::str(ex.what()));
      respond(fd, 400, "Bad Request", "application/json", body.dump(), {});
    }
  }

  // JSON for scripts/live_iya_sts.py: whether this browser is signed in, as whom, the receiver's
  // state, and the type and jti of every event received. It carries no tokens.
  void live_status(int fd, const Request& req) {
    Session opened;
    bool signed_in = session_of(req, opened);
    Json body = Json::object();
    body.set("signedIn", Json::boolean(signed_in));
    std::string who;
    if (signed_in) {
      who = !opened.person.email.empty() ? opened.person.email : !opened.person.name.empty() ? opened.person.name : opened.person.sub;
    }
    body.set("subject", who.empty() ? Json::nul() : Json::str(who));
    Json events = Json::array();
    {
      std::lock_guard<std::mutex> lock(session_mu);
      body.set("receiver", Json::str(receiver_state));
      for (const auto& item : live_events) {
        Json one = Json::object();
        one.set("type", Json::str(item.first));
        one.set("jti", Json::str(item.second));
        events.push(std::move(one));
      }
    }
    body.set("events", std::move(events));
    respond(fd, 200, "OK", "application/json", body.dump(), {{"Cache-Control", "no-store"}});
  }

  void static_file(int fd, const std::string& name, const std::string& type) {
    std::string text;
    std::string error;
    if (!read_text_file_ok(public_dir + "/" + name, text, error)) {
      html(fd, 404, "Not found", "<h1>Not found</h1>", {});
      return;
    }
    respond(fd, 200, "OK", type, text, {{"Cache-Control", "max-age=300"}});
  }

  void handle(int fd, const Request& req) {
    if (req.path == "/healthz" && req.method == "GET") {
      respond(fd, 200, "OK", "text/plain", "ok", {});
      return;
    }
    if (req.path == "/live-status" && req.method == "GET") {
      live_status(fd, req);
      return;
    }
    if (req.path == "/styles.css" && req.method == "GET") {
      static_file(fd, "styles.css", "text/css; charset=utf-8");
      return;
    }
    if (req.path == "/app.js" && req.method == "GET") {
      static_file(fd, "app.js", "text/javascript; charset=utf-8");
      return;
    }
    if (req.path == "/" && req.method == "GET") {
      home(fd, req);
      return;
    }
    if (req.path == "/login" && req.method == "GET") {
      login(fd);
      return;
    }
    if (req.path == "/callback" && req.method == "GET") {
      callback(fd, req);
      return;
    }
    if (req.path == "/logout" && req.method == "POST") {
      logout(fd, req);
      return;
    }
    if (req.path == "/gnap/push" && req.method == "POST") {
      push(fd, req);
      return;
    }
    html(fd, 404, "Not found", "<h1>Not found</h1>", {});
  }
};

void public_url_of(int argc, char** argv, std::string& url, bool& given) {
  const char* env = std::getenv("PUBLIC_URL");
  if (env != nullptr && env[0] != '\0') {
    url = trim_right_slash(env);
    given = true;
  }
  for (int i = 1; i < argc; i++) {
    if (std::strcmp(argv[i], "--public-url") == 0 && i + 1 < argc) {
      url = trim_right_slash(argv[++i]);
      given = true;
    }
  }
}

}  // namespace

int main(int argc, char** argv) {
  Demo demo;
  public_url_of(argc, argv, demo.public_url, demo.public_given);
  const char* port = std::getenv("PORT");
  demo.port = port != nullptr && port[0] != '\0' ? port : "3000";
  const char* config = std::getenv("GNAP_CONFIG");
  demo.config_path = config != nullptr && config[0] != '\0' ? config : "demo/gnap.json";
  demo.config_dir = dir_of(demo.config_path);
  demo.public_dir = demo.config_dir + "/public";
  const char* secret = std::getenv("SESSION_SECRET");
  if (secret != nullptr && secret[0] != '\0') {
    demo.secret = secret;
  } else {
    unsigned char buf[32];
    RAND_bytes(buf, sizeof(buf));
    demo.secret.assign(reinterpret_cast<char*>(buf), sizeof(buf));
  }
  int fd = ::socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0) {
    std::perror("socket");
    return 1;
  }
  int one = 1;
  setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_ANY);
  addr.sin_port = htons(static_cast<uint16_t>(std::atoi(demo.port.c_str())));
  if (bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
    std::perror("bind");
    return 1;
  }
  if (listen(fd, 64) != 0) {
    std::perror("listen");
    return 1;
  }
  std::printf("gnap-caep-risc demo on port %s, configuration %s\n", demo.port.c_str(), demo.config_path.c_str());
  std::fflush(stdout);
  while (true) {
    int client = ::accept(fd, nullptr, nullptr);
    if (client < 0) continue;
    timeval tv{};
    tv.tv_sec = 30;
    setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    Request req;
    try {
      if (read_request(client, req)) demo.handle(client, req);
    } catch (const std::exception& ex) {
      std::printf("%s\n", ex.what());
      demo.html(client, 500, "Error",
                "<h1>Something went wrong</h1><p>" + html_escape(ex.what()) + "</p><p><a href=\"/\">Home</a></p>", {});
    }
    ::close(client);
  }
}
