// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

#include "crypto.hpp"
#include "http.hpp"
#include "subject.hpp"
#include "url.hpp"
#include "util.hpp"

#include <cctype>
#include <condition_variable>
#include <cstdio>
#include <mutex>
#include <thread>

namespace iya::gnap {
namespace {

const char* kDefaultEvents[] = {
    kEventSessionRevoked, kEventCredentialChange,
    "https://schemas.openid.net/secevent/caep/event-type/assurance-level-change",
    "https://schemas.openid.net/secevent/caep/event-type/token-claims-change", kEventAccountDisabled,
    "https://schemas.openid.net/secevent/risc/event-type/account-enabled",
    "https://schemas.openid.net/secevent/risc/event-type/account-purged", kEventCredentialCompromise,
    "https://schemas.openid.net/secevent/risc/event-type/sessions-revoked",
    "https://schemas.openid.net/secevent/risc/event-type/account-credential-change-required"};

const char* kEnding[] = {kEventSessionRevoked, kEventAccountDisabled,
                         "https://schemas.openid.net/secevent/risc/event-type/account-purged", kEventCredentialCompromise,
                         "https://schemas.openid.net/secevent/risc/event-type/sessions-revoked"};

const char* kVerification = "https://schemas.openid.net/secevent/ssf/event-type/verification";
const char* kStreamUpdated = "https://schemas.openid.net/secevent/ssf/event-type/stream-updated";

struct Tracked {
  std::string local_id;
  std::string person;
  std::string email;
  std::string idp_session;
  bool has_expires = false;
  double expires_at = 0;
};

std::string lower_copy(std::string value) {
  for (char& c : value)
    if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
  return value;
}

bool signature_retry(const std::string& message) {
  return message.find("publishes no") != std::string::npos || message.find("signing key") != std::string::npos ||
         message.find("does not verify") != std::string::npos;
}

std::vector<std::string> audience_list(const Json* value) {
  std::vector<std::string> out;
  if (value == nullptr || value->type == Type::Null) return out;
  if (value->type == Type::Array) {
    for (const auto& item : value->arr) out.push_back(item.type == Type::String ? item.text : item.dump());
    return out;
  }
  if (value->type == Type::String) return {value->text};
  return {value->dump()};
}

std::string clip(const std::string& value, size_t max) {
  if (value.size() <= max) return value;
  return value.substr(0, max);
}

}  // namespace

struct SignalsReceiver::Impl {
  std::string transmitter;
  SignalsReceiver::EndFn on_end;
  SignalsReceiver::HeaderFn headers;
  std::vector<std::string> events;
  std::vector<std::string> end_on;
  int interval = 5000;
  int max_events = 50;
  std::vector<Tracked> index;
  Json config;
  bool has_config = false;
  std::vector<Json> keys;
  double keys_at = 0;
  Json stream;
  bool has_stream = false;
  std::vector<std::string> ack;
  Json errs = Json::object();
  std::map<std::string, std::vector<SignalsReceiver::EventFn>> handlers;
  TlsOpt tls;
  std::mutex mu;
  std::mutex gate;
  std::condition_variable cv;
  bool stop = false;
  bool entered = false;
  std::thread worker;
  bool started = false;

  ~Impl() { stop_join(); }

  void stop_join() {
    {
      std::lock_guard<std::mutex> lock(mu);
      stop = true;
    }
    cv.notify_all();
    if (worker.joinable()) worker.join();
    started = false;
  }

  Answer call(const std::string& method, const std::string& url, const Json* body) {
    std::string dumped;
    const std::string* text = nullptr;
    if (body != nullptr) {
      dumped = body->dump();
      text = &dumped;
    }
    std::map<std::string, std::string> headers_out{{"accept", "application/json"}};
    if (headers) {
      auto extra = headers(method, url, text == nullptr ? "" : *text);
      for (const auto& item : extra) headers_out[lower_copy(item.first)] = item.second;
    }
    if (text != nullptr && !headers_out.count("content-type")) headers_out["content-type"] = "application/json";
    TlsOpt tls_copy;
    {
      std::lock_guard<std::mutex> lock(mu);
      tls_copy = tls;
    }
    return http_send(url, method, headers_out, text, tls_copy, "ssf");
  }

  void discover() {
    auto urls = well_known(transmitter, "ssf-configuration");
    Error last("ssf", "no transmitter configuration at " + (urls.empty() ? "" : urls[0]));
    if (urls.size() == 2) last = Error("ssf", "no transmitter configuration at " + urls[0] + " or " + urls[1]);
    for (size_t i = 0; i < urls.size(); i++) {
      Answer answer = call("GET", urls[i], nullptr);
      if (answer.status == 404 && i + 1 != urls.size()) continue;
      Json parsed;
      bool bad = false;
      try {
        parsed = answer.body.empty() ? Json::nul() : Json::parse(answer.body);
      } catch (const Error&) {
        bad = true;
      }
      if (bad || answer.status != 200 || parsed.type != Type::Object || jstr_key(parsed, "configuration_endpoint").empty() ||
          jstr_key(parsed, "jwks_uri").empty()) {
        last = Error("ssf", urls[i] + " answered " + std::to_string(answer.status) + " without a usable transmitter configuration");
        continue;
      }
      if (const Json* methods = parsed.get("delivery_methods_supported");
          methods != nullptr && methods->type == Type::Array && !methods->arr.empty()) {
        bool found = false;
        for (const auto& item : methods->arr)
          if (jstr(&item) == kPollDelivery) found = true;
        if (!found) throw Error("ssf", "the transmitter does not offer poll delivery (RFC 8936)");
      }
      config = parsed;
      has_config = true;
      return;
    }
    throw last;
  }

  std::vector<Json> jwks(bool force) {
    if (!force && !keys.empty() && now_ms() - keys_at < 3600000) return keys;
    Answer answer = call("GET", jstr_key(config, "jwks_uri"), nullptr);
    Json parsed;
    try {
      parsed = Json::parse(answer.body);
    } catch (const Error&) {
      parsed = Json::nul();
    }
    if (answer.status != 200 || parsed.type != Type::Object || parsed.get("keys") == nullptr ||
        parsed.get("keys")->type != Type::Array) {
      throw Error("ssf", "the transmitter's JWKS answered " + std::to_string(answer.status));
    }
    std::vector<Json> next;
    for (const auto& item : parsed.get("keys")->arr)
      if (item.type == Type::Object) next.push_back(item);
    keys = next;
    keys_at = now_ms();
    return keys;
  }

  void ensure_stream() {
    std::string endpoint = jstr_key(config, "configuration_endpoint");
    Answer answer = call("GET", endpoint, nullptr);
    if (answer.status == 200) {
      Json parsed;
      try {
        parsed = Json::parse(answer.body);
      } catch (const Error&) {
        parsed = Json::nul();
      }
      std::vector<const Json*> streams;
      if (parsed.type == Type::Array) {
        for (const auto& item : parsed.arr) streams.push_back(&item);
      } else if (parsed.type != Type::Null) {
        streams.push_back(&parsed);
      }
      for (const Json* item : streams) {
        if (item->type != Type::Object || jstr_key(*item, "stream_id").empty()) continue;
        const Json* delivery = item->get("delivery");
        if (delivery != nullptr && jstr_key(*delivery, "method") == kPollDelivery) {
          stream = *item;
          has_stream = true;
          return;
        }
      }
    } else if (answer.status != 404) {
      throw Error("ssf", "listing the streams at " + endpoint + " answered " + std::to_string(answer.status) + ": " +
                             clip(answer.body, 300));
    }
    Json payload = Json::object();
    Json delivery = Json::object();
    delivery.set("method", Json::str(kPollDelivery));
    payload.set("delivery", std::move(delivery));
    Json events_json = Json::array();
    for (const auto& item : events) events_json.push(Json::str(item));
    payload.set("events_requested", std::move(events_json));
    Answer created_answer = call("POST", endpoint, &payload);
    Json created;
    try {
      created = Json::parse(created_answer.body);
    } catch (const Error&) {
      created = Json::nul();
    }
    if ((created_answer.status != 200 && created_answer.status != 201) || created.type != Type::Object ||
        jstr_key(created, "stream_id").empty()) {
      throw Error("ssf", "creating a stream at " + endpoint + " answered " + std::to_string(created_answer.status) + ": " +
                             clip(created_answer.body, 300));
    }
    stream = created;
    has_stream = true;
  }

  std::vector<std::string> find_index(const std::function<bool(const Tracked&)>& match) {
    double now = now_ms();
    std::vector<std::string> out;
    std::vector<Tracked> kept;
    for (const auto& item : index) {
      if (item.has_expires && item.expires_at <= now) continue;
      kept.push_back(item);
      if (match(item)) out.push_back(item.local_id);
    }
    index = std::move(kept);
    return out;
  }

  std::vector<std::string> sessions_for(const std::string& event_type, const Json& subject) {
    if (event_type == kVerification || event_type == kStreamUpdated) return {};
    std::lock_guard<std::mutex> lock(mu);
    std::string idp = jstr_key(subject, "idp_session");
    if (!idp.empty()) {
      auto found = find_index([&](const Tracked& item) { return item.idp_session == idp; });
      if (!found.empty() || event_type == kEventSessionRevoked) return found;
    }
    std::string person = jstr_key(subject, "person");
    if (!person.empty()) return find_index([&](const Tracked& item) { return item.person == person; });
    std::string email = jstr_key(subject, "email");
    if (!email.empty()) {
      std::string wanted = lower_copy(email);
      return find_index([&](const Tracked& item) { return item.email == wanted; });
    }
    return {};
  }

  void handle(const std::string& jti, const std::string& token) {
    std::vector<Json> published = jwks(false);
    JwsParts verified;
    try {
      verified = verify_jws_with_keys(token, published);
    } catch (const Error& err) {
      if (!signature_retry(err.what())) throw;
      published = jwks(true);
      verified = verify_jws_with_keys(token, published);
    }
    const Json& header = verified.header;
    const Json& payload = verified.payload;
    if (header.get("typ") != nullptr && header.get("typ")->type != Type::Null && lower_copy(jstr_key(header, "typ")) != "secevent+jwt") {
      std::string shown = header.get("typ")->type == Type::String ? header.get("typ")->text : header.get("typ")->dump();
      throw Error("validation", "the SET's typ is " + shown);
    }
    if (jstr_key(payload, "iss") != jstr_key(config, "issuer")) {
      std::string got = payload.get("iss") == nullptr ? "" : (payload.get("iss")->type == Type::String ? payload.get("iss")->text : payload.get("iss")->dump());
      throw Error("validation", "the SET was issued by " + got + ", not " + jstr_key(config, "issuer"));
    }
    auto want = audience_list(stream.get("aud"));
    auto got = audience_list(payload.get("aud"));
    if (!want.empty()) {
      bool match = false;
      for (const auto& one : got)
        if (contains_string(want, one)) match = true;
      if (!match) {
        std::string shown;
        for (size_t i = 0; i < got.size(); i++) {
          if (i) shown += ", ";
          shown += got[i];
        }
        throw Error("validation", "the SET is for " + shown + ", not this stream");
      }
    }
    if (payload.get("jti") != nullptr && payload.get("jti")->type != Type::Null && jstr_key(payload, "jti") != jti) {
      throw Error("validation", "the SET's jti is not the one it was delivered under");
    }
    const Json* events_doc = payload.get("events");
    if (events_doc == nullptr || events_doc->type != Type::Object || events_doc->obj.empty()) {
      throw Error("validation", "the SET carries no events");
    }
    for (const auto& event_item : events_doc->obj) {
      const Json* subject_source = payload.get("sub_id");
      if (subject_source == nullptr || subject_source->type == Type::Null) {
        if (event_item.second.type == Type::Object) subject_source = event_item.second.get("subject");
      }
      Json subject = subject_source == nullptr ? Json::object() : subject_of_value(*subject_source, jstr_key(config, "issuer"));
      auto sessions = sessions_for(event_item.first, subject);
      bool ends = contains_string(end_on, event_item.first) && !sessions.empty();
      SignalEvent event;
      event.type = event_item.first;
      event.payload_json = event_item.second.dump();
      event.subject_json = subject.dump();
      event.jti = jti;
      event.sessions = sessions;
      event.ended = ends;
      if (ends) {
        try {
          on_end(sessions, event);
        } catch (const std::exception& err) {
          std::fprintf(stderr, "ssf: onEndSessions threw for %s (SET %s is still acknowledged): %s\n", event.type.c_str(),
                       jti.c_str(), err.what());
          event.ended = false;
        }
        if (event.ended) {
          std::lock_guard<std::mutex> lock(mu);
          std::vector<Tracked> kept;
          for (const auto& item : index) {
            bool drop = false;
            for (const auto& id : sessions)
              if (item.local_id == id) drop = true;
            if (!drop) kept.push_back(item);
          }
          index = std::move(kept);
        }
      }
      std::vector<EventFn> callbacks;
      {
        std::lock_guard<std::mutex> lock(mu);
        auto typed = handlers.find(event.type);
        if (typed != handlers.end()) callbacks.insert(callbacks.end(), typed->second.begin(), typed->second.end());
        auto star = handlers.find("*");
        if (star != handlers.end()) callbacks.insert(callbacks.end(), star->second.begin(), star->second.end());
      }
      for (const auto& callback : callbacks) {
        try {
          callback(event);
        } catch (const std::exception& err) {
          std::fprintf(stderr, "ssf: a handler for %s threw (SET %s is still acknowledged): %s\n", event.type.c_str(), jti.c_str(),
                       err.what());
        }
      }
    }
  }

  bool poll_now() {
    const Json* delivery = stream.get("delivery");
    std::string url = delivery == nullptr ? "" : jstr_key(*delivery, "endpoint_url");
    std::vector<std::string> ack_now;
    Json errs_now = Json::object();
    {
      std::lock_guard<std::mutex> lock(mu);
      ack_now.swap(ack);
      errs_now = errs;
      errs = Json::object();
    }
    Json body = Json::object();
    body.set("maxEvents", Json::integer(max_events));
    body.set("returnImmediately", Json::boolean(true));
    if (!ack_now.empty()) {
      Json list = Json::array();
      for (const auto& item : ack_now) list.push(Json::str(item));
      body.set("ack", std::move(list));
    }
    if (!errs_now.obj.empty()) body.set("setErrs", errs_now);
    Answer answer = call("POST", url, &body);
    if (answer.status != 200) {
      std::lock_guard<std::mutex> lock(mu);
      ack.insert(ack.begin(), ack_now.begin(), ack_now.end());
      for (const auto& item : errs_now.obj)
        if (!errs.has(item.first)) errs.set(item.first, item.second);
      throw Error("ssf", "the poll answered " + std::to_string(answer.status) + ": " + clip(answer.body, 300));
    }
    Json parsed = Json::object();
    if (!answer.body.empty()) {
      try {
        parsed = Json::parse(answer.body);
      } catch (const Error&) {
        throw Error("ssf", "the poll answered 200 with a body that is not JSON");
      }
    }
    const Json* sets = parsed.type == Type::Object ? parsed.get("sets") : nullptr;
    if (sets != nullptr && sets->type != Type::Null && sets->type != Type::Object) {
      throw Error("ssf", "the poll sets are not a JSON object");
    }
    if (sets != nullptr && sets->type == Type::Object) {
      for (const auto& item : sets->obj) {
        if (item.second.type != Type::String) throw Error("ssf", "the poll sets are not a JSON object");
        try {
          handle(item.first, item.second.text);
          std::lock_guard<std::mutex> lock(mu);
          ack.push_back(item.first);
        } catch (const Error& err) {
          std::fprintf(stderr, "ssf: SET %s refused: %s\n", item.first.c_str(), err.what());
          std::string code = err.code == "signature" ? "invalid_key" : "invalid_request";
          Json problem = Json::object();
          problem.set("err", Json::str(code));
          problem.set("description", Json::str(err.what()));
          std::lock_guard<std::mutex> lock(mu);
          errs.set(item.first, std::move(problem));
        }
      }
    }
    return parsed.type == Type::Object && parsed.get("moreAvailable") != nullptr && parsed.get("moreAvailable")->type == Type::Bool &&
           parsed.get("moreAvailable")->b;
  }

  bool poll_once() {
    std::lock_guard<std::mutex> gate_lock(gate);
    return poll_now();
  }

  void loop() {
    {
      std::lock_guard<std::mutex> lock(mu);
      entered = true;
    }
    cv.notify_all();
    while (true) {
      {
        std::lock_guard<std::mutex> lock(mu);
        if (stop) return;
      }
      try {
        poll_once();
      } catch (const std::exception& err) {
        std::fprintf(stderr, "ssf: poll failed: %s\n", err.what());
      }
      std::unique_lock<std::mutex> lock(mu);
      if (stop) return;
      cv.wait_for(lock, std::chrono::milliseconds(interval), [this] { return stop; });
    }
  }
};

SignalsReceiver::SignalsReceiver(std::string transmitter_in, EndFn on_end, HeaderFn headers, int poll_interval_ms)
    : impl_(std::make_unique<Impl>()) {
  if (!on_end) throw Error("config", "onEndSessions is required");
  if (transmitter_in.rfind("https://", 0) != 0 && transmitter_in.rfind("http://", 0) != 0) {
    throw Error("config", "transmitter must be an http(s) URL");
  }
  impl_->transmitter = trim_right_slash(std::move(transmitter_in));
  impl_->on_end = std::move(on_end);
  impl_->headers = std::move(headers);
  for (const char* item : kDefaultEvents) impl_->events.emplace_back(item);
  for (const char* item : kEnding) impl_->end_on.emplace_back(item);
  impl_->interval = poll_interval_ms == 0 ? 5000 : poll_interval_ms;
}

SignalsReceiver::~SignalsReceiver() = default;
SignalsReceiver::SignalsReceiver(SignalsReceiver&&) noexcept = default;
SignalsReceiver& SignalsReceiver::operator=(SignalsReceiver&&) noexcept = default;

void SignalsReceiver::on(const std::string& type, EventFn fn) {
  std::lock_guard<std::mutex> lock(impl_->mu);
  impl_->handlers[type].push_back(std::move(fn));
}

void SignalsReceiver::start() {
  if (impl_->started) return;
  impl_->discover();
  impl_->jwks(true);
  impl_->ensure_stream();
  const Json* delivery = impl_->stream.get("delivery");
  if (delivery == nullptr || jstr_key(*delivery, "endpoint_url").empty()) {
    throw Error("ssf", "the stream has no poll endpoint_url");
  }
  {
    std::lock_guard<std::mutex> lock(impl_->mu);
    impl_->stop = false;
    impl_->entered = false;
  }
  impl_->worker = std::thread([this] { impl_->loop(); });
  impl_->started = true;
  std::unique_lock<std::mutex> lock(impl_->mu);
  impl_->cv.wait(lock, [this] { return impl_->entered; });
}

void SignalsReceiver::stop() { impl_->stop_join(); }

bool SignalsReceiver::poll_once() { return impl_->poll_once(); }

void SignalsReceiver::untrack(const std::string& local_id) {
  std::lock_guard<std::mutex> lock(impl_->mu);
  std::vector<Tracked> kept;
  for (const auto& item : impl_->index)
    if (item.local_id != local_id) kept.push_back(item);
  impl_->index = std::move(kept);
}

void SignalsReceiver::set_tls(const TlsOpt& tls) {
  std::lock_guard<std::mutex> lock(impl_->mu);
  impl_->tls = tls;
}

void SignalsReceiver::track(const std::string& local_id, const std::string& person, const std::string& email,
                            const std::string& idp_session) {
  std::lock_guard<std::mutex> lock(impl_->mu);
  Tracked session;
  session.local_id = local_id;
  session.person = person;
  session.email = lower_copy(email);
  session.idp_session = idp_session;
  bool replaced = false;
  for (auto& item : impl_->index) {
    if (item.local_id == local_id) {
      item = session;
      replaced = true;
    }
  }
  if (!replaced) impl_->index.push_back(session);
}

void SignalsReceiver::verify_stream(const std::string& state) {
  std::string endpoint = jstr_key(impl_->config, "verification_endpoint");
  if (endpoint.empty()) throw Error("ssf", "the transmitter publishes no verification_endpoint");
  Json body = Json::object();
  body.set("stream_id", Json::str(jstr_key(impl_->stream, "stream_id")));
  if (!state.empty()) body.set("state", Json::str(state));
  Answer answer = impl_->call("POST", endpoint, &body);
  if (answer.status != 200 && answer.status != 204) {
    throw Error("ssf", "verification answered " + std::to_string(answer.status));
  }
}

std::string SignalsReceiver::stream_id() const { return jstr_key(impl_->stream, "stream_id"); }

}  // namespace iya::gnap
