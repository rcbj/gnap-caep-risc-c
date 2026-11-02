// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

#pragma once

#include "crypto.hpp"
#include "json.hpp"

#include <memory>
#include <string>
#include <vector>

namespace iya::gnap {

struct FullConfig {
  std::string grant_endpoint;
  std::string id_token_issuer;
  std::string application;
  std::string class_id;
  std::string display_name;
  std::string display_uri;
  bool has_display = false;
  Json access;
  int signals = -1;
  std::vector<std::string> sub_id_formats;
  std::vector<std::string> assertion_formats;
  std::shared_ptr<ClientKey> key;
  std::string finish_uri;
  std::string finish_method;
  std::vector<std::string> interaction_start;
  bool require_bound = true;
  bool use_instance_id = true;
  std::string tls_ca;
  bool allow_insecure = false;
  double clock_tolerance_sec = 30;
  double max_wait_sec = 30;
  double transaction_ttl_sec = 600;
  bool has_ssf = false;
  std::string ssf_transmitter;
  int poll_interval_ms = 0;
};

FullConfig resolve_full(const std::string& json, const std::string& base_dir);
Config config_view(const FullConfig& full);

}  // namespace iya::gnap
