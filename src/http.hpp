// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

#pragma once

#include "iya/gnap.hpp"

#include <map>
#include <string>

namespace iya::gnap {

Answer http_send(const std::string& url, const std::string& method, const std::map<std::string, std::string>& headers,
                 const std::string* body, const TlsOpt& tls, const std::string& code);

}  // namespace iya::gnap
