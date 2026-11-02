// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

#pragma once

#include "json.hpp"

#include <functional>
#include <string>
#include <vector>

namespace iya::gnap {

Subject person_from_value(const Json& doc, const std::string& issuer, const std::vector<std::string>& audiences,
                          double skew, const std::function<std::vector<Json>()>& keys);
Json subject_of_value(const Json& doc, const std::string& issuer);

}  // namespace iya::gnap
