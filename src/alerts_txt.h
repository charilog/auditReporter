#pragma once
#include <string>
#include <vector>
#include "report.h"

bool parseAlertsTxt(const std::string& path,
                    Risk minRisk,
                    std::vector<WebAlert>& out,
                    std::string& err);
