#pragma once
#include <string>
#include <vector>
#include "report.h"

bool parsePortsTxt(const std::string& path,
                   const std::string& onlyProtocol, // tcp|udp|any
                   std::vector<OpenPort>& out,
                   std::string& err);
