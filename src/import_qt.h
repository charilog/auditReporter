#pragma once
#include <string>
#include <vector>
#include "report.h"

// Ports input can be:
// - ports.txt (protocol,port,state,service) OR
// - Nmap XML (.xml)
bool parsePortsAuto(const std::string& path,
                    const std::string& onlyProtocol, // tcp|udp|any
                    std::vector<OpenPort>& out,
                    std::string& err);

// Alerts input can be:
// - alerts.txt (TSV) OR
// - OWASP ZAP JSON (.json)
bool parseAlertsAuto(const std::string& path,
                     Risk minRisk,
                     std::vector<WebAlert>& out,
                     std::string& err);
