#pragma once
#include <string>
#include <vector>

struct OpenPort {
  std::string protocol; // "tcp"/"udp"
  int port = 0;
  std::string state;    // "open"
  std::string service;  // e.g. "http"
};

enum class Risk { None=0, Low=1, Medium=2, High=3 };

struct WebAlert {
  std::string site;
  std::string alert;
  Risk risk = Risk::None;
  std::string riskDesc;
  std::string description;
  std::string solution;
  std::string reference;
};

struct AuditReport {
  std::string generatedAtUtc;
  std::vector<OpenPort> openPorts;
  std::vector<WebAlert> alerts;
};

Risk parseRisk(const std::string& s);
std::string riskToString(Risk r);

bool writeReportJson(const std::string& path, const AuditReport& rep, std::string& err);

bool writeAuditIni(const std::string& iniPath,
                   const std::string& portsPath,
                   const std::string& alertsPath,
                   const std::string& outJson,
                   const std::string& minRisk,
                   const std::string& onlyProtocol,
                   std::string& err);
