#include "report.h"
#include <fstream>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <cctype>
#include <cstdio>

static std::string nowUtcIso8601() {
  using namespace std::chrono;
  auto t = system_clock::to_time_t(system_clock::now());
  std::tm tm{};
#if defined(_WIN32)
  gmtime_s(&tm, &t);
#else
  gmtime_r(&t, &tm);
#endif
  std::ostringstream oss;
  oss << std::put_time(&tm, "%Y-%m-%dT%H:%M:%SZ");
  return oss.str();
}

static std::string lower(std::string s) {
  for (auto& c : s) c = (char)std::tolower((unsigned char)c);
  return s;
}

Risk parseRisk(const std::string& s) {
  auto x = lower(s);
  if (x == "high") return Risk::High;
  if (x == "medium") return Risk::Medium;
  if (x == "low") return Risk::Low;
  return Risk::None;
}

std::string riskToString(Risk r) {
  switch (r) {
    case Risk::High: return "high";
    case Risk::Medium: return "medium";
    case Risk::Low: return "low";
    default: return "none";
  }
}

static std::string jsonEscape(const std::string& in) {
  std::string out;
  out.reserve(in.size() + 16);
  for (unsigned char c : in) {
    switch (c) {
      case '\\': out += "\\\\"; break;
      case '"':  out += "\\\""; break;
      case '\b': out += "\\b"; break;
      case '\f': out += "\\f"; break;
      case '\n': out += "\\n"; break;
      case '\r': out += "\\r"; break;
      case '\t': out += "\\t"; break;
      default:
        if (c < 0x20) {
          char buf[7];
          std::snprintf(buf, sizeof(buf), "\\u%04x", (unsigned)c);
          out += buf;
        } else {
          out.push_back((char)c);
        }
    }
  }
  return out;
}

bool writeReportJson(const std::string& path, const AuditReport& rep, std::string& err) {
  std::ofstream out(path);
  if (!out) { err = "Cannot write report: " + path; return false; }

  const std::string ts = rep.generatedAtUtc.empty() ? nowUtcIso8601() : rep.generatedAtUtc;

  out << "{\n";
  out << "  \"generated_at_utc\": \"" << jsonEscape(ts) << "\",\n";

  out << "  \"open_ports\": [\n";
  for (size_t i = 0; i < rep.openPorts.size(); ++i) {
    const auto& p = rep.openPorts[i];
    out << "    {"
        << "\"protocol\":\"" << jsonEscape(p.protocol) << "\","
        << "\"port\":" << p.port << ","
        << "\"state\":\"" << jsonEscape(p.state) << "\","
        << "\"service\":\"" << jsonEscape(p.service) << "\""
        << "}";
    if (i + 1 != rep.openPorts.size()) out << ",";
    out << "\n";
  }
  out << "  ],\n";

  out << "  \"web_alerts\": [\n";
  for (size_t i = 0; i < rep.alerts.size(); ++i) {
    const auto& a = rep.alerts[i];
    out << "    {"
        << "\"site\":\"" << jsonEscape(a.site) << "\","
        << "\"alert\":\"" << jsonEscape(a.alert) << "\","
        << "\"risk\":\"" << jsonEscape(riskToString(a.risk)) << "\","
        << "\"risk_desc\":\"" << jsonEscape(a.riskDesc) << "\","
        << "\"description\":\"" << jsonEscape(a.description) << "\","
        << "\"solution\":\"" << jsonEscape(a.solution) << "\","
        << "\"reference\":\"" << jsonEscape(a.reference) << "\""
        << "}";
    if (i + 1 != rep.alerts.size()) out << ",";
    out << "\n";
  }
  out << "  ]\n";
  out << "}\n";
  return true;
}

bool writeAuditIni(const std::string& iniPath,
                   const std::string& portsPath,
                   const std::string& alertsPath,
                   const std::string& outJson,
                   const std::string& minRisk,
                   const std::string& onlyProtocol,
                   std::string& err) {
  std::ofstream out(iniPath);
  if (!out) { err = "Cannot write ini: " + iniPath; return false; }

  out << "[inputs]\n";
  out << "ports_path = " << portsPath << "\n";
  out << "alerts_path = " << alertsPath << "\n\n";

  out << "[filters]\n";
  out << "min_risk = " << minRisk << "          ; none|low|medium|high\n";
  out << "only_protocol = " << onlyProtocol << "        ; tcp|udp|any\n\n";

  out << "[output]\n";
  out << "report_json = " << outJson << "\n";
  return true;
}
