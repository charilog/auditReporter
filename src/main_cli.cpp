#include <iostream>
#include "ini.h"
#include "report.h"
#include "import_qt.h"

static std::string normProto(std::string s) {
  for (auto& c : s) c = (char)std::tolower((unsigned char)c);
  if (s == "tcp" || s == "udp") return s;
  return "any";
}

int main(int argc, char** argv) {
  if (argc < 2) {
    std::cerr << "Usage: audit_reporter_cli <audit.ini>\n";
    return 2;
  }

  std::string err;
  Ini ini;
  if (!ini.load(argv[1], err)) {
    std::cerr << "INI error: " << err << "\n";
    return 3;
  }

  const std::string portsPath  = ini.get("inputs", "ports_path", "inputs/ports.txt");
  const std::string alertsPath = ini.get("inputs", "alerts_path", "inputs/alerts.txt");
  const std::string outJson    = ini.get("output", "report_json", "report.json");

  const Risk minRisk = parseRisk(ini.get("filters", "min_risk", "none"));
  const std::string onlyProto = normProto(ini.get("filters", "only_protocol", "any"));

  AuditReport rep;

  if (!portsPath.empty()) {
    if (!parsePortsAuto(portsPath, onlyProto, rep.openPorts, err)) {
      std::cerr << "Ports parse error: " << err << "\n";
      return 4;
    }
  }

  if (!alertsPath.empty()) {
    if (!parseAlertsAuto(alertsPath, minRisk, rep.alerts, err)) {
      std::cerr << "Alerts parse error: " << err << "\n";
      return 5;
    }
  }

  if (!writeReportJson(outJson, rep, err)) {
    std::cerr << "Report write error: " << err << "\n";
    return 6;
  }

  std::cout << "OK: wrote " << outJson
            << " (open_ports=" << rep.openPorts.size()
            << ", alerts=" << rep.alerts.size() << ")\n";
  return 0;
}
