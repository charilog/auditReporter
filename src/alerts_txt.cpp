#include "alerts_txt.h"
#include <fstream>
#include <cctype>

static std::string trim(std::string s) {
  auto issp = [](unsigned char c){ return std::isspace(c) != 0; };
  while (!s.empty() && issp((unsigned char)s.front())) s.erase(s.begin());
  while (!s.empty() && issp((unsigned char)s.back())) s.pop_back();
  return s;
}

static std::vector<std::string> splitTsv(const std::string& line) {
  std::vector<std::string> parts;
  size_t start = 0;
  while (true) {
    size_t pos = line.find('\t', start);
    if (pos == std::string::npos) { parts.push_back(line.substr(start)); break; }
    parts.push_back(line.substr(start, pos - start));
    start = pos + 1;
  }
  return parts;
}

bool parseAlertsTxt(const std::string& path,
                    Risk minRisk,
                    std::vector<WebAlert>& out,
                    std::string& err) {
  std::ifstream in(path);
  if (!in) { err = "Cannot open alerts file: " + path; return false; }

  std::string line;
  size_t lineNo = 0;
  while (std::getline(in, line)) {
    ++lineNo;
    line = trim(line);
    if (line.empty()) continue;
    if (line[0] == '#') continue;

    auto parts = splitTsv(line);
    if (parts.size() < 6) { err = "Bad alerts line at line " + std::to_string(lineNo); return false; }

    WebAlert a;
    a.site = trim(parts[0]);
    a.alert = trim(parts[1]);
    a.risk = parseRisk(trim(parts[2]));
    a.riskDesc = "";
    a.description = trim(parts[3]);
    a.solution = trim(parts[4]);
    a.reference = trim(parts[5]);

    if ((int)a.risk < (int)minRisk) continue;
    out.push_back(std::move(a));
  }
  return true;
}
