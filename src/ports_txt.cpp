#include "ports_txt.h"
#include <fstream>
#include <cctype>

static std::string trim(std::string s) {
  auto issp = [](unsigned char c){ return std::isspace(c) != 0; };
  while (!s.empty() && issp((unsigned char)s.front())) s.erase(s.begin());
  while (!s.empty() && issp((unsigned char)s.back())) s.pop_back();
  return s;
}

static std::string lower(std::string s) {
  for (auto& c : s) c = (char)std::tolower((unsigned char)c);
  return s;
}

static bool split4(const std::string& line, std::string& a, std::string& b, std::string& c, std::string& d) {
  size_t p1 = line.find(',');
  if (p1 == std::string::npos) return false;
  size_t p2 = line.find(',', p1 + 1);
  if (p2 == std::string::npos) return false;
  size_t p3 = line.find(',', p2 + 1);
  if (p3 == std::string::npos) return false;

  a = trim(line.substr(0, p1));
  b = trim(line.substr(p1 + 1, p2 - (p1 + 1)));
  c = trim(line.substr(p2 + 1, p3 - (p2 + 1)));
  d = trim(line.substr(p3 + 1));
  return true;
}

bool parsePortsTxt(const std::string& path,
                   const std::string& onlyProtocol,
                   std::vector<OpenPort>& out,
                   std::string& err) {
  std::ifstream in(path);
  if (!in) { err = "Cannot open ports file: " + path; return false; }

  std::string protoFilter = lower(onlyProtocol);
  if (protoFilter != "tcp" && protoFilter != "udp") protoFilter = "any";

  std::string line;
  size_t lineNo = 0;
  while (std::getline(in, line)) {
    ++lineNo;
    line = trim(line);
    if (line.empty()) continue;
    if (line[0] == '#') continue;

    std::string proto, portStr, state, service;
    if (!split4(line, proto, portStr, state, service)) {
      err = "Bad ports line at line " + std::to_string(lineNo);
      return false;
    }

    proto = lower(proto);
    state = lower(state);

    if (protoFilter != "any" && proto != protoFilter) continue;
    if (state != "open") continue;

    int port = 0;
    try { port = std::stoi(portStr); }
    catch (...) { err = "Invalid port at line " + std::to_string(lineNo); return false; }

    if (port <= 0 || port > 65535) { err = "Port out of range at line " + std::to_string(lineNo); return false; }

    OpenPort p;
    p.protocol = proto;
    p.port = port;
    p.state = "open";
    p.service = service;
    out.push_back(std::move(p));
  }
  return true;
}
