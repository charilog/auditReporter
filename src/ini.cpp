#include "ini.h"
#include <fstream>
#include <sstream>
#include <cctype>

std::string Ini::trim(std::string s) {
  auto issp = [](unsigned char c){ return std::isspace(c) != 0; };
  while (!s.empty() && issp((unsigned char)s.front())) s.erase(s.begin());
  while (!s.empty() && issp((unsigned char)s.back())) s.pop_back();
  return s;
}

std::string Ini::toLower(std::string s) {
  for (auto& ch : s) ch = (char)std::tolower((unsigned char)ch);
  return s;
}

bool Ini::load(const std::string& path, std::string& err) {
  std::ifstream in(path);
  if (!in) { err = "Cannot open ini file: " + path; return false; }

  std::string line, section;
  size_t lineNo = 0;

  while (std::getline(in, line)) {
    ++lineNo;

    auto sc = line.find(';');
    auto hc = line.find('#');
    auto cut = std::min(sc == std::string::npos ? line.size() : sc,
                        hc == std::string::npos ? line.size() : hc);
    line = trim(line.substr(0, cut));
    if (line.empty()) continue;

    if (line.front() == '[' && line.back() == ']') {
      section = trim(line.substr(1, line.size() - 2));
      section = toLower(section);
      continue;
    }

    auto eq = line.find('=');
    if (eq == std::string::npos) {
      std::ostringstream oss;
      oss << "INI parse error at line " << lineNo << " (expected key=value)";
      err = oss.str();
      return false;
    }

    std::string key = toLower(trim(line.substr(0, eq)));
    std::string val = trim(line.substr(eq + 1));
    data_[section][key] = val;
  }

  return true;
}

std::string Ini::get(const std::string& section,
                     const std::string& key,
                     const std::string& def) const {
  auto sit = data_.find(toLower(section));
  if (sit == data_.end()) return def;
  auto kit = sit->second.find(toLower(key));
  if (kit == sit->second.end()) return def;
  return kit->second;
}
