#pragma once
#include <string>
#include <unordered_map>

class Ini {
public:
  bool load(const std::string& path, std::string& err);

  std::string get(const std::string& section,
                  const std::string& key,
                  const std::string& def = "") const;

private:
  using Section = std::unordered_map<std::string, std::string>;
  std::unordered_map<std::string, Section> data_;

  static std::string trim(std::string s);
  static std::string toLower(std::string s);
};
