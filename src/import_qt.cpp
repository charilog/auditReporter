#include "import_qt.h"
#include "ports_txt.h"
#include "alerts_txt.h"

#include <QFile>
#include <QFileInfo>
#include <QXmlStreamReader>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QString>

static std::string q2s(const QString& q) {
  auto bytes = q.toUtf8();
  return std::string(bytes.constData(), (size_t)bytes.size());
}

static QString s2q(const std::string& s) {
  return QString::fromUtf8(s.c_str());
}

static std::string toLowerAscii(std::string s) {
  for (auto& c : s) c = (char)std::tolower((unsigned char)c);
  return s;
}

static Risk riskFromZapDesc(const QString& riskdesc) {
  const QString x = riskdesc.toLower();
  if (x.contains("high")) return Risk::High;
  if (x.contains("medium")) return Risk::Medium;
  if (x.contains("low")) return Risk::Low;
  if (x.contains("informational") || x.contains("info")) return Risk::None;
  return Risk::None;
}

static bool parseNmapXml(const std::string& path,
                         const std::string& onlyProtocol,
                         std::vector<OpenPort>& out,
                         std::string& err) {
  QFile file(s2q(path));
  if (!file.open(QIODevice::ReadOnly | QIODevice::Text)) {
    err = "Cannot open Nmap XML: " + path;
    return false;
  }

  const std::string protoFilter = ([](std::string p){
    p = toLowerAscii(std::move(p));
    if (p == "tcp" || p == "udp") return p;
    return std::string("any");
  })(onlyProtocol);

  QXmlStreamReader xml(&file);

  QString portProtocol;
  int portId = -1;
  QString portState;
  QString serviceName;
  bool inPort = false;

  while (!xml.atEnd()) {
    xml.readNext();

    if (xml.isStartElement()) {
      const auto name = xml.name();
      if (name == QStringLiteral("port")) {
        inPort = true;
        portProtocol = xml.attributes().value(QStringLiteral("protocol")).toString().toLower();
        portId = xml.attributes().value(QStringLiteral("portid")).toInt();
        portState.clear();
        serviceName.clear();
      } else if (inPort && name == QStringLiteral("state")) {
        portState = xml.attributes().value(QStringLiteral("state")).toString().toLower();
      } else if (inPort && name == QStringLiteral("service")) {
        serviceName = xml.attributes().value(QStringLiteral("name")).toString();
      }
    }

    if (xml.isEndElement()) {
      if (xml.name() == QStringLiteral("port") && inPort) {
        inPort = false;

        if (portId <= 0 || portId > 65535) continue;
        if (portState != QStringLiteral("open")) continue;

        const std::string proto = q2s(portProtocol);
        if (protoFilter != "any" && proto != protoFilter) continue;

        OpenPort p;
        p.protocol = proto;
        p.port = portId;
        p.state = "open";
        p.service = q2s(serviceName);
        out.push_back(std::move(p));
      }
    }
  }

  if (xml.hasError()) {
    err = "XML parse error: " + q2s(xml.errorString());
    return false;
  }
  return true;
}

static bool parseZapJson(const std::string& path,
                         Risk minRisk,
                         std::vector<WebAlert>& out,
                         std::string& err) {
  QFile f(s2q(path));
  if (!f.open(QIODevice::ReadOnly)) {
    err = "Cannot open ZAP JSON: " + path;
    return false;
  }

  const QByteArray bytes = f.readAll();
  QJsonParseError jerr;
  QJsonDocument doc = QJsonDocument::fromJson(bytes, &jerr);
  if (jerr.error != QJsonParseError::NoError || doc.isNull()) {
    err = "JSON parse error: " + q2s(jerr.errorString());
    return false;
  }

  QJsonObject root = doc.object();

  QJsonArray sites;
  if (root.contains("site") && root.value("site").isArray()) {
    sites = root.value("site").toArray();
  } else if (root.contains("report") && root.value("report").isObject()) {
    QJsonObject rep = root.value("report").toObject();
    if (rep.contains("site") && rep.value("site").isArray()) sites = rep.value("site").toArray();
  }

  if (sites.isEmpty()) {
    err = "Unexpected ZAP JSON format: missing site[]";
    return false;
  }

  for (const QJsonValue& sv : sites) {
    if (!sv.isObject()) continue;
    QJsonObject siteObj = sv.toObject();

    QString siteName;
    if (siteObj.contains("@name")) siteName = siteObj.value("@name").toString();
    else if (siteObj.contains("name")) siteName = siteObj.value("name").toString();

    if (!siteObj.contains("alerts") || !siteObj.value("alerts").isArray()) continue;
    QJsonArray alerts = siteObj.value("alerts").toArray();

    for (const QJsonValue& av : alerts) {
      if (!av.isObject()) continue;
      QJsonObject aobj = av.toObject();

      WebAlert a;
      a.site = q2s(siteName);
      a.alert = q2s(aobj.value("alert").toString());

      QString riskdesc;
      if (aobj.contains("riskdesc")) riskdesc = aobj.value("riskdesc").toString();
      else if (aobj.contains("riskDesc")) riskdesc = aobj.value("riskDesc").toString();
      a.riskDesc = q2s(riskdesc);
      a.risk = riskFromZapDesc(riskdesc);

      if (aobj.contains("riskcode") && aobj.value("riskcode").isString()) {
        bool ok = false;
        int rc = aobj.value("riskcode").toString().toInt(&ok);
        if (ok) {
          if (rc >= 3) a.risk = Risk::High;
          else if (rc == 2) a.risk = Risk::Medium;
          else if (rc == 1) a.risk = Risk::Low;
          else a.risk = Risk::None;
        }
      }

      QString desc;
      if (aobj.contains("desc")) desc = aobj.value("desc").toString();
      else if (aobj.contains("description")) desc = aobj.value("description").toString();
      a.description = q2s(desc);

      a.solution = q2s(aobj.value("solution").toString());
      a.reference = q2s(aobj.value("reference").toString());

      if ((int)a.risk < (int)minRisk) continue;
      out.push_back(std::move(a));
    }
  }

  return true;
}

bool parsePortsAuto(const std::string& path,
                    const std::string& onlyProtocol,
                    std::vector<OpenPort>& out,
                    std::string& err) {
  QFileInfo fi(s2q(path));
  const QString suf = fi.suffix().toLower();
  if (suf == QStringLiteral("xml")) return parseNmapXml(path, onlyProtocol, out, err);
  return parsePortsTxt(path, onlyProtocol, out, err);
}

bool parseAlertsAuto(const std::string& path,
                     Risk minRisk,
                     std::vector<WebAlert>& out,
                     std::string& err) {
  QFileInfo fi(s2q(path));
  const QString suf = fi.suffix().toLower();
  if (suf == QStringLiteral("json")) return parseZapJson(path, minRisk, out, err);
  return parseAlertsTxt(path, minRisk, out, err);
}
