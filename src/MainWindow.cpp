#include "MainWindow.h"

#include <QWidget>
#include <QVBoxLayout>
#include <QGridLayout>
#include <QHBoxLayout>
#include <QLineEdit>
#include <QComboBox>
#include <QPushButton>
#include <QLabel>
#include <QTextEdit>
#include <QFileDialog>
#include <QMessageBox>
#include <QFile>
#include <QTextStream>

#include "ini.h"
#include "report.h"
#include "import_qt.h"

static QString readAllText(const QString& path) {
  QFile f(path);
  if (!f.open(QIODevice::ReadOnly | QIODevice::Text)) return {};
  QTextStream in(&f);
  in.setEncoding(QStringConverter::Utf8);
  return in.readAll();
}

static std::string q2s(const QString& q) {
  auto bytes = q.toUtf8();
  return std::string(bytes.constData(), (size_t)bytes.size());
}

static QString s2q(const std::string& s) {
  return QString::fromUtf8(s.c_str());
}

static std::string normProto(std::string s) {
  for (auto& c : s) c = (char)std::tolower((unsigned char)c);
  if (s == "tcp" || s == "udp") return s;
  return "any";
}

MainWindow::MainWindow(QWidget* parent) : QMainWindow(parent) {
  setWindowTitle("Audit Reporter v1.0");

  auto* central = new QWidget(this);
  auto* root = new QVBoxLayout(central);

  {
    auto* row = new QHBoxLayout();
    row->addWidget(new QLabel("INI:", central));
    iniPath_ = new QLineEdit("audit.ini", central);
    row->addWidget(iniPath_, 1);

    auto* btnLoad = new QPushButton("Load", central);
    auto* btnSave = new QPushButton("Save", central);
    row->addWidget(btnLoad);
    row->addWidget(btnSave);

    connect(btnLoad, &QPushButton::clicked, this, &MainWindow::loadIni);
    connect(btnSave, &QPushButton::clicked, this, &MainWindow::saveIni);

    root->addLayout(row);
  }

  {
    auto* grid = new QGridLayout();

    grid->addWidget(new QLabel("Ports input (.txt or Nmap .xml):", central), 0, 0);
    portsPath_ = new QLineEdit("inputs/ports.txt", central);
    grid->addWidget(portsPath_, 0, 1);
    auto* b1 = new QPushButton("Browse...", central);
    grid->addWidget(b1, 0, 2);
    connect(b1, &QPushButton::clicked, this, &MainWindow::browsePorts);

    grid->addWidget(new QLabel("Alerts input (.txt or ZAP .json):", central), 1, 0);
    alertsPath_ = new QLineEdit("inputs/alerts.txt", central);
    grid->addWidget(alertsPath_, 1, 1);
    auto* b2 = new QPushButton("Browse...", central);
    grid->addWidget(b2, 1, 2);
    connect(b2, &QPushButton::clicked, this, &MainWindow::browseAlerts);

    grid->addWidget(new QLabel("Output JSON:", central), 2, 0);
    outputPath_ = new QLineEdit("report.json", central);
    grid->addWidget(outputPath_, 2, 1);
    auto* b3 = new QPushButton("Browse...", central);
    grid->addWidget(b3, 2, 2);
    connect(b3, &QPushButton::clicked, this, &MainWindow::browseOutput);

    grid->addWidget(new QLabel("Protocol filter:", central), 3, 0);
    protoBox_ = new QComboBox(central);
    protoBox_->addItem("any");
    protoBox_->addItem("tcp");
    protoBox_->addItem("udp");
    grid->addWidget(protoBox_, 3, 1);

    grid->addWidget(new QLabel("Min risk:", central), 4, 0);
    riskBox_ = new QComboBox(central);
    riskBox_->addItem("none");
    riskBox_->addItem("low");
    riskBox_->addItem("medium");
    riskBox_->addItem("high");
    riskBox_->setCurrentText("medium");
    grid->addWidget(riskBox_, 4, 1);

    auto* runBtn = new QPushButton("Run", central);
    runBtn->setMinimumHeight(34);
    grid->addWidget(runBtn, 5, 0, 1, 3);
    connect(runBtn, &QPushButton::clicked, this, &MainWindow::runAudit);

    root->addLayout(grid);
  }

  statusLabel_ = new QLabel("Ready.", central);
  root->addWidget(statusLabel_);

  outputView_ = new QTextEdit(central);
  outputView_->setReadOnly(true);
  outputView_->setPlaceholderText("report.json will be shown here after Run...");
  root->addWidget(outputView_, 1);

  setCentralWidget(central);
  loadIni();
}

void MainWindow::setStatusOk(const QString& msg) {
  statusLabel_->setText("OK: " + msg);
  statusLabel_->setStyleSheet("color: #1b5e20;");
}

void MainWindow::setStatusErr(const QString& msg) {
  statusLabel_->setText("ERROR: " + msg);
  statusLabel_->setStyleSheet("color: #b71c1c;");
}

void MainWindow::browsePorts() {
  auto p = QFileDialog::getOpenFileName(this, "Select ports input", ".", "Ports/Nmap (*.txt *.xml);;All files (*.*)");
  if (!p.isEmpty()) portsPath_->setText(p);
}

void MainWindow::browseAlerts() {
  auto p = QFileDialog::getOpenFileName(this, "Select alerts input", ".", "Alerts/ZAP (*.txt *.json);;All files (*.*)");
  if (!p.isEmpty()) alertsPath_->setText(p);
}

void MainWindow::browseOutput() {
  auto p = QFileDialog::getSaveFileName(this, "Select output JSON", ".", "JSON files (*.json);;All files (*.*)");
  if (!p.isEmpty()) outputPath_->setText(p);
}

void MainWindow::loadIni() {
  const QString iniPath = iniPath_->text().trimmed();
  if (iniPath.isEmpty()) return;

  std::string err;
  Ini ini;
  if (!ini.load(q2s(iniPath), err)) {
    setStatusErr("Cannot load INI (" + iniPath + "). Using UI defaults.");
    return;
  }

  portsPath_->setText(s2q(ini.get("inputs","ports_path","inputs/ports.txt")));
  alertsPath_->setText(s2q(ini.get("inputs","alerts_path","inputs/alerts.txt")));
  outputPath_->setText(s2q(ini.get("output","report_json","report.json")));

  protoBox_->setCurrentText(s2q(normProto(ini.get("filters","only_protocol","any"))));
  riskBox_->setCurrentText(s2q(ini.get("filters","min_risk","medium")));

  setStatusOk("Loaded " + iniPath);
}

void MainWindow::saveIni() {
  const QString iniPath = iniPath_->text().trimmed();
  if (iniPath.isEmpty()) {
    QMessageBox::warning(this, "INI", "INI path is empty.");
    return;
  }

  std::string err;
  const bool ok = writeAuditIni(
    q2s(iniPath),
    q2s(portsPath_->text().trimmed()),
    q2s(alertsPath_->text().trimmed()),
    q2s(outputPath_->text().trimmed()),
    q2s(riskBox_->currentText()),
    q2s(protoBox_->currentText()),
    err
  );

  if (!ok) { setStatusErr(s2q(err)); return; }
  setStatusOk("Saved " + iniPath);
}

void MainWindow::runAudit() {
  const QString ports = portsPath_->text().trimmed();
  const QString alerts = alertsPath_->text().trimmed();
  const QString outJson = outputPath_->text().trimmed();

  if (outJson.isEmpty()) {
    QMessageBox::warning(this, "Run", "Output JSON path is empty.");
    return;
  }

  const std::string onlyProto = q2s(protoBox_->currentText());
  const Risk minRisk = parseRisk(q2s(riskBox_->currentText()));

  AuditReport rep;
  std::string err;

  if (!ports.isEmpty()) {
    if (!parsePortsAuto(q2s(ports), onlyProto, rep.openPorts, err)) {
      setStatusErr(s2q(err));
      return;
    }
  }

  if (!alerts.isEmpty()) {
    if (!parseAlertsAuto(q2s(alerts), minRisk, rep.alerts, err)) {
      setStatusErr(s2q(err));
      return;
    }
  }

  if (!writeReportJson(q2s(outJson), rep, err)) {
    setStatusErr(s2q(err));
    return;
  }

  setStatusOk(QString("Wrote %1 (open_ports=%2, alerts=%3)")
              .arg(outJson)
              .arg((int)rep.openPorts.size())
              .arg((int)rep.alerts.size()));

  const QString text = readAllText(outJson);
  if (!text.isEmpty()) outputView_->setPlainText(text);
  else outputView_->setPlainText("Report written, but could not read file:\n" + outJson);
}
