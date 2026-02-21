#pragma once
#include <QMainWindow>

class QLineEdit;
class QComboBox;
class QTextEdit;
class QLabel;

class MainWindow : public QMainWindow {
  Q_OBJECT
public:
  explicit MainWindow(QWidget* parent = nullptr);

private slots:
  void browsePorts();
  void browseAlerts();
  void browseOutput();
  void loadIni();
  void saveIni();
  void runAudit();

private:
  void setStatusOk(const QString& msg);
  void setStatusErr(const QString& msg);

  QLineEdit* iniPath_ = nullptr;
  QLineEdit* portsPath_ = nullptr;   // ports.txt OR nmap.xml
  QLineEdit* alertsPath_ = nullptr;  // alerts.txt OR zap.json
  QLineEdit* outputPath_ = nullptr;

  QComboBox* protoBox_ = nullptr;
  QComboBox* riskBox_ = nullptr;

  QTextEdit* outputView_ = nullptr;
  QLabel* statusLabel_ = nullptr;
};
