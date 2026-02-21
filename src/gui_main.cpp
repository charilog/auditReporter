#include <QApplication>
#include "MainWindow.h"

int main(int argc, char** argv) {
  QApplication app(argc, argv);
  MainWindow w;
  w.resize(950, 650);
  w.show();
  return app.exec();
}
