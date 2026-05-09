#include <QtQml/qqml.h>
#include <QGuiApplication>
#include <QClipboard>

#include "clipboard.h"
#include "zann/src/cxxqt.cxxqt.h"

extern "C" void zann_register_types() {
  qmlRegisterType<zann::AppModel>("org.zann", 1, 0, "AppModel");
}

QClipboard* zann_get_clipboard() {
  return QGuiApplication::clipboard();
}

void zann_clipboard_set_text(QClipboard* clipboard, const QString& text) {
  if (clipboard) {
    clipboard->setText(text);
  }
}
