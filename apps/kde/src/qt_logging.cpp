#include <QtCore/qlogging.h>
#include <QtCore/QString>

static QtMessageHandler g_prev_handler = nullptr;

static void zann_message_handler(QtMsgType type,
                                 const QMessageLogContext& context,
                                 const QString& message) {
  if (message.contains("ToolTip: Binding loop detected for property \"contentWidth\"")) {
    return;
  }
  if (g_prev_handler) {
    g_prev_handler(type, context, message);
  }
}

extern "C" void zann_install_message_filter() {
  if (!g_prev_handler) {
    g_prev_handler = qInstallMessageHandler(zann_message_handler);
  }
}
