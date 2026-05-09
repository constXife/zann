#pragma once

class QClipboard;
class QString;

QClipboard* zann_get_clipboard();
void zann_clipboard_set_text(QClipboard* clipboard, const QString& text);
