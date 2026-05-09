#include <QtQuickTest/quicktest.h>
#include <cstdlib>

extern "C" void zann_register_types();

extern "C" int zann_qml_test_main(int argc, char **argv) {
  zann_register_types();
  const char *testPath = std::getenv("ZANN_QML_TEST_PATH");
  const char *path = (testPath && *testPath) ? testPath : "tests/qml";
  return quick_test_main(argc, argv, "zann-kde-tests", path);
}
