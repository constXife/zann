mod cxxqt;

use cxx_qt_lib::{QGuiApplication, QQmlApplicationEngine, QUrl};

fn main() {
    std::env::set_var("QT_QUICK_CONTROLS_STYLE", "org.kde.desktop");
    unsafe {
        zann_install_message_filter();
    }
    cxx_qt::init_crate!(zann);
    unsafe {
        zann_register_types();
    }

    let mut app = QGuiApplication::new();
    let mut engine = QQmlApplicationEngine::new();
    let qml_path = std::env::current_dir()
        .expect("cwd unavailable")
        .join("qml")
        .join("main.qml");
    let qml_url = QUrl::from(&format!("file://{}", qml_path.display()));

    engine.pin_mut().load(&qml_url);
    app.pin_mut().exec();
}

extern "C" {
    fn zann_register_types();
    fn zann_install_message_filter();
}
