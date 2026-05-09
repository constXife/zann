mod cxxqt;

use std::ffi::CString;
use std::os::raw::c_char;

use cxx_qt as _;
use cxx_qt_lib as _;

extern "C" {
    fn zann_qml_test_main(argc: i32, argv: *mut *mut c_char) -> i32;
}

fn main() {
    if std::env::var("QT_QUICK_CONTROLS_STYLE").is_err() {
        std::env::set_var("QT_QUICK_CONTROLS_STYLE", "org.kde.desktop");
    }
    if std::env::var("QT_QPA_PLATFORM").is_err() {
        std::env::set_var("QT_QPA_PLATFORM", "offscreen");
    }
    if std::env::var("QT_LOGGING_RULES").is_err() {
        std::env::set_var(
            "QT_LOGGING_RULES",
            "qt.qml.warning=false;qt.qml.binding.removal.info=false;qt.qml.binding.removal.debug=false",
        );
    }
    std::env::set_var("ZANN_TEST_ENABLE", "1");
    if std::env::var("ZANN_TEST_SKIP_REMOTE_SYNC").is_err() {
        std::env::set_var("ZANN_TEST_SKIP_REMOTE_SYNC", "1");
    }
    let args: Vec<CString> = std::env::args()
        .map(|arg| CString::new(arg).expect("invalid arg"))
        .collect();
    let mut argv: Vec<*mut c_char> = args.iter().map(|arg| arg.as_ptr() as *mut c_char).collect();
    let code = unsafe { zann_qml_test_main(argv.len() as i32, argv.as_mut_ptr()) };
    std::process::exit(code);
}
