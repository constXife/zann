use cxx_qt_build::CxxQtBuilder;
use std::env;
use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-changed=src/qml_register.cpp");
    println!("cargo:rerun-if-changed=src/qt_logging.cpp");
    println!("cargo:rerun-if-changed=src/clipboard.h");
    println!("cargo:rerun-if-changed=qml/main.qml");
    unsafe {
        CxxQtBuilder::new()
            .file("src/cxxqt.rs")
            .qt_module("Qml")
            .qt_module("Quick")
            .qt_module("QuickTest")
            .cc_builder(|cc| {
                cc.include("src");
            })
            .build();
    }

    let qtbuild = qt_build_utils::QtBuild::new(vec![
        "Core".to_owned(),
        "Gui".to_owned(),
        "Qml".to_owned(),
        "Quick".to_owned(),
        "QuickTest".to_owned(),
    ])
    .expect("Failed to locate Qt installation");
    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR missing"));
    let include_dir = out_dir.join("cxxqtbuild/include");

    let mut cc = cc::Build::new();
    cc.cpp(true);
    cc.file("src/qml_register.cpp");
    cc.file("src/qml_test_runner.cpp");
    cc.file("src/qt_logging.cpp");
    cc.include("src");
    cc.include(include_dir);
    for include in qtbuild.include_paths() {
        cc.include(include);
    }
    cc.compile("zann_register");

}
