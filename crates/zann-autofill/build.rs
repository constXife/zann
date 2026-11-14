use sha2::{Digest, Sha256};

fn main() {
    for name in ["public_suffix_list.dat", "equivalent_domains.json"] {
        let path = format!("data/{name}");
        let pin = format!("{path}.sha256");
        println!("cargo:rerun-if-changed={path}");
        println!("cargo:rerun-if-changed={pin}");
        let bytes = std::fs::read(&path).expect("vendored autofill data exists");
        let expected = std::fs::read_to_string(&pin).expect("autofill data digest exists");
        assert_eq!(
            format!("{:x}", Sha256::digest(bytes)),
            expected.trim(),
            "autofill data digest mismatch: {path}"
        );
    }
}
