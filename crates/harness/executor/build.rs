use std::{env, fs};

fn main() {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let out_dir = env::var("OUT_DIR").unwrap();
    let plugin_dir = format!("{manifest_dir}/test_plugins");
    let out_path = format!("{out_dir}/tests.rs");

    let mut content = String::new();

    // Iterate over all .rs files in the directory, and add an import for each
    // one.
    for entry in std::fs::read_dir(&plugin_dir).unwrap() {
        let entry = entry.unwrap();
        if entry.file_type().unwrap().is_file() && entry.path().extension().unwrap() == "rs" {
            let file_name = entry
                .path()
                .file_name()
                .unwrap()
                .to_string_lossy()
                .into_owned();
            let module_name = file_name.strip_suffix(".rs").unwrap();

            content.push_str(&format!(
                "#[path = \"{plugin_dir}/{file_name}\"]\nmod {module_name};\n",
            ));
        }
    }

    fs::write(out_path, content).expect("Unable to write to file");
}
