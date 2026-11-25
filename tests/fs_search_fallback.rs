#![cfg(target_os = "linux")]

use jms_bridge::fsprobe::{decode, remote_script, FsOptions};
use serde_json::Value;
use std::{fs, os::unix::fs::symlink, path::Path, process::Command};

fn run(options: &FsOptions, bin: &Path) -> Value {
    let output = Command::new("/bin/bash")
        .env("PATH", bin)
        .arg("-c")
        .arg(remote_script(options, "rg").unwrap())
        .output()
        .unwrap();
    assert!(output.status.success(), "{:?}", output.status);
    let value = decode(&output.stdout, options, &output.stderr);
    assert_eq!(value["engine"], "grep");
    assert_eq!(value["ok"], true, "{value}");
    value
}

#[test]
fn grep_single_file_hint_distinguishes_literal_alternation_without_noise() {
    let root = tempfile::tempdir().unwrap();
    let commands = root.path().join("bin");
    let docs = root.path().join("docs");
    fs::create_dir(&commands).unwrap();
    fs::create_dir(&docs).unwrap();
    for tool in ["awk", "base64", "bash", "find", "grep", "head", "od", "readlink", "sort", "stat", "timeout"] {
        symlink(format!("/usr/bin/{tool}"), commands.join(tool)).unwrap();
    }
    let doc = docs.join("sample.md");
    fs::write(&doc, "FlagTree is enabled\nMP31 uses a different path\n").unwrap();
    let literal = FsOptions {
        action: "search".into(), path: doc.to_str().unwrap().into(),
        pattern: "FlagTree|MP31".into(), include: vec!["*.md".into()],
        ..Default::default()
    };
    let v = run(&literal, &commands);
    assert_eq!(v["returned"], 0);
    assert_eq!(v["complete"], true);
    assert!(v.get("warnings").is_none());
    assert_eq!(v["hint"], "Literal match; set literal=false for alternation.");

    let regex = FsOptions {literal: Some(false), ..literal};
    let v = run(&regex, &commands);
    assert_eq!(v["returned"], 2);
    assert!(v.get("hint").is_none() && v.get("warnings").is_none());

    let directory = FsOptions {path: docs.to_str().unwrap().into(), ..regex};
    let v = run(&directory, &commands);
    assert_eq!(v["returned"], 2);
    assert_eq!(v["warnings"][0], "grep fallback ignores .gitignore/.ignore; use exclude.");
    assert_eq!(v["ignore_rules_applied"], false);
    let v = run(&FsOptions {respect_ignore: Some(false), ..directory}, &commands);
    assert!(v.get("warnings").is_none());
}
