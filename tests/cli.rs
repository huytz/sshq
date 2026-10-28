use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Command, Output};

fn home() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/home")
}

fn sshq(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_sshq"))
        .args(args)
        .env("HOME", home())
        .output()
        .unwrap()
}

fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

fn aliases(args: &[&str]) -> Vec<String> {
    let mut a = vec!["-a"];
    a.extend_from_slice(args);
    let o = sshq(&a);
    stdout(&o).lines().map(String::from).collect()
}

#[test]
fn lists_all_hosts_including_includes_in_order() {
    assert_eq!(
        aliases(&[]),
        [
            "stg-api",
            "prod-web-1",
            "prod-web-2",
            "prod-db-1",
            "bastion",
            "node_3",
            "node_30",
            "v6",
            "local"
        ]
    );
}

#[test]
fn table_has_header_and_columns() {
    let o = sshq(&["prod-db"]);
    assert!(o.status.success());
    let out = stdout(&o);
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(lines.len(), 2);
    assert!(lines[0].starts_with("ALIAS"));
    for col in ["prod-db-1", "198.51.100.20", "postgres", "2222", "bastion"] {
        assert!(lines[1].contains(col), "missing {col}: {}", lines[1]);
    }
}

#[test]
fn text_terms_are_anded_and_search_comments() {
    assert_eq!(aliases(&["prod", "deploy"]), ["prod-web-1", "prod-web-2"]);
    assert_eq!(aliases(&["staging"]), ["stg-api"]);
    assert_eq!(aliases(&["web1"]), ["prod-web-1"]);
    assert_eq!(aliases(&["box"]), ["bastion"]);
}

#[test]
fn exact_ip_lookup() {
    assert_eq!(aliases(&["198.51.100.3"]), ["node_3"]);
    assert_eq!(aliases(&["2001:db8::42"]), ["v6"]);
}

#[test]
fn cidr_lookup() {
    assert_eq!(
        aliases(&["192.0.2.0/24"]),
        ["stg-api", "prod-web-1", "prod-web-2"]
    );
    assert_eq!(
        aliases(&["192.0.2.0/24", "prod"]),
        ["prod-web-1", "prod-web-2"]
    );
    assert_eq!(aliases(&["2001:db8::/32"]), ["v6"]);
}

#[test]
fn resolve_flag_matches_dns_hostnames() {
    assert!(aliases(&["127.0.0.1"]).is_empty());
    assert_eq!(aliases(&["-r", "127.0.0.1"]), ["local"]);
    let o = sshq(&["-r", "127.0.0.0/8"]);
    let out = stdout(&o);
    assert!(
        out.contains("localhost (") && out.contains("127.0.0.1"),
        "{out}"
    );
}

#[test]
fn no_match_exits_1() {
    let o = sshq(&["10.9.9.9"]);
    assert_eq!(o.status.code(), Some(1));
    assert!(stderr(&o).contains("no match"));
}

#[test]
fn explicit_file_flag() {
    let f = home().join(".ssh/config.d/staging.conf");
    let o = sshq(&["-a", "-f", f.to_str().unwrap()]);
    assert_eq!(stdout(&o).trim(), "stg-api");
}

#[test]
fn missing_file_exits_1() {
    let o = sshq(&["-f", "/nonexistent/config"]);
    assert_eq!(o.status.code(), Some(1));
    assert!(stderr(&o).contains("no hosts found"));
}

#[test]
fn bad_flags_exit_2() {
    assert_eq!(sshq(&["-f"]).status.code(), Some(2));
    assert_eq!(sshq(&["--nope"]).status.code(), Some(2));
}

#[test]
fn help_and_version() {
    assert!(stdout(&sshq(&["-h"])).contains("usage:"));
    let v = stdout(&sshq(&["-V"]));
    assert_eq!(v.trim(), format!("sshq {}", env!("CARGO_PKG_VERSION")));
}

fn fake_ssh_path() -> String {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("fake-ssh");
    fs::create_dir_all(&dir).unwrap();
    let bin = dir.join("ssh");
    fs::write(&bin, "#!/bin/sh\necho \"fake-ssh $*\"\n").unwrap();
    fs::set_permissions(&bin, fs::Permissions::from_mode(0o755)).unwrap();
    format!(
        "{}:{}",
        dir.display(),
        std::env::var("PATH").unwrap_or_default()
    )
}

fn go(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_sshq"))
        .arg("go")
        .args(args)
        .env("HOME", home())
        .env("PATH", fake_ssh_path())
        .output()
        .unwrap()
}

#[test]
fn go_execs_ssh_on_single_or_exact_match() {
    let o = go(&["bastion"]);
    assert!(o.status.success());
    assert_eq!(stdout(&o).trim(), "fake-ssh bastion");
    assert_eq!(stdout(&go(&["node_3"])).trim(), "fake-ssh node_3");
    assert_eq!(stdout(&go(&["198.51.100.30"])).trim(), "fake-ssh node_30");
}

#[test]
fn go_ambiguous_lists_and_exits_1() {
    let o = go(&["node"]);
    assert_eq!(o.status.code(), Some(1));
    assert!(stderr(&o).contains("2 matches"));
    assert!(!stdout(&o).contains("fake-ssh"));
    assert!(stdout(&o).contains("node_30"));
}
