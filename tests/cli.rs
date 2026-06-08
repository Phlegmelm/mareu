//! End-to-end tests that run the built `mareu` binary and assert on its output.
//! These exercise the Unix contract: stdin/stdout/exit-code behavior.

use std::process::Command;

fn mareu() -> Command {
    Command::new(env!("CARGO_BIN_EXE_mareu"))
}

#[test]
fn analyze_json_reports_findings() {
    let out = mareu()
        .args(["analyze", "tests/fixtures/parser.c", "--output", "json"])
        .output()
        .expect("run mareu");
    assert!(out.status.success());
    let v: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("valid json on stdout");
    assert_eq!(v["command"], "analyze");
    assert_eq!(v["ai_used"], false);
    let findings = v["findings"].as_array().unwrap();
    assert!(!findings.is_empty());
    // The tainted memcpy should be the top (critical) finding.
    assert_eq!(findings[0]["severity"], "CRITICAL");
    assert_eq!(findings[0]["cwe"], "CWE-787");
}

#[test]
fn analyze_reads_stdin() {
    use std::io::Write;
    use std::process::Stdio;
    let mut child = mareu()
        .args(["analyze", "--output", "json"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"void f(){ char b[8]; strcpy(b, x); }")
        .unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["target"], "<stdin>");
    assert!(!v["findings"].as_array().unwrap().is_empty());
}

#[test]
fn scaffold_intent_check_refuses_named_target() {
    let out = mareu()
        .args(["scaffold", "--type", "poc", "--vuln", "pwn target.victim.com"])
        .output()
        .unwrap();
    // Exit code 2 = intent refusal (RFC §4.2).
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn scaffold_exploit_requires_unsafe() {
    let out = mareu()
        .args(["scaffold", "--type", "exploit", "--class", "bof", "--vuln", "x"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("--unsafe"));
}

#[test]
fn scaffold_template_is_deterministic_and_runnable_shape() {
    let out = mareu()
        .args(["scaffold", "--type", "poc", "--class", "bof", "--vuln", "x", "--no-color"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let body = String::from_utf8_lossy(&out.stdout);
    assert!(body.contains("int main"));
    assert!(body.contains("status: SCAFFOLD"));
}

#[test]
fn mcp_stdio_lists_tools_and_calls_analyze() {
    use std::io::{BufRead, BufReader, Write};
    use std::process::Stdio;

    let mut child = mareu()
        .arg("mcp")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();

    // Write the JSON-RPC session from a thread so reading can run concurrently.
    let mut stdin = child.stdin.take().unwrap();
    let writer = std::thread::spawn(move || {
        let msgs = [
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05"}}"#,
            r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#,
            r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"mareu_analyze","arguments":{"content":"void f(){char b[8];strcpy(b,x);}"}}}"#,
        ];
        for m in msgs {
            writeln!(stdin, "{m}").unwrap();
        }
        // Drop stdin to signal EOF so the server exits.
    });

    let stdout = child.stdout.take().unwrap();
    let mut responses = Vec::new();
    for line in BufReader::new(stdout).lines() {
        let line = line.unwrap();
        if line.trim().is_empty() {
            continue;
        }
        responses.push(serde_json::from_str::<serde_json::Value>(&line).unwrap());
        if responses.len() == 3 {
            break;
        }
    }
    writer.join().unwrap();
    let _ = child.wait();

    let by = |id: i64| responses.iter().find(|m| m["id"] == id).unwrap();

    // initialize
    assert_eq!(by(1)["result"]["serverInfo"]["name"], "mareu");
    // tools/list — all four tools present
    let tools = by(2)["result"]["tools"].as_array().unwrap();
    assert_eq!(tools.len(), 4);
    let names: Vec<&str> = tools.iter().map(|t| t["name"].as_str().unwrap()).collect();
    assert!(names.contains(&"mareu_analyze"));
    assert!(names.contains(&"mareu_scaffold"));
    // tools/call analyze — returns non-error structured content with a finding
    let call = &by(3)["result"];
    assert_eq!(call["isError"], false);
    let inner: serde_json::Value =
        serde_json::from_str(call["content"][0]["text"].as_str().unwrap()).unwrap();
    assert!(!inner["findings"].as_array().unwrap().is_empty());
}

#[test]
fn dry_run_makes_no_network_call_and_prints_prompt() {
    let out = mareu()
        .args([
            "analyze",
            "tests/fixtures/parser.c",
            "--ai",
            "--dry-run",
            "--no-color",
        ])
        .output()
        .unwrap();
    assert!(out.status.success());
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(s.contains("SYSTEM PROMPT"));
    assert!(s.contains("vulnerability researcher"));
}
