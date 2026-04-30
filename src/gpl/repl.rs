#![allow(dead_code, unused_variables, unused_imports)]
use crate::gpl::parser::GplParser;
use crate::gpl::validator::GplValidator;

pub fn run_repl() {
    use std::io::{self, BufRead, Write};
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut out = stdout.lock();
    writeln!(out, "GPL REPL — type 'exit' to quit").ok();
    let mut buf = String::new();
    for line in stdin.lock().lines() {
        let line = match line { Ok(l) => l, Err(_) => break };
        if line.trim() == "exit" { break; }
        buf.push_str(&line);
        buf.push('\n');
        if buf.contains('}') {
            match GplParser::parse(&buf) {
                Ok(policy) => {
                    let warnings = GplValidator::validate(&policy).unwrap_or_default();
                    writeln!(out, "OK: {} rules, {} warnings", policy.rules.len(), warnings.len()).ok();
                    for w in &warnings { writeln!(out, "  warning: {w}").ok(); }
                }
                Err(e) => { writeln!(out, "Error: {e}").ok(); }
            }
            buf.clear();
        }
    }
}
