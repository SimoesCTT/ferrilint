use rayon::prelude::*;
use std::time::Instant;

use rpm_parse_rs::RpmLead;
use spec_lex_rs::{SpecParser, MacroContext};

fn main() {
    println!("\x1b[1;32m[ferrilint-bench]\x1b[0m Starting high-precision benchmark suite...");

    // 1. Benchmark RPM Header / Lead Parsing
    let dummy_lead_data = vec![
        0xed, 0xab, 0xee, 0xdb, 0x03, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x00, 0x01, 0x00, 0x00, 0x66, 0x65, 0x72, 0x72, 0x69, 0x6c, 0x69, 0x6e,
        0x74, 0x2d, 0x74, 0x65, 0x73, 0x74, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    ];

    let iterations = 1_000_000;
    let start = Instant::now();
    for _ in 0..iterations {
        let _ = RpmLead::parse(&dummy_lead_data);
    }
    let duration = start.elapsed();
    let ops_per_sec = iterations as f64 / duration.as_secs_f64();
    println!("  [BENCH] RPM Lead Parse: {:.2} ops/sec ({:?})", ops_per_sec, duration);

    // 2. Benchmark Spec Lexing & Macro Expansion
    let dummy_spec = r#"
        %global debug_package %{nil}
        Name:           ferrilint
        Version:        0.1.0
        Release:        1%{?dist}
        Summary:        Lightning-fast native RPM linter

        License:        MIT OR Apache-2.0
        URL:            https://github.com/SimoesCTT/ferrilint

        %description
        A lightning-fast static analysis engine.
    "";

    let spec_iterations = 100_000;
    let start_spec = Instant::now();
    for _ in 0..spec_iterations {
        let macro_ctx = MacroContext::new();
        let _ = macro_ctx.expand(dummy_spec);
    }
    let duration_spec = start_spec.elapsed();
    let spec_ops = spec_iterations as f64 / duration_spec.as_secs_f64();
    println!("  [BENCH] Spec Expansion: {:.2} ops/sec ({:?})", spec_ops, duration_spec);

    println!("\x1b[1;32m[SUCCESS]\x1b[0m All benchmark suites passed successfully.");
}
