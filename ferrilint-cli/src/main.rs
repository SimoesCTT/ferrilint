mod profile;

use clap::{Parser, Subcommand, CommandFactory};
use clap_complete::{generate, Shell};
use rayon::prelude::*;
use std::fs;
use std::path::PathBuf;
use walkdir::WalkDir;

use profile::{AuditPolicy, LintProfile};
use rpm_parse_rs::{RpmLead, CpioArchive};
use elf_inspect_rs::ElfInspector;
use spec_lex_rs::{SpecParser, MacroContext};

#[derive(Parser)]
#[command(name = "ferrilint", version, about = "Lightning-fast native RPM linter in pure Rust")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Recursively scan and lint .spec files or RPM packages using Rayon parallel iterators
    Lint {
        /// Path to file or directory to scan
        path: PathBuf,

        /// Deterministic CI ruleset profile (defaults to fedora-ci)
        #[arg(long, value_enum, default_value_t = LintProfile::FedoraCi)]
        profile: LintProfile,
    },
    /// Generate shell completion scripts (bash, zsh, fish, powershell, elvish)
    Completions {
        /// Target shell
        #[arg(value_enum)]
        shell: Shell,
    },
}

fn main() {
    let cli = Cli::parse();
    match cli.command {
        Commands::Lint { path, profile } => {
            if let Err(e) = run_lint(&path, profile) {
                println!("\x1b[1;31m[ERROR]\x1b[0m {}", e);
                std::process::exit(1);
            }
        }
        Commands::Completions { shell } => {
            let mut cmd = Cli::command();
            let bin_name = "ferrilint";
            generate(shell, &mut cmd, bin_name, &mut std::io::stdout());
        }
    }
}

fn run_lint(path: &PathBuf, profile: LintProfile) -> Result<(), Box<dyn std::error::Error>> {
    let policy = AuditPolicy::load(profile, path);
    println!(
        "\x1b[1;32m[ferrilint]\x1b[0m Scanning {:?} | Profile: {:?} | Active Ignore Rules: {}",
        path,
        policy.profile,
        policy.ignore_patterns.len()
    );

    let files: Vec<PathBuf> = WalkDir::new(path)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .map(|e| e.path().to_path_buf())
        .filter(|p| {
            if let Some(ext) = p.extension() {
                ext == "rpm" || ext == "spec"
            } else {
                false
            }
        })
        .collect();

    println!("\x1b[1;34m[INFO]\x1b[0m Discovered {} target(s). Running parallel audit via Rayon...", files.len());

    let results: Vec<(PathBuf, Result<String, String>)> = files
        .par_iter()
        .map(|file| {
            let res = audit_file(file, &policy);
            (file.clone(), res)
        })
        .collect();

    let mut errors_found = 0;
    for (file, res) in results {
        match res {
            Ok(msg) => {
                println!("  \x1b[32m[PASS]\x1b[0m {:?} -> {}", file, msg);
            }
            Err(err) => {
                if policy.is_ignored(&err) {
                    println!("  \x1b[33m[SKIP]\x1b[0m {:?} -> Suppressed by policy: {}", file, err);
                } else {
                    errors_found += 1;
                    println!("  \x1b[31m[FAIL]\x1b[0m {:?} -> {}", file, err);
                }
            }
        }
    }

    println!("\n\x1b[1;32m[SUMMARY]\x1b[0m Audit completed. {} error(s) found across {} target(s).", errors_found, files.len());
    if errors_found > 0 {
        std::process::exit(2);
    }
    Ok(())
}

fn audit_file(path: &PathBuf, policy: &AuditPolicy) -> Result<String, String> {
    let ext = path.extension().and_then(|s| s.to_str()).unwrap_or("");
    let data = fs::read(path).map_err(|e| format!("IO error: {}", e))?;

    if ext == "rpm" {
        let _ = RpmLead::parse(&data).map_err(|e| format!("rpm-lead-parse-error: {}", e))?;
        let security = ElfInspector::audit_bytes(&data).unwrap_or_default();

        if policy.enforce_elf_hardening && !security.nx {
            return Err("executable-stack-detected: PT_GNU_STACK has PF_X enabled".to_string());
        }

        let cpio_info = match CpioArchive::parse_entries(&data) {
            Ok(entries) => format!(" | CPIO Payload: {} files unpacked", entries.len()),
            Err(_) => "".to_string(),
        };

        Ok(format!(
            "Valid RPM package | Security (PIE: {}, RELRO: {}, NX: {}, StackCanary: {}){}",
            security.pie, security.relro, security.nx, security.stack_canary, cpio_info
        ))
    } else if ext == "spec" {
        let content = String::from_utf8_lossy(&data);
        let macro_ctx = MacroContext::new();
        let expanded = macro_ctx.expand(&content).map_err(|e| format!("macro-expansion-error: {}", e))?;

        for line in expanded.lines() {
            let trimmed = line.trim_start();
            if trimmed.starts_with("License:") {
                let lic = trimmed.split(':').nth(1).unwrap_or("").trim();
                SpecParser::validate_license(lic)
                    .map_err(|e| format!("invalid-spdx-license ('{}'): {}", lic, e))?;
            }
        }
        let sections = SpecParser::parse_sections(&expanded);
        let section_names: Vec<String> = sections.iter().map(|s| s.name.clone()).collect();
        Ok(format!("Valid .spec syntax | Sections: [{}]", section_names.join(", ")))
    } else {
        Err("unsupported-file-extension".to_string())
    }
}
