use clap::{Parser, Subcommand};
use ferrilint::{audit_elf, audit_spec, CpioReader, MacroContext};
use std::fs;
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "ferrilint",
    version,
    about = "High-performance pure-Rust RPM linter & binary audit suite"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Expand RPM macros in a spec file
    Spec {
        #[arg(help = "Path to RPM spec file")]
        path: PathBuf,
    },
    /// Audit RPM spec security and hardening flags
    LintSpec {
        #[arg(help = "Path to RPM spec file")]
        path: PathBuf,
    },
    /// Parse and walk SVR4 newc CPIO archive
    Cpio {
        #[arg(help = "Path to CPIO archive")]
        path: PathBuf,
    },
    /// Audit ELF binary security properties (PIE, RELRO, NX, RPATH/RUNPATH)
    Elf {
        #[arg(help = "Path to ELF binary")]
        path: PathBuf,
    },
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Spec { path } => {
            let content = fs::read_to_string(&path)?;
            let mut ctx = MacroContext::new();
            let expanded = ctx.expand(&content)?;
            print!("{}", expanded);
        }
        Commands::LintSpec { path } => {
            let content = fs::read_to_string(&path)?;
            let report = audit_spec(&content);
            println!("RPM Spec Security Audit for {:?}", path);
            println!("  Hardened Macros Used: {}", report.uses_hardened_macros);
            println!("  Undefine Hardened Build: {}", report.has_undefine_hardened_build);
            if report.warnings.is_empty() {
                println!("  Status: CLEAN (No hardening warnings)");
            } else {
                println!("  Warnings:");
                for w in &report.warnings {
                    println!("    - {}", w);
                }
            }
        }
        Commands::Cpio { path } => {
            let data = fs::read(&path)?;
            let reader = CpioReader::new(&data);
            for entry in reader {
                match entry {
                    Ok(e) => println!("{} ({} bytes, mode: {:o})", e.path, e.data.len(), e.mode),
                    Err(err) => eprintln!("CPIO error: {:?}", err),
                }
            }
        }
        Commands::Elf { path } => {
            let data = fs::read(&path)?;
            match audit_elf(&data) {
                Ok(audit) => {
                    println!("ELF Security Audit for {:?}", path);
                    println!("  PIE:        {}", audit.is_pie);
                    println!("  RELRO:      {:?}", audit.relro);
                    println!("  NX:         {}", audit.has_nx);
                    println!("  Exec Stack: {}", audit.stack_executable);
                    println!("  Has RPATH:  {}", audit.has_rpath);
                    println!("  RUNPATH:    {:?}", audit.runpath);
                }
                Err(err) => eprintln!("ELF audit error: {:?}", err),
            }
        }
    }

    Ok(())
}
