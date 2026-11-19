use clap::ValueEnum;
use regex::Regex;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum LintProfile {
    /// Curated zero-noise profile matching Fedora CI gating rules
    FedoraCi,
    /// Full security & spec compliance checks including pedantic warnings
    Strict,
    /// Fast structural & SPDX validation only (no ELF hardening failures)
    Minimal,
}

pub struct AuditPolicy {
    pub profile: LintProfile,
    pub enforce_elf_hardening: bool,
    pub ignore_patterns: Vec<Regex>,
}

impl AuditPolicy {
    pub fn load(profile: LintProfile, target_dir: &Path) -> Self {
        let enforce_elf_hardening = matches!(profile, LintProfile::FedoraCi | LintProfile::Strict);
        let mut ignore_patterns = Vec::new();

        if profile == LintProfile::FedoraCi {
            for pat in [
                r"spelling-error",
                r"no-manual-page-for-binary",
                r"incoherent-version-in-changelog",
            ] {
                if let Ok(re) = Regex::new(pat) {
                    ignore_patterns.push(re);
                }
            }
        }

        let search_root = if target_dir.is_file() {
            target_dir.parent().unwrap_or_else(|| Path::new("."))
        } else {
            target_dir
        };

        // Native line-based parsing for rpmlint.toml Filters = ["..."]
        let toml_path = search_root.join("rpmlint.toml");
        if let Ok(content) = fs::read_to_string(&toml_path) {
            for line in content.lines() {
                let trimmed = line.trim();
                if trimmed.starts_with('"') || trimmed.starts_with('\'') {
                    if let Some(pat) = trimmed.strip_prefix('"').and_then(|s| s.strip_suffix('"'))
                        .or_else(|| trimmed.strip_prefix('\'').and_then(|s| s.strip_suffix('\''))) 
                    {
                        if let Ok(re) = Regex::new(pat) {
                            ignore_patterns.push(re);
                        }
                    }
                }
            }
        }

        // Native .rpmlintrc addFilter("...") parser
        let rc_path = search_root.join(".rpmlintrc");
        if let Ok(content) = fs::read_to_string(&rc_path) {
            if let Ok(extract_re) = Regex::new(r#"addFilter\(\s*["']([^"']+)["']\s*\)"#) {
                for cap in extract_re.captures_iter(&content) {
                    if let Some(pat) = cap.get(1) {
                        if let Ok(re) = Regex::new(pat.as_str()) {
                            ignore_patterns.push(re);
                        }
                    }
                }
            }
        }

        Self {
            profile,
            enforce_elf_hardening,
            ignore_patterns,
        }
    }

    pub fn is_ignored(&self, diagnostic: &str) -> bool {
        self.ignore_patterns.iter().any(|re| re.is_match(diagnostic))
    }
}
