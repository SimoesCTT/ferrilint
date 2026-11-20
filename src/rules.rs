use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

use crate::elf::{ElfAudit, RelroStatus};

#[derive(Debug, Serialize, Deserialize)]
pub struct PolicyConfig {
    pub policy: PolicyMeta,
    pub rules: RulesSection,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PolicyMeta {
    pub name: String,
    pub version: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RulesSection {
    pub elf_hardening: Option<ElfHardeningRule>,
    pub path_policies: Option<PathPoliciesRule>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ElfHardeningRule {
    pub severity: String,
    pub require_pie: bool,
    pub require_full_relro: bool,
    pub require_nx: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PathPoliciesRule {
    pub severity: String,
    pub forbid_rpath: bool,
    pub forbidden_runpath_prefixes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditViolation {
    pub rule_name: &'static str,
    pub severity: String,
    pub message: String,
}

#[derive(Debug, Clone)]
pub struct TargetBinary {
    pub path: String,
    pub audit: ElfAudit,
}

impl PolicyConfig {
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self, Box<dyn std::error::Error>> {
        let contents = fs::read_to_string(path)?;
        let config: PolicyConfig = toml::from_str(&contents)?;
        Ok(config)
    }
}

pub fn evaluate_elf_audit(config: &PolicyConfig, target: &TargetBinary) -> Vec<AuditViolation> {
    let mut violations = Vec::new();
    let audit = &target.audit;

    if let Some(ref hardening) = config.rules.elf_hardening {
        if hardening.require_pie && !audit.is_pie {
            violations.push(AuditViolation {
                rule_name: "elf_hardening",
                severity: hardening.severity.clone(),
                message: "Missing PIE (Position Independent Executable)".to_string(),
            });
        }
        if hardening.require_full_relro && audit.relro != RelroStatus::Full {
            violations.push(AuditViolation {
                rule_name: "elf_hardening",
                severity: hardening.severity.clone(),
                message: format!("Inadequate RELRO status: {:?} (Full RELRO required)", audit.relro),
            });
        }
        if hardening.require_nx && !audit.has_nx {
            violations.push(AuditViolation {
                rule_name: "elf_hardening",
                severity: hardening.severity.clone(),
                message: "Missing NX (Non-executable stack) protection".to_string(),
            });
        }
    }

    if let Some(ref paths) = config.rules.path_policies {
        if paths.forbid_rpath && audit.has_rpath {
            violations.push(AuditViolation {
                rule_name: "path_policies",
                severity: paths.severity.clone(),
                message: "Contains deprecated DT_RPATH entry".to_string(),
            });
        }
        if let Some(ref runpath) = audit.runpath {
            for forbidden in &paths.forbidden_runpath_prefixes {
                if runpath.starts_with(forbidden) {
                    violations.push(AuditViolation {
                        rule_name: "path_policies",
                        severity: paths.severity.clone(),
                        message: format!("Forbidden RUNPATH prefix detected: '{}'", runpath),
                    });
                }
            }
        }
    }

    violations
}

pub fn audit_binaries_parallel(
    targets: &[TargetBinary],
    config: &PolicyConfig,
) -> Vec<(String, Vec<AuditViolation>)> {
    targets
        .par_iter()
        .map(|t| (t.path.clone(), evaluate_elf_audit(config, t)))
        .filter(|(_, violations)| !violations.is_empty())
        .collect()
}

pub fn export_sarif(violations: &[(String, Vec<AuditViolation>)]) -> String {
    let sarif_obj = serde_json::json!({
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "ferrilint",
                        "version": "0.1.0",
                        "informationUri": "https://github.com/SimoesCTT/ferrilint"
                    }
                },
                "results": violations.iter().flat_map(|(path, viols)| {
                    viols.iter().map(move |v| {
                        serde_json::json!({
                            "ruleId": v.rule_name,
                            "level": if v.severity == "error" { "error" } else { "warning" },
                            "message": {
                                "text": v.message
                            },
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {
                                            "uri": path
                                        }
                                    }
                                }
                            ]
                        })
                    })
                }).collect::<Vec<_>>()
            }
        ]
    });

    serde_json::to_string_pretty(&sarif_obj).unwrap_or_default()
}
