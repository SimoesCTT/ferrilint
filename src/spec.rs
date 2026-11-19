#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpecAuditReport {
    pub has_undefine_hardened_build: bool,
    pub uses_hardened_macros: bool,
    pub warnings: Vec<String>,
}

pub fn audit_spec(content: &str) -> SpecAuditReport {
    let mut has_undefine_hardened_build = false;
    let mut uses_hardened_macros = false;
    let mut warnings = Vec::new();

    for line in content.lines() {
        let trimmed = line.trim();

        if trimmed.starts_with("%undefine") && trimmed.contains("_hardened_build") {
            has_undefine_hardened_build = true;
        }

        if trimmed.contains("%cmake") || trimmed.contains("%configure") || trimmed.contains("%cargo_build") || trimmed.contains("%set_build_flags") {
            uses_hardened_macros = true;
        }
    }

    if has_undefine_hardened_build {
        warnings.push("Security warning: _hardened_build is explicitly undefined in this spec file.".to_string());
    }

    if !uses_hardened_macros {
        warnings.push("Best practice warning: Standard build macro (%cmake, %configure, %cargo_build, %set_build_flags) not detected.".to_string());
    }

    SpecAuditReport {
        has_undefine_hardened_build,
        uses_hardened_macros,
        warnings,
    }
}
