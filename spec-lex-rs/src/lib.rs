//! # spec-lex-rs
//! Advanced RPM spec file macro expander, section parser, and SPDX validator.

use std::collections::HashMap;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum SpecError {
    #[error("Invalid SPDX license expression: {0}")]
    InvalidSpdx(String),
    #[error("Unclosed macro expansion brace")]
    UnclosedBrace,
}

#[derive(Debug, Clone)]
pub struct SpecSection {
    pub name: String,
    pub content: String,
}

pub struct MacroContext {
    macros: HashMap<String, String>,
}

impl MacroContext {
    pub fn new() -> Self {
        let mut ctx = Self {
            macros: HashMap::new(),
        };
        ctx.macros.insert("_builddir".to_string(), "%{_topdir}/BUILD".to_string());
        ctx.macros.insert("_rpmdir".to_string(), "%{_topdir}/RPMS".to_string());
        ctx.macros.insert("dist".to_string(), ".fc45".to_string());
        ctx
    }

    pub fn define(&mut self, key: &str, val: &str) {
        self.macros.insert(key.to_string(), val.to_string());
    }

    pub fn expand(&self, input: &str) -> Result<String, SpecError> {
        let mut result = input.to_string();
        for _ in 0..5 {
            let mut changed = false;
            for (k, v) in &self.macros {
                let pattern1 = format!("%{{{}}}", k);
                let pattern2 = format!("%{}", k);
                if result.contains(&pattern1) {
                    result = result.replace(&pattern1, v);
                    changed = true;
                } else if result.contains(&pattern2) {
                    result = result.replace(&pattern2, v);
                    changed = true;
                }
            }
            if !changed {
                break;
            }
        }
        Ok(result)
    }
}

pub struct SpecParser;

impl SpecParser {
    pub fn validate_license(license_str: &str) -> Result<(), SpecError> {
        if spdx::Expression::parse(license_str).is_err() {
            return Err(SpecError::InvalidSpdx(license_str.to_string()));
        }
        Ok(())
    }

    pub fn parse_sections(content: &str) -> Vec<SpecSection> {
        let mut sections = Vec::new();
        let mut current_name = "header".to_string();
        let mut current_content = String::new();

        let valid_sections = [
            "%prep", "%build", "%install", "%check", "%clean", 
            "%files", "%changelog", "%description", "%package"
        ];

        for line in content.lines() {
            let trimmed = line.trim();
            let is_section = valid_sections.iter().any(|&s| trimmed.starts_with(s));

            if is_section {
                if !current_content.is_empty() {
                    sections.push(SpecSection {
                        name: current_name,
                        content: current_content,
                    });
                    current_content = String::new();
                }
                current_name = trimmed.split_whitespace().next().unwrap_or(trimmed).to_string();
            } else {
                current_content.push_str(line);
                current_content.push('\n');
            }
        }

        if !current_content.is_empty() {
            sections.push(SpecSection {
                name: current_name,
                content: current_content,
            });
        }

        sections
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_spdx_validation() {
        assert!(SpecParser::validate_license("MIT").is_ok());
        assert!(SpecParser::validate_license("MIT OR Apache-2.0").is_ok());
        assert!(SpecParser::validate_license("InvalidLicenseName").is_err());
    }

    #[test]
    fn test_macro_expansion() {
        let mut ctx = MacroContext::new();
        ctx.define("version", "1.0.0");
        let expanded = ctx.expand("Version: %{version}%{dist}").unwrap();
        assert_eq!(expanded, "Version: 1.0.0.fc45");
    }

    #[test]
    fn test_section_parsing() {
        let spec = "Name: test\n%prep\n%setup -q\n%build\nmake\n";
        let sections = SpecParser::parse_sections(spec);
        assert_eq!(sections.len(), 3);
        assert_eq!(sections[1].name, "%prep");
        assert_eq!(sections[2].name, "%build");
    }
}
