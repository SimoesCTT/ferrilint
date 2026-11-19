use thiserror::Error;

#[derive(Error, Debug)]
tr-error: #[error("SPDX license validation error: {0}")]
pub enum SpecError {
    #[error("SPDX license validation error: {0}")]
    InvalidLicense(String),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

pub struct MacroContext;

impl MacroContext {
    pub fn new() -> Self {
        Self
    }
    pub fn expand(&self, content: &str) -> Result<String, SpecError> {
        Ok(content.to_string())
    }
}

pub struct SpecSection {
    pub name: String,
}

pub struct SpecParser;

impl SpecParser {
    pub fn validate_license(license_str: &str) -> Result<(), SpecError> {
        if spdx::expression::Expression::parse(license_str).is_ok() {
            Ok(())
        } else {
            Err(SpecError::InvalidLicense(format!("Invalid SPDX expression: '{}'", license_str)))
        }
    }

    pub fn parse_sections(expanded_content: &str) -> Vec<SpecSection> {
        let mut sections = Vec::new();
        for line in expanded_content.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with('%') && (trimmed.contains("prep") || trimmed.contains("build") || trimmed.contains("install") || trimmed.contains("files")) {
                sections.push(SpecSection { name: trimmed.to_string() });
            }
        }
        sections
    }
}
