use std::collections::HashMap;
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MacroError {
    RecursionLimitExceeded(String),
    UnterminatedMacro(String),
}

impl fmt::Display for MacroError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MacroError::RecursionLimitExceeded(m) => write!(f, "RecursionLimitExceeded(\"{}\")", m),
            MacroError::UnterminatedMacro(m) => write!(f, "UnterminatedMacro(\"{}\")", m),
        }
    }
}

impl std::error::Error for MacroError {}

pub struct MacroContext {
    macros: HashMap<String, String>,
}

impl MacroContext {
    pub fn new() -> Self {
        let mut macros = HashMap::new();
        macros.insert("_bindir".to_string(), "/usr/bin".to_string());
        macros.insert("_libdir".to_string(), "/usr/lib64".to_string());
        macros.insert("_sysconfdir".to_string(), "/etc".to_string());
        macros.insert("fedora".to_string(), "45".to_string());
        Self { macros }
    }

    pub fn define(&mut self, name: &str, value: &str) {
        self.macros.insert(name.to_string(), value.to_string());
    }

    pub fn expand(&mut self, input: &str) -> Result<String, MacroError> {
        for line in input.lines() {
            let trimmed = line.trim();
            if let Some(rest) = trimmed.strip_prefix("%global").or_else(|| trimmed.strip_prefix("%define")) {
                let parts: Vec<&str> = rest.split_whitespace().collect();
                if parts.len() >= 2 {
                    let key = parts[0];
                    let val = parts[1..].join(" ");
                    self.macros.insert(key.to_string(), val);
                }
            }
        }

        self.expand_str(input, 0, &mut Vec::new())
    }

    fn expand_str(&self, input: &str, depth: usize, active_macros: &mut Vec<String>) -> Result<String, MacroError> {
        if depth > 64 {
            return Err(MacroError::RecursionLimitExceeded(active_macros.last().cloned().unwrap_or_default()));
        }

        let mut lines_out = Vec::new();
        let lines: Vec<&str> = input.lines().collect();
        let mut idx = 0;

        while idx < lines.len() {
            let line = lines[idx];
            let trimmed = line.trim();

            if trimmed.starts_with("%if ") {
                let cond_expr = &trimmed[4..].trim();
                let condition_met = self.evaluate_condition(cond_expr)?;
                
                idx += 1;
                let mut true_branch = Vec::new();
                let mut false_branch = Vec::new();
                let mut in_else = false;
                let mut nesting = 1;

                while idx < lines.len() {
                    let l = lines[idx];
                    let t = l.trim();
                    if t.starts_with("%if ") {
                        nesting += 1;
                    } else if t == "%endif" {
                        nesting -= 1;
                        if nesting == 0 {
                            idx += 1;
                            break;
                        }
                    } else if t == "%else" && nesting == 1 {
                        in_else = true;
                        idx += 1;
                        continue;
                    }

                    if in_else {
                        false_branch.push(l);
                    } else {
                        true_branch.push(l);
                    }
                    idx += 1;
                }

                let active_branch = if condition_met { true_branch } else { false_branch };
                let branch_text = active_branch.join("\n");
                let expanded_branch = self.expand_str(&branch_text, depth + 1, active_macros)?;
                if !expanded_branch.is_empty() {
                    lines_out.push(expanded_branch);
                }
                continue;
            }

            let expanded_line = self.expand_line_macros(line, depth, active_macros)?;
            lines_out.push(expanded_line);
            idx += 1;
        }

        Ok(lines_out.join("\n"))
    }

    fn evaluate_condition(&self, expr: &str) -> Result<bool, MacroError> {
        let expanded = self.expand_str(expr, 0, &mut Vec::new())?;
        let parts: Vec<&str> = expanded.split_whitespace().collect();
        if parts.len() == 3 {
            let left = parts[0].parse::<i64>().unwrap_or(0);
            let op = parts[1];
            let right = parts[2].parse::<i64>().unwrap_or(0);
            return Ok(match op {
                "==" => left == right,
                "!=" => left != right,
                ">=" => left >= right,
                "<=" => left <= right,
                ">" => left > right,
                "<" => left < right,
                _ => false,
            });
        }
        Ok(expanded.trim() != "0" && !expanded.trim().is_empty())
    }

    fn expand_line_macros(&self, input: &str, depth: usize, active_macros: &mut Vec<String>) -> Result<String, MacroError> {
        let bytes = input.as_bytes();
        let mut result = String::with_capacity(input.len());
        let mut i = 0;

        while i < bytes.len() {
            if bytes[i] == b'%' && i + 1 < bytes.len() {
                if bytes[i + 1] == b'{' {
                    let start = i + 2;
                    if let Some(end) = input[start..].find('}') {
                        let end_pos = start + end;
                        let macro_expr = &input[start..end_pos];
                        
                        let (macro_name, is_optional) = if let Some(stripped) = macro_expr.strip_prefix('?') {
                            (stripped, true)
                        } else {
                            (macro_expr, false)
                        };

                        let val = if let Some(v) = self.macros.get(macro_name) {
                            v.clone()
                        } else if is_optional {
                            "".to_string()
                        } else {
                            format!("%{{{}}}", macro_expr)
                        };

                        active_macros.push(macro_name.to_string());
                        let expanded_val = self.expand_str(&val, depth + 1, active_macros)?;
                        active_macros.pop();

                        result.push_str(&expanded_val);
                        i = end_pos + 1;
                        continue;
                    }
                } else {
                    let start = i + 1;
                    let mut end = start;
                    while end < bytes.len() && (bytes[end].is_ascii_alphanumeric() || bytes[end] == b'_') {
                        end += 1;
                    }
                    if end > start {
                        let macro_name = &input[start..end];
                        if let Some(v) = self.macros.get(macro_name) {
                            active_macros.push(macro_name.to_string());
                            let expanded_val = self.expand_str(v, depth + 1, active_macros)?;
                            active_macros.pop();
                            result.push_str(&expanded_val);
                        } else {
                            result.push('%');
                            result.push_str(macro_name);
                        }
                        i = end;
                        continue;
                    }
                }
            }
            result.push(bytes[i] as char);
            i += 1;
        }

        Ok(result)
    }
}
