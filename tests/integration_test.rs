use ferrilint::{audit_elf, audit_spec, CpioReader, MacroContext};

#[test]
fn test_macro_expansion_basic() {
    let mut ctx = MacroContext::new();
    ctx.define("name", "ferrilint");
    ctx.define("version", "0.1.0");

    let input = "Name: %{name}\nVersion: %{version}";
    let expanded = ctx.expand(input).unwrap();
    assert!(expanded.contains("Name: ferrilint"));
    assert!(expanded.contains("Version: 0.1.0"));
}

#[test]
fn test_macro_conditionals() {
    let mut ctx = MacroContext::new();
    let input = "%if 0%{?fedora} >= 40\nFeature: enabled\n%else\nFeature: disabled\n%endif";
    let expanded = ctx.expand(input).unwrap();
    assert!(expanded.contains("Feature: enabled"));
    assert!(!expanded.contains("Feature: disabled"));
}

#[test]
fn test_cpio_reader_invalid_magic() {
    let dummy_data = vec![0u8; 110];
    let mut reader = CpioReader::new(&dummy_data);
    let result = reader.next();
    assert!(result.is_some());
    assert!(result.unwrap().is_err());
}

#[test]
fn test_elf_audit_mock() {
    let mut elf_data = vec![0u8; 128];
    // ELF magic
    elf_data[0..4].copy_from_slice(b"\x7fELF");
    // Class 64-bit (2)
    elf_data[4] = 2;
    // e_type = ET_DYN (3)
    elf_data[16] = 3;
    elf_data[17] = 0;

    let audit = audit_elf(&elf_data).unwrap();
    assert!(audit.is_pie);
}

#[test]
fn test_spec_linter() {
    let spec_content = r#"
        Name: test-pkg
        Version: 1.0.0
        %undefine _hardened_build
        %build
        ./configure
    "#;

    let report = audit_spec(spec_content);
    assert!(report.has_undefine_hardened_build);
    assert!(!report.warnings.is_empty());

    let hardened_spec = r#"
        Name: test-pkg
        Version: 1.0.0
        %build
        %cmake
    "#;
    let report_hardened = audit_spec(hardened_spec);
    assert!(!report_hardened.has_undefine_hardened_build);
    assert!(report_hardened.uses_hardened_macros);
}
