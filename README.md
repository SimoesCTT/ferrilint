# ferrilint — The Native, Zero-FFI RPM Linter in Rust

`ferrilint` is a lightning-fast, drop-in static analysis engine and package inspection suite for `.spec` files, source RPMs (`.src.rpm`), and binary RPMs (`.rpm`). Built entirely in **pure Rust**, it completely eliminates Python overhead, external C subprocesses (`librpm`), and legacy FHS/spelling false positives.

---

## 🏗️ Core Architecture & Crate Stack

- **`rpm-parse-rs`**: Zero-copy parsing of RPM headers, leads, signatures, and SVR4 CPIO payloads using pure Rust byte slices.
- **`elf-inspect-rs`**: Native ELF64 header inspection, dynamic section parsing, symbol analysis, and security hardening flag audits (`RELRO`, `PIE`, `NX`, Stack Canaries) without spawning binutils (`readelf`/`objdump`).
- **`spec-lex-rs`**: High-performance `.spec` file lexer, macro expander (`%define`, `%global`, nested expansions), section parser (`%prep`, `%build`, `%install`, `%files`), and SPDX expression validator.
- **`ferrilint-cli`**: Multithreaded parallel execution engine powered by **Rayon**, featuring native CI profiles and filter compatibility.
- **`ferrilint-bench`**: High-precision performance benchmarking harness.

---

## ⚙️ CI Profiles & `rpmlint.toml` Compatibility

To eliminate CI false-positive friction and config drift, `ferrilint` supports built-in profiles and native ingestion of existing ignore rules:

```bash
# Run with Fedora CI gating rules (suppresses spelling & FHS false positives)
ferrilint lint --profile fedora-ci .

# Run with full strict security checks
ferrilint lint --profile strict .

# Fast structural validation only
ferrilint lint --profile minimal .
ferrilint automatically detects and parses local rpmlint.toml (Filters = [...]) and legacy .rpmlintrc (addFilter("...")) directives.
##🚀 Installation & Usage
Building from Source
cargo build --release --workspace

## Installing Globally (~/.local/bin)
mkdir -p ~/.local/bin
cp target/release/ferrilint-cli ~/.local/bin/ferrilint
chmod +x ~/.local/bin/ferrilint

## 📜 License
Licensed under either the MIT License or Apache License 2.0, at your option.
