Here is the complete, production-ready `README.md` for `ferrilint` incorporating the Fedora Copr installation instructions, core subcommands, and CI/SARIF usage examples:

```markdown
# ferrilint

`ferrilint` is a lightning-fast native RPM linter, spec auditor, CPIO walker, and ELF security audit suite written in 100% pure Rust with zero FFI and Rayon parallel concurrency. Designed for Fedora packagers and modern CI pipelines, it enforces strict security policies and build best practices.

---

## Features

- **Blazing Fast Concurrency:** Built with Rayon for parallel multi-target inspection.
- **Spec Auditing (`lint-spec`):** Validates RPM spec files for missing standard build macros, hardened flags, and best practices.
- **Package Inspection (`lint`):** Deeply inspects built SRPM and binary RPM packages for integrity and structure.
- **ELF Security Policy (`policy`):** Audits compiled binaries and shared libraries against strict hardening policies (RELRO, PIE, Stack Canaries, etc.).
- **Standards-Compliant Reporting:** Native support for SARIF 2.1.0 and JSON export for seamless integration with security dashboards and CI/CD tools.

---

## Installation

### Fedora (via Copr)
You can install the official stable release directly from the Copr repository:

```bash
sudo dnf copr enable simoesctt/ferrilint
sudo dnf install ferrilint

```

---

## Usage & CLI Subcommands

### 1. Audit an RPM Spec File

Inspect local spec files for build macros and security compliance:

```bash
ferrilint lint-spec ferrilint.spec

```

### 2. Inspect SRPM or Binary RPM Packages

Verify package integrity and contents:

```bash
ferrilint lint ~/rpmbuild/RPMS/x86_64/ferrilint-0.1.0-1.fc45.x86_64.rpm

```

### 3. Run ELF Security Policy Audits

Audit system binaries or custom builds against a TOML security policy profile:

```bash
ferrilint policy /usr/bin/ls --config ferrilint.toml

```

---

## Configuration (`ferrilint.toml`)

Define custom security rules and profiles using standard TOML configuration:

```toml
[profile.fedora-strict-security]
require_full_relro = true
require_pie = true
require_stack_protector = true



---

## License

Distributed under the MIT License. See `LICENSE` for more information.


