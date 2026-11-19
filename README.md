# ferrilint

High-performance, pure-Rust RPM linter and binary security audit suite.

## Features

- Spec Macro Expansion (spec): Pure-Rust RPM macro expander with multi-line conditional block support (%if, %else, %endif).
- Spec Hardening Linter (lint-spec): Audits RPM spec files for security flags, hardening macros, and standard build macros (%cmake, %configure, %cargo_build, %set_build_flags).
- CPIO Archive Traversal (cpio): Zero-copy SVR4 newc CPIO archive reader (CpioReader).
- ELF Security Auditing (elf): Comprehensive inspection of PIE, RELRO status, NX, and RPATH/RUNPATH properties.

## Installation via Fedora Copr

    sudo dnf copr enable @simoes/ferrilint
    sudo dnf install ferrilint

## Usage

    # Expand RPM macros in a spec file
    ferrilint spec package.spec

    # Audit an RPM spec file for hardening and standards
    ferrilint lint-spec package.spec

    # Inspect a CPIO archive
    ferrilint cpio payload.cpio

    # Audit an ELF binary for security features
    ferrilint elf /usr/bin/some-binary

## License

MIT
