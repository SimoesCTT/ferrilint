Name:           ferrilint
Version:        0.1.0
Release:        1%{?dist}
Summary:        Lightning-fast native RPM linter and inspection suite in pure Rust

License:        MIT
URL:            https://github.com/SimoesCTT/ferrilint
Source0:        %{name}-%{version}-vendor.tar.xz

BuildRequires:  rust
BuildRequires:  cargo

%description
Lightning-fast native RPM linter, spec auditor, CPIO walker, and ELF security 
audit suite written in 100% pure Rust with zero FFI and Rayon parallel concurrency. 
Features built-in CI profiles and native TOML security policy rules.

%prep
%autosetup -n %{name}-%{version} -p1

%build
%set_build_flags
cargo build --release --offline

%install
rm -rf %{buildroot}
install -Dm 0755 target/release/ferrilint %{buildroot}%{_bindir}/ferrilint
install -Dm 0644 ferrilint.toml %{buildroot}%{_sysconfdir}/ferrilint.toml

%files
%{_bindir}/ferrilint
%config(noreplace) %{_sysconfdir}/ferrilint.toml
%doc README.md

%changelog
* Fri Nov 20 2026 Americo Simoes <simoes@samaramas.com> - 0.1.0-1
- Initial release of ferrilint native pure-Rust RPM linter and ELF security suite
