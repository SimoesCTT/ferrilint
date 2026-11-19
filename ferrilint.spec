%global rust_edition 2024

Name:           ferrilint
Version:        0.1.0
Release:        1%{?dist}
Summary:        Lightning-fast native RPM linter and inspection suite in pure Rust

License:        MIT OR Apache-2.0
URL:            https://github.com/SimoesCTT/ferrilint
Source0:        %{url}/archive/refs/tags/%{name}-%{version}.tar.gz

BuildRequires:  cargo
BuildRequires:  rust
BuildRequires:  rust-packaging >= 24
BuildRequires:  rustfmt

%description
A lightning-fast, drop-in static analysis engine and package inspection suite 
for .spec files, source RPMs (.src.rpm), and binary RPMs (.rpm), built entirely 
in pure Rust to eliminate Python overhead and legacy FHS false positives.

%prep
%autosetup -n %{name}-%{version} -p1
%cargo_prep

%build
%cargo_build

%install
install -D -p -m 0755 target/release/ferrilint-cli %{buildroot}%{_bindir}/ferrilint

%files
%license LICENSE
%doc README.md
%{_bindir}/ferrilint

%changelog
* Thu Nov 19 2026 A. Simões <simoesctt@github> - 0.1.0-1
- Initial release of ferrilint native RPM linter suite
