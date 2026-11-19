%bcond check 0
%global cargo_install_lib 0

Name:           ferrilint
Version:        0.1.0
Release:        1%{?dist}
Summary:        Lightning-fast native RPM linter and inspection suite in pure Rust

License:        MIT OR Apache-2.0
URL:            https://github.com/SimoesCTT/ferrilint
Source0:        %{url}/archive/refs/tags/v%{version}.tar.gz
Source1:        %{name}-%{version}-vendor.tar.xz

BuildRequires:  cargo
BuildRequires:  rust
BuildRequires:  rust-packaging >= 24

%description
A lightning-fast, drop-in static analysis engine and package inspection suite
for .spec files, source RPMs (.src.rpm), and binary RPMs (.rpm), built entirely
in pure Rust to eliminate Python overhead and legacy FHS false positives.
Features built-in CI profiles (fedora-ci, strict, minimal) and native rpmlint.toml
filter compatibility.

%prep
%autosetup -n %{name}-%{version} -p1 -a 1
%cargo_prep -v vendor

%build
%cargo_build
%cargo_vendor_manifest

%install
%cargo_install

%if %{with check}
%check
%cargo_test
%endif

%files
%license LICENSE
%license cargo-vendor.txt
%doc README.md
%{_bindir}/ferrilint

%changelog
* Thu Nov 19 2026 A. Simões <simoesctt@github> - 0.1.0-1
- Initial release of ferrilint native RPM linter suite with CI profiles
