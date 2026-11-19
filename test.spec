Name:           ferrilint-demo
Version:        1.0.0
Release:        1%{?dist}
Summary:        A lightning-fast native RPM linter demo
License:        MIT OR Apache-2.0
URL:            https://github.com/SimoesCTT/ferrilint

%description
A demonstration package for ferrilint zero-FFI static analysis validation.

%prep
%autosetup -p1

%build
%cargo_build

%install
%cargo_install

%files
%license LICENSE
%doc README.md
