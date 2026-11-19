Name: %{name}
Version: %{version}
Summary: Test RPM spec for ferrilint

%global name ferrilint
%global version 0.1.0

%if 0%{?fedora} >= 40
BuildRequires: rustc cargo
%endif
