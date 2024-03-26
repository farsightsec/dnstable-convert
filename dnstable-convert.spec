%global debug_package %{nil}
Name:           dnstable-convert
Version:        0.13.0
Release:        1%{?dist}
Summary:        A utility for converting dnstable files to different formats

License:        Apache-2.0
URL:            https://github.com/farsightsec/dnstable-convert
Source0:        https://dl.farsightsecurity.com/dist/dnstable-convert/%{name}-%{version}.tar.gz
BuildRequires:  gcc make pkgconfig wdns-devel >= 0.11.0 mtbl-devel >= 1.5.0 libnmsg-devel nmsg-msg-module-sie-devel dnstable-devel
Requires:       dnstable mtbl nmsg-msg-module-sie

%description
Convert passive DNS NMSG data to and from dnstable MTBL

%prep
%setup -q 

%build
[ -x configure ] || autoreconf -fvi
%configure
make %{?_smp_mflags}

%install
rm -rf $RPM_BUILD_ROOT
%make_install

%files
%{_bindir}/dnstable_convert
%{_bindir}/dnstable_unconvert
%{_mandir}/man1/dnstable_convert.1.gz
%{_mandir}/man1/dnstable_unconvert.1.gz

%doc README.md COPYRIGHT LICENSE

%changelog
