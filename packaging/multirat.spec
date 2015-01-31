Name:	multirat	
Summary:	CAPI for smartbonding
Version:	0.1.25
Release:	1
Group:		Development/Libraries
License:	TO_BE_FILLED_IN
URL:	N/A	
Source0:	%{name}-%{version}.tar.gz

#Requires(post): sys-assert
#BuildRequires: pkgconfig(capi-base-common)
#BuildRequires: pkgconfig(bundle)
BuildRequires: pkgconfig(glib-2.0)
BuildRequires: pkgconfig(dlog)
BuildRequires: pkgconfig(dbus-1)
BuildRequires: pkgconfig(dbus-glib-1)
BuildRequires: pkgconfig(vconf)
BuildRequires: pkgconfig(libcares)
BuildRequires: pkgconfig(capi-network-connection)
BuildRequires: pkgconfig(capi-network-wifi)
#BuildRequires: pkgconfig(capi-appfw-application)
#BuildRequires: pkgconfig(download-provider)
BuildRequires: cmake
#BuildRequires: expat-devel
Requires: dbus-glib

%description
CAPI for SMARTBONDING

%package devel
Summary:	smartbonding
Group:		Development/Libraries
Requires:	%{name} = %{version}-%{release}

%description devel
CAPI for SMARTBONDING (developement files)

%prep
%setup -q

%build
#cmake . -DCMAKE_INSTALL_PREFIX="/"

#make %{?jobs:-j%jobs}

export LDFLAGS+="-Wl,--rpath=%{_prefix}/lib -Wl,--as-needed"
mkdir cmake_tmp
cd cmake_tmp
LDFLAGS="$LDFLAGS" cmake .. -DCMAKE_INSTALL_PREFIX=%{_prefix}
cmake .. -DCMAKE_INSTALL_PREFIX=%{_prefix}
make %{?jobs:-j%jobs}



%install
rm -rf %{buildroot}
cd cmake_tmp
%make_install
mkdir -p %{buildroot}/usr/share/license

%post -p /sbin/ldconfig

%postun -p /sbin/ldconfig

%files 
%manifest multirat.manifest
%attr(755,root,root) 
%{_libdir}/libmultirat.so* 

%files devel
%attr(755,root,root) 
%{_libdir}/pkgconfig/multirat.pc
/usr/include/multirat/multirat_libapi.h
/usr/include/multirat/multirat_process.h
/usr/include/multirat/multirat_SB_http.h
/usr/include/multirat/multirat_conf.h
/usr/include/multirat/smartbonding-client.h

