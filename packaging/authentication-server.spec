Name:       authentication-server
Summary:    Authentication server
Version:    0.0.1
Release:    1
Group:      System/Security
License:    Apache-2.0
Source0:    %{name}-%{version}.tar.gz
BuildRequires: cmake
BuildRequires: pkgconfig(dlog)
BuildRequires: pkgconfig(openssl)
BuildRequires: pkgconfig(libsmack)
BuildRequires: pkgconfig(libsystemd-daemon)
%{?systemd_requires}

%description
Authentication server with client libraries

%package -n libauthentication-server-client
Summary:    Authentication server (client)
Group:      Development/Libraries
Requires:   authentication-server = %{version}-%{release}
Requires(post): /sbin/ldconfig
Requires(postun): /sbin/ldconfig

%description -n libauthentication-server-client
Authentication server package (client)

%package -n libauthentication-server-client-admin
Summary:    Authentication server (client-admin)
Group:      Development/Libraries
Requires:   authentication-server = %{version}-%{release}
Requires(post): /sbin/ldconfig
Requires(postun): /sbin/ldconfig

%description -n libauthentication-server-client-admin
Authentication server package (client-admin)

%package -n libauthentication-server-client-devel
Summary:    Authentication server (client-devel)
Group:      Development/Libraries
Requires:   libauthentication-server-client = %{version}-%{release}
Requires:   libauthentication-server-client-admin = %{version}-%{release}

%description -n libauthentication-server-client-devel
Authentication server package (client-devel)

%package -n authentication-server-devel
Summary:    Authentication (Development)
Group:      Development/Libraries
Requires:   authentication-server = %{version}-%{release}

%description -n authentication-server-devel
Authentication server package (Development)

%prep
%setup -q

%build

export CFLAGS="$CFLAGS -DTIZEN_DEBUG_ENABLE"
export CXXFLAGS="$CXXFLAGS -DTIZEN_DEBUG_ENABLE"
export FFLAGS="$FFLAGS -DTIZEN_DEBUG_ENABLE"
export LDFLAGS+="-Wl,--rpath=%{_libdir}"

%cmake . -DVERSION=%{version} \
        -DCMAKE_BUILD_TYPE=%{?build_type:%build_type}%{!?build_type:RELEASE} \
        -DCMAKE_VERBOSE_MAKEFILE=ON

make %{?jobs:-j%jobs}

%install
rm -rf %{buildroot}
mkdir -p %{buildroot}/usr/share/license
cp LICENSE %{buildroot}/usr/share/license/%{name}
cp LICENSE %{buildroot}/usr/share/license/libauthentication-server-client
cp LICENSE %{buildroot}/usr/share/license/libauthentication-server-client-admin
%make_install

mkdir -p %{buildroot}/usr/lib/systemd/system/multi-user.target.wants
mkdir -p %{buildroot}/usr/lib/systemd/system/sockets.target.wants
mkdir -p %{buildroot}/usr/lib/systemd/system/basic.target.wants
ln -s ../authentication-server.service %{buildroot}/usr/lib/systemd/system/multi-user.target.wants/authentication-server.service
ln -s ../authentication-server-passwd-check.socket %{buildroot}/usr/lib/systemd/system/sockets.target.wants/authentication-server-passwd-check.socket
ln -s ../authentication-server-passwd-set.socket %{buildroot}/usr/lib/systemd/system/sockets.target.wants/authentication-server-passwd-set.socket
ln -s ../authentication-server-passwd-reset.socket %{buildroot}/usr/lib/systemd/system/sockets.target.wants/authentication-server-passwd-reset.socket
ln -s ../authentication-server-passwd-policy.socket %{buildroot}/usr/lib/systemd/system/sockets.target.wants/authentication-server-passwd-policy.socket

%clean
rm -rf %{buildroot}

%post
systemctl daemon-reload
if [ $1 = 1 ]; then
    # installation
    systemctl start authentication-server.service
fi

if [ $1 = 2 ]; then
    # update
    systemctl restart authentication-server.service
fi

%preun
if [ $1 = 0 ]; then
    # unistall
    systemctl stop authentication-server.service
fi

%postun
if [ $1 = 0 ]; then
    # unistall
    systemctl daemon-reload
fi

%post -n libauthentication-server-client -p /sbin/ldconfig

%postun -n libauthentication-server-client -p /sbin/ldconfig

%post -n libauthentication-server-client-admin -p /sbin/ldconfig

%postun -n libauthentication-server-client-admin -p /sbin/ldconfig

%files -n authentication-server
%manifest %{_datadir}/authentication-server.manifest
%attr(755,root,root) /usr/bin/authentication-server
%{_libdir}/libauthentication-server-commons.so.*
%attr(-,root,root) /usr/lib/systemd/system/multi-user.target.wants/authentication-server.service
%attr(-,root,root) /usr/lib/systemd/system/authentication-server.service
%attr(-,root,root) /usr/lib/systemd/system/authentication-server.target
%attr(-,root,root) /usr/lib/systemd/system/sockets.target.wants/authentication-server-passwd-check.socket
%attr(-,root,root) /usr/lib/systemd/system/authentication-server-passwd-check.socket
%attr(-,root,root) /usr/lib/systemd/system/sockets.target.wants/authentication-server-passwd-set.socket
%attr(-,root,root) /usr/lib/systemd/system/authentication-server-passwd-set.socket
%attr(-,root,root) /usr/lib/systemd/system/sockets.target.wants/authentication-server-passwd-reset.socket
%attr(-,root,root) /usr/lib/systemd/system/authentication-server-passwd-reset.socket
%attr(-,root,root) /usr/lib/systemd/system/sockets.target.wants/authentication-server-passwd-policy.socket
%attr(-,root,root) /usr/lib/systemd/system/authentication-server-passwd-policy.socket

%{_datadir}/license/%{name}

%files -n libauthentication-server-client
%manifest %{_datadir}/libauthentication-server-client.manifest
%defattr(-,root,root,-)
%{_libdir}/libauthentication-server-client.so.*
%{_datadir}/license/libauthentication-server-client

%files -n libauthentication-server-client-admin
%manifest %{_datadir}/libauthentication-server-client-admin.manifest
%defattr(-,root,root,-)
%{_libdir}/libauthentication-server-client-admin.so.*
%{_datadir}/license/libauthentication-server-client-admin

%files -n libauthentication-server-client-devel
%defattr(-,root,root,-)
%{_libdir}/libauthentication-server-client.so
%{_libdir}/libauthentication-server-client-admin.so
%{_libdir}/libauthentication-server-commons.so
/usr/include/authentication-server/auth-passwd.h
/usr/include/authentication-server/auth-passwd-admin.h
/usr/include/authentication-server/auth-passwd-error.h
/usr/include/authentication-server/auth-passwd-policy-types.h
%{_libdir}/pkgconfig/*.pc

