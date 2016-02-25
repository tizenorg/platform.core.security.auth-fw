Name:       authentication-server
Summary:    Authentication server
Version:    0.0.1
Release:    1
Group:      Security/Service
License:    Apache-2.0
Source0:    %{name}-%{version}.tar.gz
Source1001: %{name}.manifest
Source1002: lib%{name}-client.manifest
Source1003: lib%{name}-client-admin.manifest
BuildRequires: cmake
BuildRequires: pkgconfig(dlog)
BuildRequires: pkgconfig(openssl)
BuildRequires: pkgconfig(libsmack)
BuildRequires: pkgconfig(libsystemd-daemon)
BuildRequires: pkgconfig(libtzplatform-config)
%{?systemd_requires}

%description
Authentication server with client libraries

%package -n lib%{name}-client
Summary:    Authentication server (client)
Group:      Security/Libraries
Requires:   %{name} = %{version}-%{release}
Requires(post): /sbin/ldconfig
Requires(postun): /sbin/ldconfig

%description -n lib%{name}-client
Authentication server package (client)

%package -n lib%{name}-client-admin
Summary:    Authentication server (client-admin)
Group:      Security/Libraries
Requires:   %{name} = %{version}-%{release}
Requires(post): /sbin/ldconfig
Requires(postun): /sbin/ldconfig

%description -n lib%{name}-client-admin
Authentication server package (client-admin)

%package -n lib%{name}-client-devel
Summary:    Authentication server (client-devel)
Group:      Security/Development
Requires:   lib%{name}-client = %{version}-%{release}
Requires:   lib%{name}-client-admin = %{version}-%{release}

%description -n lib%{name}-client-devel
Authentication server package (client-devel)

%prep
%setup -q
cp -a %{SOURCE1001} %{SOURCE1002} %{SOURCE1003} .

%global run_dir %{?TZ_SYS_RUN:%TZ_SYS_RUN/}%{!?TZ_SYS_RUN:/var/run/}
%global sock_passwd_check %{name}-passwd-check.socket
%global sock_passwd_set %{name}-passwd-set.socket
%global sock_passwd_reset %{name}-passwd-reset.socket
%global sock_passwd_policy %{name}-passwd-policy.socket

%build

export CFLAGS="$CFLAGS -DTIZEN_DEBUG_ENABLE"
export CXXFLAGS="$CXXFLAGS -DTIZEN_DEBUG_ENABLE"
export FFLAGS="$FFLAGS -DTIZEN_DEBUG_ENABLE"
export LDFLAGS+="-Wl,--rpath=%{_libdir}"

%cmake . -DVERSION=%{version} \
        -DCMAKE_BUILD_TYPE=%{?build_type:%build_type}%{!?build_type:RELEASE} \
        -DCMAKE_VERBOSE_MAKEFILE=ON \
        -DSERVICE_NAME=%{name} \
        -DBIN_DIR:PATH=%{_bindir} \
        -DRUN_DIR:PATH=%{run_dir} \
        -DSYSTEMD_UNIT_DIR:PATH=%{_unitdir} \
        -DSOCK_PASSWD_CHECK=%{sock_passwd_check} \
        -DSOCK_PASSWD_SET=%{sock_passwd_set} \
        -DSOCK_PASSWD_RESET=%{sock_passwd_reset} \
        -DSOCK_PASSWD_POLICY=%{sock_passwd_policy}

make %{?jobs:-j%jobs}

%install
%make_install
%install_service multi-user.target.wants %{name}.service
%install_service sockets.target.wants %{sock_passwd_check}
%install_service sockets.target.wants %{sock_passwd_set}
%install_service sockets.target.wants %{sock_passwd_reset}
%install_service sockets.target.wants %{sock_passwd_policy}

%post
/sbin/ldconfig
systemctl daemon-reload
if [ $1 = 1 ]; then
    # installation
    systemctl start %{name}.service
fi

if [ $1 = 2 ]; then
    # update
    systemctl restart %{name}.service
fi

%preun
if [ $1 = 0 ]; then
    # unistall
    systemctl stop %{name}.service
fi

%postun
/sbin/ldconfig
if [ $1 = 0 ]; then
    # unistall
    systemctl daemon-reload
fi

%post -n lib%{name}-client -p /sbin/ldconfig

%postun -n lib%{name}-client -p /sbin/ldconfig

%post -n lib%{name}-client-admin -p /sbin/ldconfig

%postun -n lib%{name}-client-admin -p /sbin/ldconfig

%files
%manifest %{name}.manifest
%license LICENSE
%{_bindir}/%{name}
%{_libdir}/lib%{name}-commons.so.*
%{_unitdir}/%{name}.target
%{_unitdir}/%{name}.service
%{_unitdir}/multi-user.target.wants/%{name}.service
%{_unitdir}/%{sock_passwd_check}
%{_unitdir}/%{sock_passwd_set}
%{_unitdir}/%{sock_passwd_reset}
%{_unitdir}/%{sock_passwd_policy}
%{_unitdir}/sockets.target.wants/%{sock_passwd_check}
%{_unitdir}/sockets.target.wants/%{sock_passwd_set}
%{_unitdir}/sockets.target.wants/%{sock_passwd_reset}
%{_unitdir}/sockets.target.wants/%{sock_passwd_policy}

%files -n lib%{name}-client
%manifest lib%{name}-client.manifest
%license LICENSE
%{_libdir}/lib%{name}-client.so.*

%files -n lib%{name}-client-admin
%manifest lib%{name}-client-admin.manifest
%license LICENSE
%{_libdir}/lib%{name}-client-admin.so.*

%files -n lib%{name}-client-devel
%{_libdir}/lib%{name}-client.so
%{_libdir}/lib%{name}-client-admin.so
%{_libdir}/lib%{name}-commons.so
%{_includedir}/%{name}/auth-passwd.h
%{_includedir}/%{name}/auth-passwd-admin.h
%{_includedir}/%{name}/auth-passwd-error.h
%{_includedir}/%{name}/auth-passwd-policy-types.h
%{_libdir}/pkgconfig/*.pc
