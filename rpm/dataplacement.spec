Summary: dataplacement
Name: dataplacement
Version: 0.0.7
Release: 1%{?dist}
License: Apache 2.0
Url: https://github.com/matyasselmeci/dataplacement-exp
Source0: %{name}-%{version}.tar.gz
Requires: /usr/sbin/condor_placementd
Requires: /usr/sbin/nginx
Requires: condor
Buildarch: noarch


%description
dataplacement


%prep
%autosetup

%build
exit 0

%install
cd nginxdp
%make_install PREFIX=%{_prefix} UNITDIR=%{_unitdir}
mkdir -p ${RPM_BUILD_ROOT}/srv/dataplacement/{files,files_upload,files_upload_tmp}
mkdir -p ${RPM_BUILD_ROOT}/var/log/dataplacement
touch ${RPM_BUILD_ROOT}/srv/dataplacement/dataauth.sock

%files
%config(noreplace) /etc/nginxdp.ini
%{_unitdir}/dataauth.service
%{_unitdir}/nginxdp.service
%{_unitdir}/uploadmover.service
%{_unitdir}/nginxdp.target
/usr/sbin/dataauth.py
/usr/sbin/uploadmover.py
/usr/sbin/nginxdp.py
/usr/sbin/nginxdp_config.py
/usr/share/dataplacement/*
%attr(755,nginx,nginx) %dir /srv/dataplacement
%ghost /srv/dataplacement/dataauth.sock
%attr(755,nginx,nginx) %dir /srv/dataplacement/files
%attr(755,nginx,nginx) %dir /srv/dataplacement/files_upload
%attr(755,nginx,nginx) %dir /srv/dataplacement/files_upload_tmp
%attr(751,nginx,root) %dir /var/log/dataplacement

%changelog
* Fri Oct 30 2026 Mátyás Selmeci <mselmeci@wisc.edu> - 0.0.7
- Set subsys-specific options

* Fri Oct 30 2026 Mátyás Selmeci <mselmeci@wisc.edu> - 0.0.6
- Have nginx be the one to drop privs (so it can read root-owned files such as the host key)

* Thu Oct 29 2026 Mátyás Selmeci <mselmeci@wisc.edu> - 0.0.5
- Fix permissions issues

* Thu Oct 29 2026 Mátyás Selmeci <mselmeci@wisc.edu> - 0.0.4
- Add systemd files

* Thu Oct 29 2026 Mátyás Selmeci <mselmeci@wisc.edu> - 0.0.3
- Initial


# vim:ft=spec
