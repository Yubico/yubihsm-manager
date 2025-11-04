Name:           yubihsm-manager
Version:        0.2.0
Release:        1%{?dist}
Summary:        Command line tool for YubiHSM 2
License:        Apache-2.0
URL:            https://github.com/Yubico/yubihsm-manager

%description
Command line tool for YubiHSM 2

%prep

%build

%install
mkdir -p %{buildroot}/usr/bin
install -m 0755 $BIN_DIR/yubihsm-manager %{buildroot}/usr/bin/yubihsm-manager

%files
/usr/bin/yubihsm-manager

%changelog
* Mon Nov 03 2025 Your Name <your@email.com> - 0.2.0-1
- Build on Fedora 43