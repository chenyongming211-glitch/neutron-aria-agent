Name:           aria-firewall
Version:        0.1.0
Release:        1%{?dist}
Summary:        eBPF/XDP Firewall with LPM trie and port-based policy

License:        MIT
URL:            https://github.com/chenyongming211-glitch/aria-firewall
Source0:        %{url}/archive/v%{version}.tar.gz

Requires:       systemd
BuildRequires:  make gcc rust cargo

%description
Aria Firewall is a high-performance eBPF/XDP firewall with LPM trie
for CIDR-based IP matching and port bitmap for policy rules.

%prep
# Extract source if needed

%build
# Already compiled, just copy files
mkdir -p %{_builddir}/aria-firewall-%{version}
cp -r * %{_builddir}/aria-firewall-%{version}/

%install
# Install binary
install -Dm755 %{_builddir}/aria-firewall-%{version}/target/x86_64-unknown-linux-gnu/release/firewall-ctl %{buildroot}%{_bindir}/firewall-ctl

# Install eBPF library
install -Dm755 %{_builddir}/aria-firewall-%{version}/target/x86_64-unknown-linux-gnu/release/libebpf_firewall.so %{buildroot}%{_libdir}/libebpf_firewall.so

# Install systemd service
install -Dm644 %{_builddir}/aria-firewall-%{version}/aria-firewall.service %{buildroot}%{_unitdir}/aria-firewall.service

# Create directories
mkdir -p %{buildroot}%{_localstatedir}/lib/aria-firewall
mkdir -p %{buildroot}%{_sysconfdir}/aria-firewall

%files
%{_bindir}/firewall-ctl
%{_libdir}/libebpf_firewall.so
%{_unitdir}/aria-firewall.service
%dir %attr(0755,root,root) %{_localstatedir}/lib/aria-firewall
%dir %attr(0755,root,root) %{_sysconfdir}/aria-firewall

%post
systemctl daemon-reload 2>/dev/null || true

%postun
systemctl daemon-reload 2>/dev/null || true

%changelog
* Wed Mar 11 2026 Aria Firewall <chenyongming211@gmail.com> - 0.1.0-1
- Initial RPM package
