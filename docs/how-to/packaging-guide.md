# Packaging Guide

This guide details how downstream package maintainers and distribution architects can build, package, and distribute `sigil` across Linux distributions (Arch Linux, Debian/Ubuntu, Fedora/RHEL, and NixOS).

---

## 1. Package Artifacts & File Placements

Under the modern zero-friction envelope architecture (ADR-0002), `sigil` operates as an integrated desktop infrastructure daemon with zero requirement for an administrative CLI. All credential queries are serviced via standard freedesktop.org interfaces (interoperable with `secret-tool`, browsers, and portals).

| Artifact | Source Location | Standard Installation Target | Mode |
|---|---|---|:---:|
| Daemon Binary | `target/release/sigil` | `/usr/bin/sigil` | `0755` |
| Native GUI Prompter | `target/release/sigil-prompter` | `/usr/bin/sigil-prompter` | `0755` |
| PAM Security Module | `target/release/libpam_sigil.so` | `/usr/lib/security/pam_sigil.so` | `0755` |
| systemd User Service | `systemd/user/sigil.service` | `/usr/lib/systemd/user/sigil.service` | `0644` |
| systemd Socket Unit | `systemd/user/sigil.socket` | `/usr/lib/systemd/user/sigil.socket` | `0644` |
| D-Bus Service | `dbus/org.freedesktop.secrets.service` | `/usr/share/dbus-1/services/org.freedesktop.secrets.service` | `0644` |

*Note on Debian/Ubuntu*: PAM modules may reside in `/usr/lib/x86_64-linux-gnu/security/` or `/lib/x86_64-linux-gnu/security/`.

---

## 2. Dependencies

### Build Dependencies
- Rust toolchain >= 1.80 (`cargo`, `rustc`)
- C compiler (`gcc` or `clang`)
- PAM development headers (`pam-devel` on Fedora/Arch; `libpam0g-dev` on Debian/Ubuntu)
- `pkg-config`
- Wayland / Vulkan client libraries (for `sigil-prompter` native rendering via Optics)

### Runtime Dependencies
- Linux PAM (`pam`)
- Session bus daemon (`dbus` / `dbus-broker`)
- Session manager (`systemd`)

---

## 3. Distribution Packaging Recipes

### Arch Linux (`PKGBUILD`)

```bash
# Maintainer: Atrium Desktop Team <dev@atrium-desktop.org>
pkgname=sigil
pkgver=1.3.4
pkgrel=1
pkgdesc="Industrial-grade, zero-friction Freedesktop Secret Service infrastructure daemon"
arch=('x86_64' 'aarch64')
url="https://github.com/atrium-desktop/sigil"
license=('MIT')
depends=('pam' 'systemd')
makedepends=('cargo' 'pkgconf')
optdepends=(
  'libsecret: for standard CLI inspection via secret-tool'
  'swaylock: screen unlock integration'
  'hyprlock: screen unlock integration'
)
provides=('org.freedesktop.secrets')
conflicts=('gnome-keyring')
source=("$pkgname-$pkgver.tar.gz::$url/archive/refs/tags/v$pkgver.tar.gz")
sha256sums=('SKIP')

prepare() {
  cd "$pkgname-$pkgver"
  export RUSTUP_TOOLCHAIN=stable
  cargo fetch --locked --target "$(rustc -vV | sed -n 's/host: //p')"
}

build() {
  cd "$pkgname-$pkgver"
  export RUSTUP_TOOLCHAIN=stable
  cargo build --frozen --release --workspace
}

check() {
  cd "$pkgname-$pkgver"
  export RUSTUP_TOOLCHAIN=stable
  cargo test --frozen --workspace
}

package() {
  cd "$pkgname-$pkgver"

  # Binaries
  install -Dm755 target/release/sigil "$pkgdir/usr/bin/sigil"
  install -Dm755 target/release/sigil-prompter "$pkgdir/usr/bin/sigil-prompter"

  # PAM module
  install -Dm755 target/release/libpam_sigil.so "$pkgdir/usr/lib/security/pam_sigil.so"

  # systemd user units
  install -Dm644 systemd/user/sigil.service "$pkgdir/usr/lib/systemd/user/sigil.service"
  install -Dm644 systemd/user/sigil.socket "$pkgdir/usr/lib/systemd/user/sigil.socket"

  # D-Bus service definition
  install -Dm644 dbus/org.freedesktop.secrets.service "$pkgdir/usr/share/dbus-1/services/org.freedesktop.secrets.service"
}
```

---

### Fedora / RHEL (`sigil.spec`)

```spec
Name:           sigil
Version:        1.3.4
Release:        1%{?dist}
Summary:        Industrial-grade, zero-friction Freedesktop Secret Service daemon

License:        MIT
URL:            https://github.com/atrium-desktop/sigil
Source0:        %{url}/archive/refs/tags/v%{version}.tar.gz

BuildRequires:  cargo
BuildRequires:  rust >= 1.80
BuildRequires:  pam-devel
BuildRequires:  pkgconfig
BuildRequires:  systemd-rpm-macros

Requires:       pam
Requires:       systemd
Provides:       org.freedesktop.secrets

%description
Sigil is an industrial-grade credential management service providing full Freedesktop
Secret Service API support alongside zero-touch auto-provisioning and memory zeroization.

%prep
%autosetup -p1

%build
cargo build --release --workspace

%check
cargo test --workspace

%install
# Binaries
install -D -p -m 0755 target/release/sigil %{buildroot}%{_bindir}/sigil
install -D -p -m 0755 target/release/sigil-prompter %{buildroot}%{_bindir}/sigil-prompter

# PAM module
install -D -p -m 0755 target/release/libpam_sigil.so %{buildroot}%{_libdir}/security/pam_sigil.so

# systemd user units
install -D -p -m 0644 systemd/user/sigil.service %{buildroot}%{_userunitdir}/sigil.service
install -D -p -m 0644 systemd/user/sigil.socket %{buildroot}%{_userunitdir}/sigil.socket

# D-Bus service
install -D -p -m 0644 dbus/org.freedesktop.secrets.service %{buildroot}%{_datadir}/dbus-1/services/org.freedesktop.secrets.service

%post
%systemd_user_post sigil.socket

%preun
%systemd_user_preun sigil.socket

%files
%license LICENSE
%doc README.md
%{_bindir}/sigil
%{_bindir}/sigil-prompter
%{_libdir}/security/pam_sigil.so
%{_userunitdir}/sigil.service
%{_userunitdir}/sigil.socket
%{_datadir}/dbus-1/services/org.freedesktop.secrets.service
```

---

### Debian / Ubuntu (`debian/rules`)

```makefile
#!/usr/bin/make -f
export DH_VERBOSE = 1

%:
	dh $@ --buildsystem=cargo

override_dh_auto_install:
	# Install binaries
	install -D -m 0755 target/release/sigil debian/sigil/usr/bin/sigil
	install -D -m 0755 target/release/sigil-prompter debian/sigil/usr/bin/sigil-prompter

	# Install PAM module (multi-arch security directory)
	install -D -m 0755 target/release/libpam_sigil.so debian/sigil/lib/$(DEB_HOST_MULTIARCH)/security/pam_sigil.so

	# Install systemd user units
	install -D -m 0644 systemd/user/sigil.service debian/sigil/usr/lib/systemd/user/sigil.service
	install -D -m 0644 systemd/user/sigil.socket debian/sigil/usr/lib/systemd/user/sigil.socket

	# Install D-Bus service
	install -D -m 0644 dbus/org.freedesktop.secrets.service debian/sigil/usr/share/dbus-1/services/org.freedesktop.secrets.service
```

---

### NixOS Module Example

```nix
{ config, lib, pkgs, ... }:

with lib;

let
  cfg = config.services.sigil;
in {
  options.services.sigil = {
    enable = mkEnableOption "Sigil Freedesktop Secret Service daemon";
  };

  config = mkIf cfg.enable {
    security.pam.services.system-login.text = mkDefault ''
      auth     optional ${pkgs.sigil}/lib/security/pam_sigil.so
      password optional ${pkgs.sigil}/lib/security/pam_sigil.so
      session  optional ${pkgs.sigil}/lib/security/pam_sigil.so
    '';

    systemd.user.sockets.sigil = {
      description = "Sigil Credential Service Native Activation Socket";
      wantedBy = [ "sockets.target" ];
      socketConfig = {
        ListenStream = "%t/sigil/native.sock";
        SocketMode = "0600";
        DirectoryMode = "0700";
      };
    };

    systemd.user.services.sigil = {
      description = "Sigil Secret Service Daemon";
      after = [ "sigil.socket" ];
      wants = [ "sigil.socket" ];
      serviceConfig = {
        ExecStart = "${pkgs.sigil}/bin/sigil";
        Type = "dbus";
        BusName = "org.freedesktop.secrets";
      };
    };
  };
}
```

---

## 4. Packaging Verification Checklist

1. [ ] Socket activation is configured: `sigil.socket` enabled in user presets (`/usr/lib/systemd/user-preset/`).
2. [ ] Binary permissions are `0755` and PAM module permissions are `0755`.
3. [ ] D-Bus service triggers activation on `org.freedesktop.secrets`.
4. [ ] Legacy `gnome-keyring` conflicts are handled cleanly.
