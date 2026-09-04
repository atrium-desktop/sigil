# Packaging Guide

This guide details how downstream package maintainers and system integrators can build, package, and distribute `sigil` across Linux distributions (Arch Linux, Debian/Ubuntu, Fedora/RHEL, and NixOS).

---

## 1. Package Artifacts & File Placements

A full distribution package of `sigil` produces the following binaries, libraries, and integration files:

| Artifact | Source Location | Standard Installation Target | Permissions |
|---|---|---|:---:|
| Daemon Binary | `target/release/sigil` | `/usr/bin/sigil` | `0755` |
| CLI Utility | `target/release/sigil-cli` | `/usr/bin/sigil-cli` | `0755` |
| GUI Prompter | `target/release/sigil-prompter` | `/usr/bin/sigil-prompter` | `0755` |
| PAM Module | `target/release/libpam_sigil.so` | `/usr/lib/security/pam_sigil.so` | `0755` |
| systemd User Unit | `systemd/user/sigil.service` | `/usr/lib/systemd/user/sigil.service` | `0644` |
| D-Bus Service | `dbus/org.freedesktop.secrets.service` | `/usr/share/dbus-1/services/org.freedesktop.secrets.service` | `0644` |

*Note*: On Debian/Ubuntu systems, PAM modules may reside in `/lib/x86_64-linux-gnu/security/` or `/lib/security/`.

---

## 2. Dependencies

### Build Dependencies

- Rust toolchain >= 1.80 (cargo, rustc)
- C compiler (`gcc` or `clang`)
- PAM development headers (`pam-devel` on Fedora/Arch; `libpam0g-dev` on Debian/Ubuntu)
- `pkg-config`

### Runtime Dependencies

- `glibc` or `musl`
- `pam` (Linux PAM)
- `dbus` / `dbus-broker` (session bus)
- `systemd` (user session manager)

---

## 3. Distribution Packaging Recipes

### Arch Linux (`PKGBUILD`)

```bash
# Maintainer: Sigil Project <dev@atrium-desktop.org>
pkgname=sigil
pkgver=1.2.2
pkgrel=1
pkgdesc="Secure, memory-first Freedesktop Secret Service implementation"
arch=('x86_64' 'aarch64')
url="https://github.com/atrium-desktop/sigil"
license=('Apache-2.0' 'MIT')
depends=('pam' 'systemd')
makedepends=('cargo' 'pkgconf')
optdepends=(
  'swaylock: automatic vault unlock upon screensaver dismissal'
  'hyprlock: screensaver unlock integration'
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
  export CARGO_TARGET_DIR=target
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
  install -Dm755 target/release/sigil-cli "$pkgdir/usr/bin/sigil-cli"
  install -Dm755 target/release/sigil-prompter "$pkgdir/usr/bin/sigil-prompter"

  # PAM module
  install -Dm755 target/release/libpam_sigil.so "$pkgdir/usr/lib/security/pam_sigil.so"

  # systemd user service
  install -Dm644 systemd/user/sigil.service "$pkgdir/usr/lib/systemd/user/sigil.service"

  # D-Bus service definition
  install -Dm644 dbus/org.freedesktop.secrets.service "$pkgdir/usr/share/dbus-1/services/org.freedesktop.secrets.service"

  # Documentation and licenses
  install -Dm644 README.md "$pkgdir/usr/share/doc/$pkgname/README.md"
  install -Dm644 SECURITY.md "$pkgdir/usr/share/doc/$pkgname/SECURITY.md"
}
```

---

### Fedora / RHEL (`sigil.spec`)

```spec
Name:           sigil
Version:        1.2.2
Release:        1%{?dist}
Summary:        Memory-first Secret Service daemon and PAM module

License:        Apache-2.0 OR MIT
URL:            https://github.com/atrium-desktop/sigil
Source0:        %{url}/archive/refs/tags/v%{version}.tar.gz

BuildRequires:  cargo
BuildRequires:  rust
BuildRequires:  pam-devel
BuildRequires:  pkgconfig
BuildRequires:  systemd-rpm-macros

Requires:       pam
Requires:       systemd

Provides:       desktop-notification-daemon
Provides:       org.freedesktop.secrets

%description
sigil is a secure, memory-first Freedesktop Secret Service daemon
providing end-to-end encryption, zero-disk PAM unlock, and sandboxed
per-app Portal secrets.

%prep
%autosetup -p1

%build
cargo build --release --workspace

%install
install -D -p -m 0755 target/release/sigil %{buildroot}%{_bindir}/sigil
install -D -p -m 0755 target/release/sigil-cli %{buildroot}%{_bindir}/sigil-cli
install -D -p -m 0755 target/release/sigil-prompter %{buildroot}%{_bindir}/sigil-prompter
install -D -p -m 0755 target/release/libpam_sigil.so %{buildroot}%{_libdir}/security/pam_sigil.so
install -D -p -m 0644 systemd/user/sigil.service %{buildroot}%{_userunitdir}/sigil.service
install -D -p -m 0644 dbus/org.freedesktop.secrets.service %{buildroot}%{_datadir}/dbus-1/services/org.freedesktop.secrets.service

%check
cargo test --release --workspace

%post
%systemd_user_post sigil.service

%preun
%systemd_user_preun sigil.service

%files
%license LICENSE*
%doc README.md SECURITY.md
%{_bindir}/sigil
%{_bindir}/sigil-cli
%{_bindir}/sigil-prompter
%{_libdir}/security/pam_sigil.so
%{_userunitdir}/sigil.service
%{_datadir}/dbus-1/services/org.freedesktop.secrets.service
```

---

### Debian / Ubuntu (`debian/rules` & structure)

For Debian packages, maintainers typically split packages into:
1. `sigil` (daemon, CLI, systemd, D-Bus)
2. `libpam-sigil` (the PAM security module)
3. `sigil-prompter` (standalone prompt dialog)

#### `debian/control` Example
```control
Source: sigil
Section: admin
Priority: optional
Maintainer: Atrium Desktop Team <dev@atrium-desktop.org>
Build-Depends: debhelper-compat (= 13), cargo, rustc, libpam0g-dev, pkg-config
Standards-Version: 4.6.2

Package: sigil
Architecture: any
Depends: ${shlibs:Depends}, ${misc:Depends}, libpam-sigil (= ${binary:Version})
Provides: org.freedesktop.secrets
Description: Memory-first desktop secret service daemon
 sigil implements the org.freedesktop.secrets API with memory-only
 unlock tokens and per-application isolation.

Package: libpam-sigil
Section: admin
Architecture: any
Depends: ${shlibs:Depends}, ${misc:Depends}
Description: PAM module for sigil automatic memory unlock
 Transmits login passwords directly to sigil over native Unix sockets
 without creating files on disk.
```

---

### Nix / NixOS (`default.nix`)

```nix
{ lib, rustPlatform, pam, pkg-config }:

rustPlatform.buildRustPackage rec {
  pname = "sigil";
  version = "1.2.2";

  src = ./.;

  cargoLock = {
    lockFile = ./Cargo.lock;
  };

  nativeBuildInputs = [ pkg-config ];
  buildInputs = [ pam ];

  postInstall = ''
    install -Dm755 target/release/libpam_sigil.so $out/lib/security/pam_sigil.so
    install -Dm644 systemd/user/sigil.service $out/lib/systemd/user/sigil.service
    install -Dm644 dbus/org.freedesktop.secrets.service $out/share/dbus-1/services/org.freedesktop.secrets.service
  '';

  meta = with lib; {
    description = "Hardened, memory-first Freedesktop Secret Service daemon";
    homepage = "https://github.com/atrium-desktop/sigil";
    license = licenses.asl20;
    platforms = platforms.linux;
  };
}
```

---

## 4. Post-Installation & User Session Triggers

1. **Reload systemd user daemon**:
   ```bash
   systemctl --user daemon-reload
   ```
2. **Enable automatic startup on session login**:
   ```bash
   systemctl --user enable sigil.service
   ```
3. **D-Bus Coexistence Notice**:
   Because only one provider may own `org.freedesktop.secrets` on the user session bus, package post-install scripts should advise users to mask or disable conflicting services:
   ```bash
   systemctl --user mask gnome-keyring-daemon.service
   ```
   For detailed migration steps, see [Troubleshooting D-Bus Conflicts](troubleshoot-dbus-conflicts.md).
