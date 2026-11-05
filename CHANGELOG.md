# Changelog

## [2.7.0] - 2026-11-05

### Features

* **panorama-5layer:** unify 5-layer host introspection across macOS & Linux — Homebrew (`Formulae` + `Casks`), macOS `/Applications`, Docker/OrbStack/Colima/Podman (`ServerVersion` + running containers + local images), global toolchains (`npm -g`, `bun`, `cargo install`, `uv`, `pyenv`, `conda`, `rustup`, `sdkman`, `mise`), and clickable Panorama Asset Explorer (`sectl assets` & GUI modal)
* **exemption-ux:** strip cross-generational Apple `_major` OS upgrades from security vulnerability counts, and add 3-tier `Skip-Version` / `Snooze 30d` / `Permanent Mute` controls (`sectl mute` / `sectl unmute` & GUI Triage `已豁免/暂缓` manager)

## [2.6.0] - 2026-11-05

### Features

* **cve-radar:** add dedicated Daily Latest CVE Intelligence Center (`sectl cve` & native GPU `每日最新 CVE` page) with multi-dimensional filtering across Language Ecosystems (GHSA), OS Distributions (Debian DSA / Ubuntu USN / Red Hat), Linux Kernel (NIST NVD 2.0), and Importance (`CRITICAL` / `HIGH` / `MEDIUM`)
* **telegram-digest:** push standalone categorized Daily CVE Digest cards to Telegram (`sectl cve --push`, GUI 1-click push, and automated daily digest with duplicate suppression)
* **arch:** organize `internal/` into 5 unidirectional domain layers (`infra`, `scan`, `heal`, `ops`, `app`)
* **workspace:** 6-worker Go concurrent dependency upgrades (`uv pip` + native Maven/Gradle `~/.m2` transitive POM resolver + safe OS Trash cleaner)
* **desktop:** native MyGo GPU Menu Bar Sentinel (`⌘⇧S`) + Mission Control (`DiffViewer`, OS Keychain vault, smart WezTerm tab launcher, streaming `~/.ssh/config` host discovery, and in-app visual scheduler)
