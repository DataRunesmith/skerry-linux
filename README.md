# Skerry for Linux

An SSH and host-management app for the Linux desktop, written in Rust with GTK4 and libadwaita.

## Build and test

Requires Rust 1.92 or newer and the development packages for GTK4, libadwaita and GtkSourceView 5 (on Debian: `libgtk-4-dev libadwaita-1-dev libgtksourceview-5-dev`).

```sh
cd LinuxApp
cargo build --release
cargo test --locked
```

Some tests are marked `#[ignore]` because they need a running `sshd`, a private key listed in `~/.ssh/authorized_keys` (pass its path in `SKERRY_TEST_SSH_KEY`), an SSH agent, Docker or internet access. Run them with `cargo test -- --ignored`.

`LinuxApp/packaging` has a desktop entry and an RPM build script. `LinuxApp/integrations` is a separate crate for Docker, Kubernetes and Proxmox with no dependencies of its own.
