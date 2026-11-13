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

<!-- coderabbit-ai-generated:v1 -->

<!-- coderabbit-ai-generated-section:v1:64e7bb6b574f5ec4114279b6d205290e092d9ec87df6cbd077a2b8430db337c0 -->

`LinuxApp/packaging` has a desktop entry and an RPM build script. `LinuxApp/integrations` is a separate crate for Docker, Kubernetes and Proxmox that declares `serde_json` as a dependency.

<!-- /coderabbit-ai-generated:v1 -->
