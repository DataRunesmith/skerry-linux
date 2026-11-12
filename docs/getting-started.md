# Get started

## Requirements

<!-- coderabbit-ai-generated:v1 -->

<!-- coderabbit-ai-generated-section:v1:1f201c4d9e89bc05ec8158441941c4bd1c2bb2f0da61a4bebe5a331adba29457 -->

Rust 1.92 or newer and the development packages for GTK 4.12 or newer, libadwaita 1.5 or newer, GtkSourceView 5 and VTE for GTK4. On Debian 13, install `build-essential libgtk-4-dev libadwaita-1-dev libgtksourceview-5-dev libvte-2.91-gtk4-dev`.

<!-- /coderabbit-ai-generated:v1 -->

## Build and test

```sh
cd LinuxApp
cargo build --release
cargo test --locked
```

<!-- coderabbit-ai-generated:v1 -->

<!-- coderabbit-ai-generated-section:v1:0b1591fa903410c4eaad8954101cc7e3592fe4a829e07368d66d1202c1f33e09 -->

Some tests are marked `#[ignore]` because they need a running `sshd`, a public key listed in `~/.ssh/authorized_keys` with `SKERRY_TEST_SSH_KEY` pointing to its corresponding private key, an SSH agent, Docker or internet access. `docker_list_command_parses_real_dockerd_output` requires at least one container (running or stopped), and `forwarded_agent_is_reachable_from_the_remote_side` requires an identity loaded in the SSH agent. Run them with `cargo test -- --ignored`.

<!-- /coderabbit-ai-generated:v1 -->

## Packaging

<!-- coderabbit-ai-generated:v1 -->

<!-- coderabbit-ai-generated-section:v1:64e7bb6b574f5ec4114279b6d205290e092d9ec87df6cbd077a2b8430db337c0 -->

`LinuxApp/packaging` has a desktop entry and an RPM build script. `LinuxApp/integrations` is a separate crate for Docker, Kubernetes and Proxmox that declares `serde_json` as a dependency.

<!-- /coderabbit-ai-generated:v1 -->
