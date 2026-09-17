# gnome-foreground-booster

Temporarily raise device-memory protection for the focused application in GNOME.
The service watches Mutter's `user.xdg.inactive-since` cgroup attribute and changes
the application's `dmem.low` values. It restores the previous values when focus
is lost or the service stops.

## Requirements

- Linux with cgroup v2 and a working dmem controller and driver.
- A Mutter version that writes `user.xdg.inactive-since` on application cgroups.
- A systemd user manager and user D-Bus session bus, with applications in `.scope`
  or `.service` cgroups beneath `app.slice`.
- The system and user [dmemcg-booster](https://github.com/razzeee/dmemcg-booster)
  services, including the [unit-notification retry fix](https://github.com/razzeee/dmemcg-booster/pull/1).
  They enable the controller and protect ancestor cgroups.

See [operation and recovery](docs/operation.md) for permissions, service ordering,
and recovery behavior.

## Build and install

Use a current Rust toolchain with edition 2024 support, a C toolchain,
`pkg-config`, and the libdbus development files, provided by `libdbus-1-dev` on
Debian-based systems.

Run these commands from this project's directory:

```sh
cargo build --release --locked
sudo install -Dm755 target/release/gnome-foreground-booster /usr/bin/gnome-foreground-booster
sudo install -Dm644 gnome-foreground-booster.service /usr/lib/systemd/user/gnome-foreground-booster.service
systemctl --user daemon-reload
systemctl --user enable --now gnome-foreground-booster.service
```

Enable the service from a GNOME graphical session. It starts and stops with
`graphical-session.target` and restarts on failure. The binary accepts no
arguments and runs as your user, without `sudo`.

To inspect its messages:

```sh
journalctl --user -u gnome-foreground-booster.service
```

## Development

See the [development guide](docs/development.md) for test commands and live
GNOME verification.
