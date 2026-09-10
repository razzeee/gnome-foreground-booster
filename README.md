# gnome-foreground-booster

Temporarily raise device-memory protection for the focused GNOME application.
The service watches Mutter's `user.xdg.inactive-since` cgroup attribute and changes
the application's `dmem.low` values. It restores the previous values when focus
is lost or the service stops.

This is an independent Rust project extracted from
[dmemcg-booster](https://github.com/razzeee/dmemcg-booster), commit `aba1db5`.
It has no source or Cargo workspace dependency on that project. The directory
can be moved into its own repository. Derived code retains the original MIT
license notice in [LICENSE](LICENSE).

## Requirements

- Linux with cgroup v2 and a working dmem controller and driver.
- A Mutter version that writes `user.xdg.inactive-since` on application cgroups.
- A systemd user manager and user D-Bus session bus.
- Applications running in `.scope` or `.service` cgroups beneath the user
  manager's `app.slice`.
- Readable root `dmem.capacity`, writable application `dmem.low`, and readable
  and writable user xattrs on application cgroups.
- Controller enablement and protection on ancestor cgroups, including
  `app.slice` and the user service hierarchy.

Today, the system and user **dmemcg-booster** services supply controller and
ancestor setup. This foreground service does not enable controllers or modify
ancestor limits. Future systemd support must provide equivalent configuration
before the shim can be removed.

Registration retries once per second when application dmem files are unavailable
or unwritable. Missing focus attributes do not cause a boost. More than one
active application is treated as ambiguous, so none is selected until the
attributes identify a single active application.

## Build and install

Use a current Rust toolchain with edition 2024 support, a C toolchain,
`pkg-config`, and the libdbus development files. For example, Debian-based
systems provide the latter through `libdbus-1-dev`.

Run these commands from this project's directory:

```sh
cargo build --release --locked
sudo install -Dm755 target/release/gnome-foreground-booster /usr/bin/gnome-foreground-booster
sudo install -Dm644 gnome-foreground-booster.service /usr/lib/systemd/user/gnome-foreground-booster.service
systemctl --user daemon-reload
systemctl --user enable --now gnome-foreground-booster.service
```

Enable the service from a GNOME graphical session with the prerequisites in
place. It starts with `graphical-session.target`, stops when that target stops,
and restarts on failure. The ordering after `dmemcg-booster-user.service` applies
when both services are started; it does not start or require the shim itself.

The binary accepts no arguments and always uses the user session bus. Run it
without `sudo`. Inspect its messages with:

```sh
journalctl --user -u gnome-foreground-booster.service
```

## Upgrade from the integrated foreground implementation

The previous dmemcg-booster user binary also applied foreground protection. Stop
it before starting this service:

```sh
systemctl --user stop dmemcg-booster-user.service
```

Install the simplified dmemcg-booster binary and the foreground binary and unit,
then run:

```sh
systemctl --user daemon-reload
systemctl --user start dmemcg-booster-user.service
systemctl --user enable --now gnome-foreground-booster.service
```

Keep the system-level shim service enabled for privileged ancestor setup. Its
next restart should also use the simplified binary.

The foreground service claims `org.gnome.ForegroundBooster` on the user bus
before changing limits. A second instance on the same bus exits with an error.
The old integrated binary does not claim this name, so it must be stopped during
the upgrade. Separate private session buses do not share this ownership check.

## Recovery state

For each changed region, the service saves the original value and the value it
will apply before writing `dmem.low`. The boost never lowers an existing limit.
After focus loss, it restores a value only if the current value still matches
the recorded boost. Differing external writes are preserved, though these
reads and writes are not an atomic transaction with other limit writers.

The record uses `user.dmemcg-booster.dmem-low-state`, format `v1`. The historical
name is intentional: the new service can recover records left by the integrated
version without migrating or discarding original limits. These records support
process crash and restart recovery and disappear with their cgroup.

SIGINT, SIGTERM, and D-Bus processing failures trigger a restoration attempt.
Failed cleanup retains the recovery record for retry or a replacement process.
Stopping the service normally is preferable to killing it, since a crash leaves
the boost in place until recovery runs or the cgroup disappears.

## Verification

```sh
cargo fmt --check
cargo test --locked
dbus-run-session -- cargo test --locked tests::ownership_rejects_duplicates_and_is_released_on_disconnect -- --ignored --exact
cargo build --release --locked
```

The ownership test is ignored in the normal run because it needs an isolated
session bus. The other tests use fake I/O or temporary directories with real
xattrs and inotify. They do not modify live cgroup limits.

For a live GNOME check, record the original `dmem.low` values for two application
cgroups, switch focus between them, and confirm the focused application's boost
and the previous application's restoration. Stop the service and confirm
restoration again. To check crash recovery, restart after interrupting the
process while boosted and confirm that a later focus loss restores the original
baseline. This requires a compatible Mutter session and dmem-capable hardware;
the automated tests do not establish those capabilities.
