# gnome-foreground-booster

Temporarily raise device-memory protection for the focused GNOME application.
The service watches Mutter's `user.xdg.inactive-since` cgroup attribute and changes
the application's `dmem.low` values. It restores the previous values when focus
is lost or the service stops.

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

Run the system and user [dmemcg-booster](https://github.com/razzeee/dmemcg-booster)
services to enable the controller and protect ancestor cgroups. This foreground
service handles individual applications; it does not enable controllers or
modify ancestor limits.

The companion must retry unit notifications when systemd has not yet assigned
`ControlGroup`. Without that retry, applications in a newly created nested slice
can remain without dmem files. Use a version containing the
[retry fix](https://github.com/razzeee/dmemcg-booster/pull/1), merged in
`9eb57f977996a800c1ff5a60f1dde556b3d9ddeb`.

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

The foreground service claims `org.gnome.ForegroundBooster` on the user bus
before changing limits. A second instance on the same bus exits with an error.
Separate private session buses do not share this ownership check.

## Recovery state

For each changed region, the service saves the original value and the value it
will apply before writing `dmem.low`. The boost never lowers an existing limit.
After focus loss, it restores a value only if the current value still matches
the recorded boost. Differing external writes are preserved, though these
reads and writes are not an atomic transaction with other limit writers.

The record uses `user.dmemcg-booster.dmem-low-state`, format `v1`. It preserves
original limits across process crashes and restarts and disappears with its cgroup.

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

### Companion integration tests

The integration suite runs both binaries, including the companion's system and
user processes, against private D-Bus services and a simulated cgroup filesystem.
Bubblewrap mounts the fixture over `/sys/fs/cgroup` in a separate mount namespace.
It exercises startup order, focus changes, external limit writes, duplicate
instances, crashes, D-Bus failure, cgroup recreation, and delayed unit setup.

Install `bubblewrap`, `dbus`, `python3-dbus`, and `python3-gi` on Debian-based
systems, and build both binaries. Then run:

```sh
/usr/bin/python3 tests/companion.py --companion /path/to/dmemcg-booster/target/release/dmemcg-booster
```

The test runner requires unprivileged user namespaces. Use the system Python so
it can import the distribution's D-Bus and GLib modules. To run a single case,
add `--test test_delayed_assignment_in_new_hierarchy`.

[GitHub Actions](.github/workflows/ci.yml) runs formatting, unit tests, the
isolated-bus ownership test, a release build, and the integration suite. CI builds
the companion at `9eb57f977996a800c1ff5a60f1dde556b3d9ddeb` without local patches.
The fixture simulates systemd notifications and controller file creation;
the binaries' D-Bus calls, xattrs, inotify watches, and process signals are real.

### Live GNOME check

For a live GNOME check, record the original `dmem.low` values for two application
cgroups, switch focus between them, and confirm the focused application's boost
and the previous application's restoration. Stop the service and confirm
restoration again. To check crash recovery, restart after interrupting the
process while boosted and confirm that a later focus loss restores the original
baseline. This requires a compatible Mutter session and dmem-capable hardware;
the automated tests do not establish those capabilities.
