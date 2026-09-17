# Development

## Checks

```sh
cargo fmt --check
cargo test --locked
dbus-run-session -- cargo test --locked tests::ownership_rejects_duplicates_and_is_released_on_disconnect -- --ignored --exact
cargo build --release --locked
```

The ownership test needs an isolated session bus and is skipped by the normal
test run. Tests do not modify live cgroup limits.

## Integration tests

Build both this project and [dmemcg-booster](https://github.com/razzeee/dmemcg-booster).
On Debian-based systems, install `bubblewrap`, `dbus`, `python3-dbus`, and
`python3-gi`. Unprivileged user namespaces must be enabled.

Run from this project's directory using the system Python:

```sh
/usr/bin/python3 tests/companion.py --companion /path/to/dmemcg-booster/target/release/dmemcg-booster
```

The suite runs the services against private D-Bus services and a simulated cgroup
filesystem. Add `--test test_delayed_assignment_in_new_hierarchy` to run one case.

## Live check

In a compatible GNOME session with dmem-capable hardware, record `dmem.low` for
two application cgroups. Switch focus and check that the focused application is
boosted and the previous application's limits are restored. Stop the service
and check restoration again. To test crash recovery, kill and restart the
service while boosted, then check that focus loss restores the original limits.
