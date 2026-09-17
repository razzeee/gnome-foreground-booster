use crate::cgroup::{application_cgroups, is_application_cgroup};
use crate::foreground::ForegroundPolicy;
use std::collections::HashMap;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use dbus::blocking::Connection;
use dbus::blocking::stdintf::org_freedesktop_dbus::RequestNameReply;
use dbus::channel::{BusType, Channel};

mod cgroup;
mod diagnostics;
mod filesystem;
mod foreground;
mod recovery;

const BUS_NAME: &str = "org.gnome.ForegroundBooster";

fn claim_name(connection: &Connection) -> Result<(), Box<dyn std::error::Error>> {
    if connection.request_name(BUS_NAME, false, false, true)? != RequestNameReply::PrimaryOwner {
        return Err("gnome-foreground-booster is already running on this user bus".into());
    }
    Ok(())
}

enum UnitEvent {
    New {
        name: String,
        object_path: String,
        attempts: u8,
    },
    Removed(String),
}

fn cgroup_interface(unit_name: &str) -> Option<&'static str> {
    Some(match unit_name.rsplit_once('.')?.1 {
        "service" => "org.freedesktop.systemd1.Service",
        "scope" => "org.freedesktop.systemd1.Scope",
        "slice" => "org.freedesktop.systemd1.Slice",
        "socket" => "org.freedesktop.systemd1.Socket",
        _ => return None,
    })
}

fn cgroup_for_unit(connection: &Connection, unit_name: &str, unit_path: &str) -> Option<PathBuf> {
    let interface = cgroup_interface(unit_name)?;
    let proxy = connection.with_proxy(
        "org.freedesktop.systemd1",
        unit_path,
        Duration::from_secs(1),
    );
    let result: Result<(dbus::arg::Variant<String>,), dbus::Error> = proxy.method_call(
        "org.freedesktop.DBus.Properties",
        "Get",
        (interface, "ControlGroup"),
    );
    let Ok((cgroup,)) = result else {
        return None;
    };
    /* UnitNew can arrive before systemd assigns the unit's cgroup. */
    if cgroup.0.is_empty() {
        return None;
    }
    Some(PathBuf::from("/sys/fs/cgroup").join(cgroup.0.trim_start_matches('/')))
}

fn existing_unit_cgroups(connection: &Connection) -> HashMap<String, PathBuf> {
    type UnitInfo = (
        String,
        String,
        String,
        String,
        String,
        String,
        dbus::Path<'static>,
        u32,
        String,
        dbus::Path<'static>,
    );
    let proxy = connection.with_proxy(
        "org.freedesktop.systemd1",
        "/org/freedesktop/systemd1",
        Duration::from_secs(2),
    );
    let result: Result<(Vec<UnitInfo>,), dbus::Error> =
        proxy.method_call("org.freedesktop.systemd1.Manager", "ListUnits", ());
    let Ok((units,)) = result else {
        return HashMap::new();
    };
    units
        .into_iter()
        .filter_map(|unit| {
            cgroup_for_unit(connection, &unit.0, &unit.6).map(|cgroup| (unit.6.to_string(), cgroup))
        })
        .collect()
}

fn application_root(connection: &Connection) -> Option<PathBuf> {
    cgroup_for_unit(
        connection,
        "app.slice",
        "/org/freedesktop/systemd1/unit/app_2eslice",
    )
}

fn register_application_cgroups(root: &Path, policy: &mut ForegroundPolicy) {
    for path in application_cgroups(root) {
        policy.register(path);
    }
}

fn process_unit_events(
    connection: &Connection,
    queue: &Arc<Mutex<Vec<UnitEvent>>>,
    unit_cgroups: &mut HashMap<String, PathBuf>,
    root: Option<&Path>,
    policy: &mut ForegroundPolicy,
) {
    let events = {
        let mut queue = queue.lock().expect("Failed to retrieve unit queue!");
        std::mem::take(&mut *queue)
    };
    let mut retries = Vec::new();
    let mut pending_new = std::collections::HashSet::new();
    for event in events {
        match event {
            UnitEvent::New {
                name,
                object_path,
                attempts,
            } => {
                if unit_cgroups.contains_key(&object_path)
                    || !pending_new.insert(object_path.clone())
                    || cgroup_interface(&name).is_none()
                {
                    continue;
                }
                if let Some(cgroup) = cgroup_for_unit(connection, &name, &object_path) {
                    if root.is_some_and(|root| is_application_cgroup(root, &cgroup)) {
                        policy.register(cgroup.clone());
                        unit_cgroups.insert(object_path, cgroup);
                    }
                } else if attempts < 10 {
                    retries.push(UnitEvent::New {
                        name,
                        object_path,
                        attempts: attempts + 1,
                    });
                }
            }
            UnitEvent::Removed(unit) => {
                pending_new.remove(&unit);
                retries.retain(|event| {
                    !matches!(event, UnitEvent::New { object_path, .. } if object_path == &unit)
                });
                if let Some(cgroup) = unit_cgroups.remove(&unit) {
                    policy.untrack(&cgroup);
                }
            }
        }
    }
    queue
        .lock()
        .expect("Failed to retrieve unit queue!")
        .extend(retries);
}

fn wait_for_session_events(connection: &Connection, policy: &ForegroundPolicy) {
    let dbus_watch = connection.channel().watch();
    let dbus_events = (if dbus_watch.read { libc::POLLIN } else { 0 })
        | (if dbus_watch.write { libc::POLLOUT } else { 0 });
    let mut descriptors = [
        libc::pollfd {
            fd: dbus_watch.fd,
            events: dbus_events,
            revents: 0,
        },
        libc::pollfd {
            fd: policy.event_fd().unwrap_or(-1),
            events: libc::POLLIN,
            revents: 0,
        },
    ];
    let result = unsafe { libc::poll(descriptors.as_mut_ptr(), descriptors.len() as _, 1000) };
    if result < 0 && io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
        eprintln!(
            "WARNING: Could not wait for session events: {}",
            io::Error::last_os_error()
        );
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::args_os().len() != 1 {
        return Err("usage: gnome-foreground-booster (no arguments)".into());
    }
    let mut channel = Channel::get_private(BusType::Session)?;
    channel.set_watch_enabled(true);
    let connection = Connection::from(channel);

    let new_unit_signal =
        dbus::message::MatchRule::new_signal("org.freedesktop.systemd1.Manager", "UnitNew");
    let unit_removed_signal =
        dbus::message::MatchRule::new_signal("org.freedesktop.systemd1.Manager", "UnitRemoved");

    let unit_queue: Arc<Mutex<Vec<UnitEvent>>> = Arc::new(Mutex::new(Vec::new()));

    let new_unit_queue = unit_queue.clone();
    connection.add_match(new_unit_signal, move |_: (), _, msg| {
        let Ok((name, unit)) = msg.read_all::<(String, dbus::Path)>() else {
            return true;
        };
        let mut queue = new_unit_queue
            .lock()
            .expect("Failed to retrieve unit queue!");
        queue.push(UnitEvent::New {
            name,
            object_path: unit.to_string(),
            attempts: 0,
        });
        true
    })?;

    let removed_unit_queue = unit_queue.clone();
    connection.add_match(unit_removed_signal, move |_: (), _, msg| {
        let Ok((_, unit)) = msg.read_all::<(String, dbus::Path)>() else {
            return true;
        };
        let mut queue = removed_unit_queue
            .lock()
            .expect("Failed to retrieve unit queue!");
        queue.push(UnitEvent::Removed(unit.to_string()));
        true
    })?;

    let manager = connection.with_proxy(
        "org.freedesktop.systemd1",
        "/org/freedesktop/systemd1",
        Duration::from_secs(2),
    );
    manager.method_call::<(), _, _, _>("org.freedesktop.systemd1.Manager", "Subscribe", ())?;

    let terminated = Arc::new(AtomicBool::new(false));
    signal_hook::flag::register(signal_hook::consts::SIGTERM, terminated.clone())?;
    signal_hook::flag::register(signal_hook::consts::SIGINT, terminated.clone())?;
    let mut policy = ForegroundPolicy::new(PathBuf::from("/sys/fs/cgroup"))?;
    let mut root = application_root(&connection);
    policy.check_prerequisites(root.as_deref());

    // Type=dbus considers the service started when this name is acquired.
    // Initialize inotify and subscribe first, but never change limits before ownership.
    claim_name(&connection)?;

    // Keep ownership until cleanup finishes, including when D-Bus processing fails.
    let result = (|| -> Result<(), dbus::Error> {
        if let Some(root) = &root {
            register_application_cgroups(root, &mut policy);
        }
        let mut unit_cgroups = existing_unit_cgroups(&connection);
        unit_cgroups.retain(|_, path| {
            root.as_deref()
                .is_some_and(|root| is_application_cgroup(root, path))
        });
        policy.reconcile();
        let mut last_maintenance = Instant::now();
        while !terminated.load(Ordering::Relaxed) {
            while connection.process(Duration::ZERO)? {}
            if terminated.load(Ordering::Relaxed) {
                break;
            }
            process_unit_events(
                &connection,
                &unit_queue,
                &mut unit_cgroups,
                root.as_deref(),
                &mut policy,
            );
            policy.process_events();
            if last_maintenance.elapsed() >= Duration::from_secs(1) {
                // Re-resolve the root and discover recreated cgroups without UnitNew.
                root = application_root(&connection);
                policy.check_prerequisites(root.as_deref());
                if let Some(root) = &root {
                    policy.restrict_to(root);
                    unit_cgroups.retain(|_, path| is_application_cgroup(root, path));
                    register_application_cgroups(root, &mut policy);
                }
                policy.maintenance();
                last_maintenance = Instant::now();
            }
            wait_for_session_events(&connection, &policy);
        }
        Ok(())
    })();
    policy.shutdown();
    result?;
    Ok(())
}

fn main() -> std::process::ExitCode {
    match run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("gnome-foreground-booster: {error}");
            std::process::ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "run under dbus-run-session; needs an isolated session bus"]
    fn ownership_rejects_duplicates_and_is_released_on_disconnect() {
        let first = Connection::new_session().unwrap();
        claim_name(&first).unwrap();
        let second = Connection::new_session().unwrap();
        assert!(claim_name(&second).is_err());
        drop(first);
        // Wait for the daemon to process the closed connection.
        for _ in 0..100 {
            if claim_name(&second).is_ok() {
                return;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        panic!("ownership was not released");
    }

    #[test]
    fn maps_cgroup_unit_types_to_their_dbus_interfaces() {
        assert_eq!(
            cgroup_interface("example.service"),
            Some("org.freedesktop.systemd1.Service")
        );
        assert_eq!(
            cgroup_interface("example.scope"),
            Some("org.freedesktop.systemd1.Scope")
        );
        assert_eq!(cgroup_interface("example.timer"), None);
    }
}
