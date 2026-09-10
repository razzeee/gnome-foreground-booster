use crate::cgroup::{
    DmemValue, is_application_cgroup, parse_dmem_values, valid_region, write_dmem,
};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs::OpenOptions;
use std::io;
use std::os::fd::{AsRawFd, RawFd};
use std::path::{Path, PathBuf};

use inotify::{EventMask, Inotify, WatchDescriptor, WatchMask};

const FOCUS_XATTR: &str = "user.xdg.inactive-since";
// Keep the historical name so upgrades recover records from the integrated daemon.
const STATE_XATTR: &str = "user.dmemcg-booster.dmem-low-state";

#[derive(Clone, Debug, Eq, PartialEq)]
struct StateEntry {
    baseline: DmemValue,
    applied: DmemValue,
}

type RecoveryState = BTreeMap<String, StateEntry>;

fn parse_state(input: &[u8]) -> Result<RecoveryState, &'static str> {
    let input = std::str::from_utf8(input).map_err(|_| "state is not UTF-8")?;
    let mut lines = input.lines();
    if lines.next() != Some("v1") {
        return Err("unsupported state version");
    }

    let mut state = RecoveryState::new();
    for line in lines {
        if line.is_empty() || line.contains('\t') || line.starts_with(' ') || line.ends_with(' ') {
            return Err("invalid whitespace in state");
        }
        let words: Vec<_> = line.split(' ').collect();
        if words.len() != 3 || !valid_region(words[0]) {
            return Err("invalid state line");
        }
        let entry = StateEntry {
            baseline: DmemValue::parse(words[1])?,
            applied: DmemValue::parse(words[2])?,
        };
        if state.insert(words[0].to_owned(), entry).is_some() {
            return Err("duplicate state region");
        }
    }
    if state.is_empty() {
        return Err("state has no regions");
    }
    Ok(state)
}

fn serialize_state(state: &RecoveryState) -> Vec<u8> {
    let mut output = String::from("v1\n");
    for (region, entry) in state {
        output.push_str(&format!("{region} {} {}\n", entry.baseline, entry.applied));
    }
    output.into_bytes()
}

fn focus_is_active(value: &[u8]) -> Result<bool, &'static str> {
    let value = std::str::from_utf8(value).map_err(|_| "focus xattr is not UTF-8")?;
    if value == "-1" {
        return Ok(true);
    }
    value
        .parse::<u64>()
        .map(|_| false)
        .map_err(|_| "invalid focus xattr")
}

trait PolicyIo {
    fn read(&self, path: &Path) -> io::Result<String>;
    fn write_dmem(&self, path: &Path, region: &str, value: DmemValue) -> io::Result<()>;
    fn get_xattr(&self, path: &Path, name: &str) -> io::Result<Option<Vec<u8>>>;
    fn set_xattr(&self, path: &Path, name: &str, value: &[u8]) -> io::Result<()>;
    fn remove_xattr(&self, path: &Path, name: &str) -> io::Result<()>;
    fn xattrs_supported(&self, path: &Path) -> io::Result<()>;
    fn writable(&self, path: &Path) -> io::Result<()>;
}

struct RealIo;

impl PolicyIo for RealIo {
    fn read(&self, path: &Path) -> io::Result<String> {
        std::fs::read_to_string(path)
    }

    fn write_dmem(&self, path: &Path, region: &str, value: DmemValue) -> io::Result<()> {
        write_dmem(path, region, value)
    }

    fn get_xattr(&self, path: &Path, name: &str) -> io::Result<Option<Vec<u8>>> {
        xattr::get(path, name)
    }

    fn set_xattr(&self, path: &Path, name: &str, value: &[u8]) -> io::Result<()> {
        xattr::set(path, name, value)
    }

    fn remove_xattr(&self, path: &Path, name: &str) -> io::Result<()> {
        xattr::remove(path, name)
    }

    fn xattrs_supported(&self, path: &Path) -> io::Result<()> {
        xattr::list(path).map(drop)
    }

    fn writable(&self, path: &Path) -> io::Result<()> {
        OpenOptions::new().write(true).open(path).map(drop)
    }
}

pub struct ForegroundPolicy {
    root: PathBuf,
    io: Box<dyn PolicyIo>,
    inotify: Option<Inotify>,
    watches: HashMap<WatchDescriptor, PathBuf>,
    paths: HashMap<PathBuf, WatchDescriptor>,
    pending_registration: HashSet<PathBuf>,
    pending_focus_checks: Vec<PathBuf>,
    ambiguous_active: HashSet<PathBuf>,
    focus_values: HashMap<PathBuf, Option<Vec<u8>>>,
    pending_apply: HashSet<PathBuf>,
    pending_restore: HashSet<PathBuf>,
    foreground: Option<PathBuf>,
}

impl ForegroundPolicy {
    pub fn new(root: PathBuf) -> io::Result<Self> {
        Ok(Self {
            root,
            io: Box::new(RealIo),
            inotify: Some(Inotify::init()?),
            watches: HashMap::new(),
            paths: HashMap::new(),
            pending_registration: HashSet::new(),
            pending_focus_checks: Vec::new(),
            ambiguous_active: HashSet::new(),
            focus_values: HashMap::new(),
            pending_apply: HashSet::new(),
            pending_restore: HashSet::new(),
            foreground: None,
        })
    }

    #[cfg(test)]
    fn with_io(root: PathBuf, io: Box<dyn PolicyIo>) -> Self {
        Self {
            root,
            io,
            inotify: None,
            watches: HashMap::new(),
            paths: HashMap::new(),
            pending_registration: HashSet::new(),
            pending_focus_checks: Vec::new(),
            ambiguous_active: HashSet::new(),
            focus_values: HashMap::new(),
            pending_apply: HashSet::new(),
            pending_restore: HashSet::new(),
            foreground: None,
        }
    }

    pub fn event_fd(&self) -> Option<RawFd> {
        self.inotify.as_ref().map(AsRawFd::as_raw_fd)
    }

    pub fn register(&mut self, cgroup: PathBuf) -> bool {
        if self.paths.contains_key(&cgroup) {
            return true;
        }
        if !self.pending_registration.insert(cgroup.clone()) {
            return false;
        }
        if !self.eligible(&cgroup) {
            return false;
        }
        let Some(inotify) = &self.inotify else {
            return false;
        };
        let mask = WatchMask::ATTRIB | WatchMask::DELETE_SELF;
        if let Ok(watch) = inotify.watches().add(&cgroup, mask) {
            self.watches.insert(watch.clone(), cgroup.clone());
            self.paths.insert(cgroup.clone(), watch);
            self.pending_registration.remove(&cgroup);
            self.pending_focus_checks.push(cgroup);
            return true;
        }
        false
    }

    pub fn untrack(&mut self, cgroup_path: &Path) {
        self.pending_registration.remove(cgroup_path);
        self.restore(cgroup_path);
        if let Some(watch) = self.paths.remove(cgroup_path) {
            self.watches.remove(&watch);
            if let Some(inotify) = &self.inotify {
                let _ = inotify.watches().remove(watch);
            }
        }
        self.pending_focus_checks.retain(|path| path != cgroup_path);
        self.ambiguous_active.remove(cgroup_path);
        if self.ambiguous_active.len() < 2 {
            self.ambiguous_active.clear();
        }
        self.focus_values.remove(cgroup_path);
        self.pending_apply.remove(cgroup_path);
    }

    pub fn restrict_to(&mut self, root: &Path) {
        let obsolete: HashSet<_> = self
            .paths
            .keys()
            .chain(self.pending_registration.iter())
            .chain(self.focus_values.keys())
            .chain(self.pending_apply.iter())
            .chain(self.foreground.iter())
            .filter(|path| !is_application_cgroup(root, path))
            .cloned()
            .collect();
        for path in obsolete {
            // Failed restoration stays pending even after the application root moves.
            self.untrack(&path);
        }
    }

    pub fn process_events(&mut self) {
        let mut buffer = [0; 4096];
        let mut paths = Vec::new();
        let mut removed = Vec::new();
        let mut overflow = false;

        loop {
            let Some(inotify) = &mut self.inotify else {
                return;
            };
            let events = match inotify.read_events(&mut buffer) {
                Ok(events) => events,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(error) => {
                    eprintln!("WARNING: Could not read foreground inotify events: {error}");
                    break;
                }
            };
            let mut any = false;
            for event in events {
                any = true;
                if event.mask.contains(EventMask::Q_OVERFLOW) {
                    overflow = true;
                    continue;
                }
                if let Some(path) = self.watches.get(&event.wd).cloned() {
                    if event
                        .mask
                        .intersects(EventMask::DELETE_SELF | EventMask::IGNORED)
                    {
                        removed.push(path);
                    } else if event.mask.contains(EventMask::ATTRIB) {
                        paths.push(path);
                    }
                }
            }
            if !any {
                break;
            }
        }

        if overflow {
            self.rebuild_watches();
            self.reconcile();
            return;
        }
        for path in removed {
            self.untrack(&path);
        }
        let pending = std::mem::take(&mut self.pending_focus_checks);
        paths.extend(pending);
        if paths.iter().any(|path| self.paths.contains_key(path)) {
            let tracked = self.paths.keys().cloned().collect();
            self.reconcile_paths(tracked);
        }
    }

    pub fn reconcile(&mut self) {
        if let Some(path) = self.foreground.take() {
            if self.paths.contains_key(&path) {
                self.pending_apply.insert(path);
            } else {
                self.pending_restore.insert(path);
            }
        }
        self.ambiguous_active.clear();
        self.focus_values.clear();
        self.pending_focus_checks.clear();
        let paths: Vec<_> = self.paths.keys().cloned().collect();
        self.reconcile_paths(paths);
    }

    pub fn shutdown(&mut self) {
        let mut paths = self.pending_restore.clone();
        paths.extend(self.pending_apply.drain());
        if let Some(path) = self.foreground.clone() {
            paths.insert(path);
        }
        for path in paths {
            self.restore(&path);
        }
    }

    /// Retry pending work once per call; the caller schedules this once per second.
    pub fn maintenance(&mut self) {
        for path in std::mem::take(&mut self.pending_registration) {
            // Unwatched cgroups can disappear without a deletion notification.
            if matches!(self.io.xattrs_supported(&path), Err(error) if error.kind() == io::ErrorKind::NotFound)
            {
                continue;
            }
            self.register(path);
        }
        let restore = self.pending_restore.clone();
        let apply = self.pending_apply.clone();
        let mut paths: HashSet<_> = self.paths.keys().cloned().collect();
        paths.extend(self.focus_values.keys().cloned());
        let complete = self.reconcile_paths(paths.into_iter().collect());
        for path in restore {
            self.restore(&path);
        }
        if !complete {
            return;
        }
        if self.foreground.is_none() && self.ambiguous_active.is_empty() {
            self.pending_apply
                .extend(self.focus_values.iter().filter_map(|(path, value)| {
                    (value
                        .as_deref()
                        .and_then(|value| focus_is_active(value).ok())
                        == Some(true))
                    .then(|| path.clone())
                }));
        }
        for path in apply {
            if self.pending_apply.contains(&path) && !self.pending_restore.contains(&path) {
                self.activate(&path);
            }
        }
    }

    fn eligible(&self, path: &Path) -> bool {
        let low = path.join("dmem.low");
        self.io
            .read(&low)
            .and_then(|value| {
                parse_dmem_values(&value)
                    .map(drop)
                    .map_err(io::Error::other)
            })
            .is_ok()
            && self.io.xattrs_supported(path).is_ok()
            && self.io.writable(&low).is_ok()
    }

    #[cfg(test)]
    fn process_focus(&mut self, path: &Path) {
        let mut paths: Vec<_> = self.focus_values.keys().cloned().collect();
        if !self.focus_values.contains_key(path) {
            paths.push(path.to_path_buf());
        }
        self.reconcile_paths(paths);
    }

    fn activate(&mut self, path: &Path) {
        if self.foreground.as_deref() == Some(path) {
            return;
        }
        self.pending_apply.insert(path.to_path_buf());
        if self.pending_restore.contains(path) {
            return;
        }
        if let Some(previous) = self.foreground.clone() {
            self.restore(&previous);
        }
        if self.recover_active_state(path) {
            return;
        }

        let capacity = match self.io.read(&self.root.join("dmem.capacity")) {
            Ok(value) => match parse_dmem_values(&value) {
                Ok(value) => value,
                Err(error) => {
                    eprintln!("WARNING: Could not parse root dmem.capacity: {error}");
                    return;
                }
            },
            Err(_) => return,
        };
        let low_path = path.join("dmem.low");
        let baseline = match self
            .io
            .read(&low_path)
            .and_then(|value| parse_dmem_values(&value).map_err(io::Error::other))
        {
            Ok(value) => value,
            Err(error) => {
                eprintln!(
                    "WARNING: Could not read dmem.low for {}: {error}",
                    path.display()
                );
                return;
            }
        };

        let mut state = RecoveryState::new();
        for (region, capacity) in capacity {
            let Some(current) = baseline.get(&region).copied() else {
                continue;
            };
            let applied = current.max(capacity);
            if applied != current {
                state.insert(
                    region,
                    StateEntry {
                        baseline: current,
                        applied,
                    },
                );
            }
        }
        if state.is_empty() {
            self.pending_apply.remove(path);
            self.foreground = Some(path.to_path_buf());
            return;
        }
        if let Err(error) = self
            .io
            .set_xattr(path, STATE_XATTR, &serialize_state(&state))
        {
            eprintln!(
                "WARNING: Could not persist foreground state for {}: {error}",
                path.display()
            );
            return;
        }

        let mut written: Vec<String> = Vec::new();
        for (region, entry) in &state {
            if let Err(error) = self.io.write_dmem(&low_path, region, entry.applied) {
                eprintln!(
                    "WARNING: Could not boost dmem.low for {}: {error}",
                    path.display()
                );
                let mut rollback_failed = false;
                for written_region in &written {
                    let entry = &state[written_region];
                    rollback_failed |= self
                        .io
                        .write_dmem(&low_path, written_region, entry.baseline)
                        .is_err();
                }
                if !rollback_failed {
                    let _ = self.io.remove_xattr(path, STATE_XATTR);
                }
                return;
            }
            written.push(region.clone());
        }
        self.foreground = Some(path.to_path_buf());
        self.pending_apply.remove(path);
    }

    fn restore(&mut self, path: &Path) {
        self.pending_apply.remove(path);
        self.pending_restore.insert(path.to_path_buf());
        if self.foreground.as_deref() == Some(path) {
            self.foreground = None;
        }
        let state_value = match self.io.get_xattr(path, STATE_XATTR) {
            Ok(Some(value)) => value,
            Ok(None) => {
                self.pending_restore.remove(path);
                return;
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                self.pending_restore.remove(path);
                return;
            }
            Err(error) => {
                eprintln!(
                    "WARNING: Could not read foreground state for {}: {error}",
                    path.display()
                );
                return;
            }
        };
        let state = match parse_state(&state_value) {
            Ok(state) => state,
            Err(error) => {
                eprintln!(
                    "WARNING: Invalid foreground state for {}: {error}",
                    path.display()
                );
                return;
            }
        };
        let low_path = path.join("dmem.low");
        let current = match self
            .io
            .read(&low_path)
            .and_then(|value| parse_dmem_values(&value).map_err(io::Error::other))
        {
            Ok(value) => value,
            Err(error) => {
                eprintln!(
                    "WARNING: Could not read dmem.low while restoring {}: {error}",
                    path.display()
                );
                return;
            }
        };

        let candidates: RecoveryState = state
            .into_iter()
            .filter(|(region, entry)| current.get(region) == Some(&entry.applied))
            .collect();
        if candidates.is_empty() {
            if let Err(error) = self.io.remove_xattr(path, STATE_XATTR) {
                eprintln!(
                    "WARNING: Could not remove foreground state for {}: {error}",
                    path.display()
                );
            } else {
                self.pending_restore.remove(path);
            }
            return;
        }
        let candidate_state = serialize_state(&candidates);
        if state_value != candidate_state
            && let Err(error) = self.io.set_xattr(path, STATE_XATTR, &candidate_state)
        {
            eprintln!(
                "WARNING: Could not narrow foreground state for {}: {error}",
                path.display()
            );
            return;
        }

        let mut retry = RecoveryState::new();
        for (region, entry) in &candidates {
            if self
                .io
                .write_dmem(&low_path, region, entry.baseline)
                .is_err()
            {
                retry.insert(region.clone(), entry.clone());
            }
        }
        let result = if retry.is_empty() {
            self.io.remove_xattr(path, STATE_XATTR)
        } else if retry == candidates {
            Ok(())
        } else {
            self.io
                .set_xattr(path, STATE_XATTR, &serialize_state(&retry))
        };
        if let Err(error) = result {
            eprintln!(
                "WARNING: Could not update foreground state for {}: {error}",
                path.display()
            );
        } else if retry.is_empty() {
            self.pending_restore.remove(path);
        }
    }

    fn reconcile_paths(&mut self, paths: Vec<PathBuf>) -> bool {
        // Do not commit a partial snapshot: a later successful read must still see changes.
        let snapshot: io::Result<Vec<_>> = paths
            .into_iter()
            .map(|path| {
                self.io
                    .get_xattr(&path, FOCUS_XATTR)
                    .map(|value| (path, value))
            })
            .collect();
        let Ok(snapshot) = snapshot else {
            return false;
        };
        let mut changed = false;
        for (path, value) in snapshot {
            if self.focus_values.get(&path) != Some(&value) {
                changed = true;
                self.focus_values.insert(path, value);
            }
        }
        if !changed {
            return true;
        }
        let active: Vec<_> = self
            .focus_values
            .iter()
            .filter_map(|(path, value)| {
                (value
                    .as_deref()
                    .and_then(|value| focus_is_active(value).ok())
                    == Some(true))
                .then(|| path.clone())
            })
            .collect();
        self.ambiguous_active = if active.len() > 1 {
            active.iter().cloned().collect()
        } else {
            HashSet::new()
        };
        let selected = (active.len() == 1).then(|| &active[0]);
        for path in self.focus_values.keys().cloned().collect::<Vec<_>>() {
            if Some(&path) != selected {
                self.pending_apply.remove(&path);
                if !self.pending_restore.contains(&path) {
                    self.restore(&path);
                }
            }
        }
        if let Some(path) = selected {
            if !self.pending_apply.contains(path) && !self.pending_restore.contains(path) {
                self.activate(path);
            }
        }
        true
    }

    fn recover_active_state(&mut self, path: &Path) -> bool {
        let value = match self.io.get_xattr(path, STATE_XATTR) {
            Ok(Some(value)) => value,
            Ok(None) => return false,
            Err(_) => return true,
        };
        let mut state = match parse_state(&value) {
            Ok(state) => state,
            Err(error) => {
                eprintln!(
                    "WARNING: Invalid foreground state for {}: {error}",
                    path.display()
                );
                return true;
            }
        };
        let low_path = path.join("dmem.low");
        let Ok(current) = self
            .io
            .read(&low_path)
            .and_then(|value| parse_dmem_values(&value).map_err(io::Error::other))
        else {
            return true;
        };
        // A persisted record precedes the writes. Only baseline values still need applying.
        state.retain(|region, entry| {
            current.get(region) == Some(&entry.baseline)
                || current.get(region) == Some(&entry.applied)
        });
        let result = if state.is_empty() {
            self.io.remove_xattr(path, STATE_XATTR)
        } else if serialize_state(&state) != value {
            self.io
                .set_xattr(path, STATE_XATTR, &serialize_state(&state))
        } else {
            Ok(())
        };
        if result.is_err() {
            return true;
        }
        for (region, entry) in &state {
            if current.get(region) == Some(&entry.baseline)
                && self
                    .io
                    .write_dmem(&low_path, region, entry.applied)
                    .is_err()
            {
                return true;
            }
        }
        self.foreground = Some(path.to_path_buf());
        self.pending_apply.remove(path);
        true
    }

    fn rebuild_watches(&mut self) {
        let paths: HashSet<_> = self.paths.keys().cloned().collect();
        let Ok(inotify) = Inotify::init() else {
            self.inotify = None;
            self.watches.clear();
            self.paths.clear();
            return;
        };
        self.inotify = Some(inotify);
        self.watches.clear();
        self.paths.clear();
        self.pending_focus_checks.clear();
        for path in paths {
            self.register(path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cgroup::DmemValues;
    use std::cell::RefCell;
    use std::collections::VecDeque;
    use std::rc::Rc;

    #[derive(Default)]
    struct FakeState {
        files: HashMap<PathBuf, DmemValues>,
        xattrs: HashMap<(PathBuf, String), Vec<u8>>,
        writes: Vec<(PathBuf, String, DmemValue)>,
        failures: VecDeque<(String, io::ErrorKind)>,
        failed_write_calls: VecDeque<usize>,
        write_calls: usize,
        set_xattr_calls: usize,
        unreadable_focus: HashSet<PathBuf>,
        unwritable: HashSet<PathBuf>,
        unsupported_xattrs: HashSet<PathBuf>,
    }

    #[derive(Clone, Default)]
    struct FakeIo(Rc<RefCell<FakeState>>);

    impl FakeIo {
        fn file(&self, path: impl Into<PathBuf>, values: &[(&str, DmemValue)]) {
            self.0.borrow_mut().files.insert(
                path.into(),
                values
                    .iter()
                    .map(|(key, value)| ((*key).to_owned(), *value))
                    .collect(),
            );
        }

        fn xattr(&self, path: &Path, name: &str, value: &[u8]) {
            self.0
                .borrow_mut()
                .xattrs
                .insert((path.to_path_buf(), name.to_owned()), value.to_vec());
        }

        fn value(&self, path: &Path, region: &str) -> DmemValue {
            self.0.borrow().files[path][region]
        }

        fn has_xattr(&self, path: &Path, name: &str) -> bool {
            self.0
                .borrow()
                .xattrs
                .contains_key(&(path.to_path_buf(), name.to_owned()))
        }

        fn fail(&self, operation: &str, kind: io::ErrorKind) {
            self.0
                .borrow_mut()
                .failures
                .push_back((operation.to_owned(), kind));
        }

        fn fail_writes(&self, calls: &[usize]) {
            self.0.borrow_mut().failed_write_calls = calls.iter().copied().collect();
        }

        fn check_failure(&self, operation: &str) -> io::Result<()> {
            let mut state = self.0.borrow_mut();
            if state.failures.front().map(|item| item.0.as_str()) == Some(operation) {
                let (_, kind) = state.failures.pop_front().unwrap();
                return Err(io::Error::from(kind));
            }
            Ok(())
        }
    }

    impl PolicyIo for FakeIo {
        fn read(&self, path: &Path) -> io::Result<String> {
            self.check_failure("read")?;
            let state = self.0.borrow();
            let values = state
                .files
                .get(path)
                .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))?;
            Ok(values
                .iter()
                .map(|(region, value)| format!("{region} {value}"))
                .collect::<Vec<_>>()
                .join("\n"))
        }

        fn write_dmem(&self, path: &Path, region: &str, value: DmemValue) -> io::Result<()> {
            self.check_failure("write")?;
            let mut state = self.0.borrow_mut();
            state.write_calls += 1;
            if state.failed_write_calls.front() == Some(&state.write_calls) {
                state.failed_write_calls.pop_front();
                return Err(io::Error::other("injected write failure"));
            }
            state
                .files
                .get_mut(path)
                .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))?
                .insert(region.to_owned(), value);
            state
                .writes
                .push((path.to_path_buf(), region.to_owned(), value));
            Ok(())
        }

        fn get_xattr(&self, path: &Path, name: &str) -> io::Result<Option<Vec<u8>>> {
            if name == FOCUS_XATTR && self.0.borrow().unreadable_focus.contains(path) {
                return Err(io::ErrorKind::PermissionDenied.into());
            }
            self.check_failure("get_xattr")?;
            Ok(self
                .0
                .borrow()
                .xattrs
                .get(&(path.to_path_buf(), name.to_owned()))
                .cloned())
        }

        fn set_xattr(&self, path: &Path, name: &str, value: &[u8]) -> io::Result<()> {
            self.0.borrow_mut().set_xattr_calls += 1;
            self.check_failure("set_xattr")?;
            self.xattr(path, name, value);
            Ok(())
        }

        fn remove_xattr(&self, path: &Path, name: &str) -> io::Result<()> {
            self.check_failure("remove_xattr")?;
            self.0
                .borrow_mut()
                .xattrs
                .remove(&(path.to_path_buf(), name.to_owned()));
            Ok(())
        }

        fn xattrs_supported(&self, path: &Path) -> io::Result<()> {
            if self.0.borrow().unsupported_xattrs.contains(path) {
                Err(io::Error::from(io::ErrorKind::Unsupported))
            } else {
                Ok(())
            }
        }

        fn writable(&self, path: &Path) -> io::Result<()> {
            if self.0.borrow().unwritable.contains(path) {
                Err(io::Error::from(io::ErrorKind::PermissionDenied))
            } else if self.0.borrow().files.contains_key(path) {
                Ok(())
            } else {
                Err(io::Error::from(io::ErrorKind::NotFound))
            }
        }
    }

    fn setup() -> (ForegroundPolicy, FakeIo, PathBuf, PathBuf) {
        let root = PathBuf::from("/test");
        let app = root.join("app.slice/app.scope");
        let io = FakeIo::default();
        io.file(
            root.join("dmem.capacity"),
            &[("0", DmemValue::Finite(100)), ("1", DmemValue::Finite(50))],
        );
        io.file(
            app.join("dmem.low"),
            &[("0", DmemValue::Finite(10)), ("1", DmemValue::Max)],
        );
        io.xattr(&app, FOCUS_XATTR, b"-1");
        (
            ForegroundPolicy::with_io(root.clone(), Box::new(io.clone())),
            io,
            root,
            app,
        )
    }

    #[test]
    fn parses_versioned_state() {
        let state = parse_state(b"v1\n0 4 42\n1 max max\n").unwrap();
        assert_eq!(state["0"].baseline, DmemValue::Finite(4));
        assert!(parse_state(b"v1\n0  4 42\n").is_err());
        assert!(parse_state(b"v2\n0 4 42\n").is_err());
        assert!(parse_state(b"v1\n").is_err());
    }

    #[test]
    fn boost_is_non_decreasing_and_repeated_focus_is_idempotent() {
        let (mut policy, io, _, app) = setup();
        policy.activate(&app);
        policy.activate(&app);

        assert_eq!(io.value(&app.join("dmem.low"), "0"), DmemValue::Finite(100));
        assert_eq!(io.value(&app.join("dmem.low"), "1"), DmemValue::Max);
        assert_eq!(io.0.borrow().writes.len(), 1);
        assert!(io.has_xattr(&app, STATE_XATTR));
    }

    #[test]
    fn inactive_transition_restores_baseline() {
        let (mut policy, io, _, app) = setup();
        policy.activate(&app);
        io.xattr(&app, FOCUS_XATTR, b"20");
        policy.process_focus(&app);

        assert_eq!(io.value(&app.join("dmem.low"), "0"), DmemValue::Finite(10));
        assert!(!io.has_xattr(&app, STATE_XATTR));
        assert!(policy.foreground.is_none());
    }

    #[test]
    fn restoration_preserves_external_writes() {
        let (mut policy, io, _, app) = setup();
        policy.activate(&app);
        io.file(
            app.join("dmem.low"),
            &[("0", DmemValue::Finite(75)), ("1", DmemValue::Max)],
        );
        policy.restore(&app);

        assert_eq!(io.value(&app.join("dmem.low"), "0"), DmemValue::Finite(75));
        assert!(!io.has_xattr(&app, STATE_XATTR));
    }

    #[test]
    fn failed_apply_rolls_back_partial_writes() {
        let (mut policy, io, root, app) = setup();
        io.file(
            root.join("dmem.capacity"),
            &[("0", DmemValue::Finite(100)), ("1", DmemValue::Finite(100))],
        );
        io.file(
            app.join("dmem.low"),
            &[("0", DmemValue::Finite(10)), ("1", DmemValue::Finite(20))],
        );
        io.fail_writes(&[2]);
        policy.activate(&app);

        assert_eq!(io.value(&app.join("dmem.low"), "0"), DmemValue::Finite(10));
        assert_eq!(io.value(&app.join("dmem.low"), "1"), DmemValue::Finite(20));
        assert!(!io.has_xattr(&app, STATE_XATTR));
        assert!(policy.foreground.is_none());
    }

    #[test]
    fn failed_rollback_retains_recovery_state() {
        let (mut policy, io, root, app) = setup();
        io.file(
            root.join("dmem.capacity"),
            &[("0", DmemValue::Finite(100)), ("1", DmemValue::Finite(100))],
        );
        io.file(
            app.join("dmem.low"),
            &[("0", DmemValue::Finite(10)), ("1", DmemValue::Finite(20))],
        );
        io.fail_writes(&[2, 3]);
        policy.activate(&app);

        assert_eq!(io.value(&app.join("dmem.low"), "0"), DmemValue::Finite(100));
        assert!(io.has_xattr(&app, STATE_XATTR));
        assert!(policy.foreground.is_none());
    }

    #[test]
    fn reactivation_preserves_pending_recovery_baseline() {
        let (mut policy, io, root, app) = setup();
        io.file(
            root.join("dmem.capacity"),
            &[("0", DmemValue::Finite(100)), ("1", DmemValue::Finite(100))],
        );
        io.file(
            app.join("dmem.low"),
            &[("0", DmemValue::Finite(10)), ("1", DmemValue::Finite(20))],
        );
        io.fail_writes(&[2, 3]);
        policy.activate(&app);
        policy.activate(&app);

        let state =
            parse_state(&io.0.borrow().xattrs[&(app.clone(), STATE_XATTR.to_owned())]).unwrap();
        assert_eq!(state["0"].baseline, DmemValue::Finite(10));
        assert_eq!(policy.foreground.as_deref(), Some(app.as_path()));
    }

    #[test]
    fn cleanup_failure_keeps_stale_state_without_reapplying_protection() {
        let (mut policy, io, _, app) = setup();
        policy.activate(&app);
        io.fail("remove_xattr", io::ErrorKind::PermissionDenied);
        policy.restore(&app);

        assert!(io.has_xattr(&app, STATE_XATTR));
        assert_eq!(io.value(&app.join("dmem.low"), "0"), DmemValue::Finite(10));
    }

    #[test]
    fn cgroup_is_watch_eligible_before_focus_xattr_exists() {
        let (policy, io, _, app) = setup();
        io.0.borrow_mut()
            .xattrs
            .remove(&(app.clone(), FOCUS_XATTR.to_owned()));
        assert!(policy.eligible(&app));

        io.0.borrow_mut().unwritable.insert(app.join("dmem.low"));
        assert!(!policy.eligible(&app));

        io.0.borrow_mut().unwritable.clear();
        io.0.borrow_mut().unsupported_xattrs.insert(app.clone());
        assert!(!policy.eligible(&app));
    }

    #[test]
    fn reconciliation_recovers_active_and_inactive_state() {
        let (mut policy, io, _, app) = setup();
        policy.activate(&app);
        policy.foreground = None;
        policy.reconcile_paths(vec![app.clone()]);
        assert_eq!(policy.foreground.as_deref(), Some(app.as_path()));

        policy.foreground = None;
        io.xattr(&app, FOCUS_XATTR, b"100");
        policy.reconcile_paths(vec![app.clone()]);
        assert_eq!(io.value(&app.join("dmem.low"), "0"), DmemValue::Finite(10));
        assert!(!io.has_xattr(&app, STATE_XATTR));
    }

    #[test]
    fn active_recovery_preserves_external_writes() {
        let (mut policy, io, _, app) = setup();
        policy.activate(&app);
        io.file(
            app.join("dmem.low"),
            &[("0", DmemValue::Finite(75)), ("1", DmemValue::Max)],
        );
        policy.foreground = None;

        policy.reconcile_paths(vec![app.clone()]);

        assert_eq!(policy.foreground.as_deref(), Some(app.as_path()));
        assert_eq!(io.value(&app.join("dmem.low"), "0"), DmemValue::Finite(75));
    }

    #[test]
    fn malformed_state_is_retained() {
        let (mut policy, io, _, app) = setup();
        io.xattr(&app, STATE_XATTR, b"v1\n0 nope 100\n");
        policy.restore(&app);
        assert!(io.has_xattr(&app, STATE_XATTR));
        assert_eq!(io.value(&app.join("dmem.low"), "0"), DmemValue::Finite(10));
    }

    #[test]
    fn ambiguous_active_cgroups_are_not_boosted() {
        let (mut policy, io, _, app) = setup();
        let other = PathBuf::from("/test/app.slice/other.scope");
        io.file(other.join("dmem.low"), &[("0", DmemValue::Finite(5))]);
        io.xattr(&other, FOCUS_XATTR, b"-1");
        policy.reconcile_paths(vec![app.clone(), other.clone()]);

        assert!(policy.foreground.is_none());
        assert_eq!(io.value(&app.join("dmem.low"), "0"), DmemValue::Finite(10));
        assert_eq!(io.value(&other.join("dmem.low"), "0"), DmemValue::Finite(5));
    }

    #[test]
    fn ambiguous_recovery_waits_for_a_new_focus_transition() {
        let (mut policy, io, _, app) = setup();
        let other = PathBuf::from("/test/app.slice/other.scope");
        policy.activate(&app);
        io.file(other.join("dmem.low"), &[("0", DmemValue::Finite(100))]);
        io.xattr(&other, FOCUS_XATTR, b"-1");
        io.xattr(&other, STATE_XATTR, b"v1\n0 5 100\n");

        policy.reconcile_paths(vec![app.clone(), other.clone()]);
        policy.process_focus(&other);
        assert!(policy.foreground.is_none());
        assert_eq!(io.value(&other.join("dmem.low"), "0"), DmemValue::Finite(5));

        let unrelated = PathBuf::from("/test/app.slice/unrelated.scope");
        io.xattr(&unrelated, FOCUS_XATTR, b"1");
        policy.process_focus(&unrelated);
        policy.process_focus(&other);
        assert!(policy.foreground.is_none());

        io.xattr(&app, FOCUS_XATTR, b"1");
        policy.process_focus(&app);
        policy.process_focus(&other);
        assert_eq!(policy.foreground.as_deref(), Some(other.as_path()));
        assert_eq!(
            io.value(&other.join("dmem.low"), "0"),
            DmemValue::Finite(100)
        );
    }

    #[test]
    fn missing_capabilities_do_not_write() {
        let (mut policy, io, root, app) = setup();
        io.0.borrow_mut().files.remove(&root.join("dmem.capacity"));
        policy.activate(&app);
        assert!(io.0.borrow().writes.is_empty());
        assert!(!io.has_xattr(&app, STATE_XATTR));
    }

    #[test]
    fn failed_state_persistence_prevents_writes() {
        let (mut policy, io, _, app) = setup();
        io.fail("set_xattr", io::ErrorKind::PermissionDenied);
        policy.activate(&app);
        assert!(io.0.borrow().writes.is_empty());
        assert_eq!(io.value(&app.join("dmem.low"), "0"), DmemValue::Finite(10));
    }

    #[test]
    fn untrack_restores_a_tracked_cgroup() {
        let (mut policy, io, _, app) = setup();
        policy.activate(&app);
        policy.untrack(&app);
        assert_eq!(io.value(&app.join("dmem.low"), "0"), DmemValue::Finite(10));
        assert!(policy.foreground.is_none());
    }

    #[test]
    fn changing_application_root_retires_old_paths_and_keeps_failed_cleanup() {
        let (mut policy, io, root, app) = setup();
        policy.process_focus(&app);
        policy
            .pending_registration
            .insert(root.join("app.slice/late.scope"));
        io.fail("write", io::ErrorKind::PermissionDenied);
        policy.restrict_to(&root.join("replacement.slice"));
        assert!(policy.foreground.is_none());
        assert!(policy.focus_values.is_empty());
        assert!(policy.pending_registration.is_empty());
        assert!(policy.pending_restore.contains(&app));
        policy.maintenance();
        assert_eq!(io.value(&app.join("dmem.low"), "0"), DmemValue::Finite(10));
        assert!(policy.pending_restore.is_empty());
    }

    #[test]
    fn unchanged_focus_does_not_retry_failed_apply() {
        let (mut policy, io, _, app) = setup();
        io.fail_writes(&[1, 2]);
        policy.process_focus(&app);
        for _ in 0..10 {
            policy.process_focus(&app);
        }
        assert_eq!(io.0.borrow().write_calls, 1);
        policy.maintenance();
        assert_eq!(io.0.borrow().write_calls, 2);
        policy.maintenance();
        assert_eq!(io.0.borrow().write_calls, 3);
        assert_eq!(policy.foreground.as_deref(), Some(app.as_path()));
    }

    #[test]
    fn incomplete_focus_snapshot_defers_selection_without_losing_changes() {
        let (mut policy, io, root, app) = setup();
        let other = root.join("other");
        io.xattr(&app, FOCUS_XATTR, b"1");
        io.xattr(&other, FOCUS_XATTR, b"1");
        assert!(policy.reconcile_paths(vec![app.clone(), other.clone()]));
        io.xattr(&app, FOCUS_XATTR, b"-1");
        io.0.borrow_mut().unreadable_focus.insert(other.clone());
        assert!(!policy.reconcile_paths(vec![app.clone(), other.clone()]));
        policy.maintenance();
        assert!(policy.foreground.is_none());
        assert!(io.0.borrow().writes.is_empty());
        io.0.borrow_mut().unreadable_focus.clear();
        assert!(policy.reconcile_paths(vec![app.clone(), other]));
        assert_eq!(policy.foreground.as_ref(), Some(&app));
    }

    #[test]
    fn incomplete_focus_snapshot_blocks_pending_apply_but_not_restore() {
        for unreadable_app in [true, false] {
            let (mut policy, io, root, app) = setup();
            let other = root.join("other");
            io.xattr(&other, FOCUS_XATTR, b"1");
            io.fail_writes(&[1]);
            policy.reconcile_paths(vec![app.clone(), other.clone()]);
            assert!(policy.pending_apply.contains(&app));
            io.file(other.join("dmem.low"), &[("0", DmemValue::Finite(100))]);
            io.xattr(&other, STATE_XATTR, b"v1\n0 5 100\n");
            policy.pending_restore.insert(other.clone());
            io.0.borrow_mut()
                .unreadable_focus
                .insert(if unreadable_app {
                    app.clone()
                } else {
                    other.clone()
                });
            policy.maintenance();
            assert!(policy.foreground.is_none());
            assert!(policy.pending_apply.contains(&app));
            assert_eq!(io.value(&app.join("dmem.low"), "0"), DmemValue::Finite(10));
            assert_eq!(io.value(&other.join("dmem.low"), "0"), DmemValue::Finite(5));
            assert!(policy.pending_restore.is_empty());
            io.xattr(&app, FOCUS_XATTR, b"2");
            io.0.borrow_mut().unreadable_focus.clear();
            policy.maintenance();
            assert!(policy.pending_apply.is_empty());
            assert_eq!(io.value(&app.join("dmem.low"), "0"), DmemValue::Finite(10));
        }
    }

    #[test]
    fn restore_errors_do_not_forget_another_foreground() {
        for operation in [
            "get_xattr",
            "read",
            "set_xattr",
            "remove_xattr",
            "malformed",
        ] {
            let (mut policy, io, root, app) = setup();
            policy.activate(&app);
            let other = root.join("other");
            io.file(other.join("dmem.low"), &[("0", DmemValue::Finite(100))]);
            io.xattr(&other, STATE_XATTR, b"v1\n0 5 100\n1 5 100\n");
            if operation == "malformed" {
                io.xattr(&other, STATE_XATTR, b"invalid");
            } else {
                io.fail(operation, io::ErrorKind::PermissionDenied);
            }
            policy.restore(&other);
            assert_eq!(
                policy.foreground.as_deref(),
                Some(app.as_path()),
                "{operation}"
            );
            assert!(policy.pending_restore.contains(&other), "{operation}");
            assert!(io.has_xattr(&other, STATE_XATTR));
        }
    }

    #[test]
    fn failed_restore_waits_for_maintenance_and_keeps_its_record() {
        let (mut policy, io, _, app) = setup();
        policy.process_focus(&app);
        io.fail_writes(&[2, 3]);
        io.xattr(&app, FOCUS_XATTR, b"1");
        policy.process_focus(&app);
        for _ in 0..10 {
            policy.process_focus(&app);
        }
        assert_eq!(io.0.borrow().write_calls, 2);
        assert!(io.has_xattr(&app, STATE_XATTR));
        policy.maintenance();
        assert_eq!(io.0.borrow().write_calls, 3);
        assert!(io.has_xattr(&app, STATE_XATTR));
        assert_eq!(io.0.borrow().set_xattr_calls, 1);
        policy.maintenance();
        assert_eq!(io.0.borrow().write_calls, 4);
        assert!(!io.has_xattr(&app, STATE_XATTR));
        assert!(policy.pending_restore.is_empty());
    }

    #[test]
    fn shutdown_restores_pending_apply_after_failed_rollback() {
        let (mut policy, io, _, app) = setup();
        io.file(
            app.join("dmem.low"),
            &[("0", DmemValue::Finite(10)), ("1", DmemValue::Finite(20))],
        );
        io.fail_writes(&[2, 3]);
        policy.process_focus(&app);
        assert!(policy.foreground.is_none());
        assert!(policy.pending_apply.contains(&app));
        policy.shutdown();
        assert_eq!(io.value(&app.join("dmem.low"), "0"), DmemValue::Finite(10));
        assert_eq!(io.value(&app.join("dmem.low"), "1"), DmemValue::Finite(20));
        assert!(!io.has_xattr(&app, STATE_XATTR));
    }

    #[test]
    fn pending_untracked_restores_are_retried_and_shutdown_attempts_all_paths() {
        let (mut policy, io, root, app) = setup();
        policy.activate(&app);
        io.fail("write", io::ErrorKind::PermissionDenied);
        policy.untrack(&app);
        assert!(policy.pending_restore.contains(&app));
        assert!(io.has_xattr(&app, STATE_XATTR));
        policy.maintenance();
        assert!(!policy.pending_restore.contains(&app));
        assert_eq!(io.value(&app.join("dmem.low"), "0"), DmemValue::Finite(10));

        policy.activate(&app);
        io.fail("write", io::ErrorKind::PermissionDenied);
        policy.untrack(&app);
        let other = root.join("other");
        io.file(other.join("dmem.low"), &[("0", DmemValue::Finite(5))]);
        policy.activate(&other);
        policy.shutdown();
        assert_eq!(io.value(&app.join("dmem.low"), "0"), DmemValue::Finite(10));
        assert_eq!(io.value(&other.join("dmem.low"), "0"), DmemValue::Finite(5));
        assert!(policy.pending_restore.is_empty());
    }

    #[test]
    fn recovery_finishes_interrupted_writes_and_preserves_external_values() {
        let (mut policy, io, _, app) = setup();
        io.file(
            app.join("dmem.low"),
            &[
                ("0", DmemValue::Finite(100)),
                ("1", DmemValue::Finite(20)),
                ("2", DmemValue::Finite(75)),
            ],
        );
        io.xattr(&app, STATE_XATTR, b"v1\n0 10 100\n1 20 100\n2 30 100\n");
        io.fail_writes(&[1]);
        policy.process_focus(&app);
        assert!(policy.foreground.is_none());
        policy.process_focus(&app);
        assert_eq!(io.0.borrow().write_calls, 1);
        policy.maintenance();
        assert_eq!(io.value(&app.join("dmem.low"), "1"), DmemValue::Finite(100));
        assert_eq!(io.value(&app.join("dmem.low"), "2"), DmemValue::Finite(75));
        policy.shutdown();
        assert_eq!(io.value(&app.join("dmem.low"), "0"), DmemValue::Finite(10));
        assert_eq!(io.value(&app.join("dmem.low"), "1"), DmemValue::Finite(20));
        assert_eq!(io.value(&app.join("dmem.low"), "2"), DmemValue::Finite(75));
    }

    struct TempDir(PathBuf);

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn temp_root() -> TempDir {
        let root = TempDir(std::env::temp_dir().join(format!(
            "dmemcg-foreground-{}-{}", std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        )));
        std::fs::create_dir(&root.0).unwrap();
        std::fs::write(root.0.join("dmem.capacity"), "0 100").unwrap();
        root
    }

    #[test]
    fn registration_waits_for_external_setup_and_retries_only_on_maintenance() {
        let root = temp_root();
        let app = root.0.join("app");
        std::fs::create_dir(&app).unwrap();
        let io = FakeIo::default();
        let mut policy = ForegroundPolicy::new(root.0.clone()).unwrap();
        policy.io = Box::new(io.clone());

        assert!(!policy.register(app.clone()));
        io.file(app.join("dmem.low"), &[("0", DmemValue::Finite(10))]);
        for _ in 0..3 {
            assert!(!policy.register(app.clone()));
            policy.process_events();
        }
        assert!(policy.pending_registration.contains(&app));
        assert!(policy.paths.is_empty());

        policy.maintenance();
        assert!(policy.pending_registration.is_empty());
        assert_eq!(policy.paths.len(), 1);
        assert_eq!(policy.watches.len(), 1);
        assert!(policy.foreground.is_none());
        assert!(io.0.borrow().writes.is_empty());
        assert!(policy.register(app.clone()));
        policy.maintenance();

        policy.untrack(&app);
        std::fs::remove_dir(&app).unwrap();
        assert!(!policy.register(app.clone()));
        assert!(policy.pending_registration.contains(&app));
        std::fs::create_dir(&app).unwrap();
        policy.maintenance();
        assert_eq!(policy.paths.len(), 1);
        assert!(policy.pending_registration.is_empty());

        policy.untrack(&app);
        io.0.borrow_mut().unwritable.insert(app.join("dmem.low"));
        assert!(!policy.register(app.clone()));
        policy.untrack(&app);
        policy.maintenance();
        assert!(policy.pending_registration.is_empty());
    }

    #[test]
    fn registration_retry_drops_deleted_unwatched_cgroup() {
        let root = temp_root();
        let app = root.0.join("app");
        std::fs::create_dir(&app).unwrap();
        let mut policy = ForegroundPolicy::new(root.0.clone()).unwrap();
        assert!(!policy.register(app.clone()));
        assert!(policy.pending_registration.contains(&app));

        std::fs::remove_dir(&app).unwrap();
        policy.maintenance();
        assert!(policy.pending_registration.is_empty());

        std::fs::create_dir(&app).unwrap();
        std::fs::write(app.join("dmem.low"), "0 10").unwrap();
        assert!(policy.register(app.clone()));
        assert!(policy.paths.contains_key(&app));
    }

    #[test]
    fn real_inotify_registration_retries_late_dmem_low() {
        let root = temp_root();
        let app = root.0.join("app");
        std::fs::create_dir(&app).unwrap();
        xattr::set(&app, FOCUS_XATTR, b"-1").unwrap();
        let mut policy = ForegroundPolicy::new(root.0.clone()).unwrap();
        assert!(!policy.register(app.clone()));
        for _ in 0..2 {
            policy.process_events();
            policy.maintenance();
            assert!(!policy.paths.contains_key(&app));
            assert!(policy.foreground.is_none());
        }
        std::fs::write(app.join("dmem.low"), "0 10").unwrap();
        for _ in 0..2 {
            policy.process_events();
            policy.maintenance();
            assert_eq!(policy.paths.len(), 1);
            assert_eq!(policy.foreground.as_ref(), Some(&app));
            assert_eq!(
                std::fs::read_to_string(app.join("dmem.low")).unwrap(),
                "0 100"
            );
        }
        xattr::set(&app, FOCUS_XATTR, b"1").unwrap();
        policy.process_events();
        assert!(policy.foreground.is_none());
        assert_eq!(
            std::fs::read_to_string(app.join("dmem.low")).unwrap(),
            "0 10"
        );
    }

    #[test]
    fn full_reconcile_revalidates_replaced_foreground_at_same_path() {
        let root = temp_root();
        let app = root.0.join("app");
        std::fs::create_dir(&app).unwrap();
        std::fs::write(app.join("dmem.low"), "0 10").unwrap();
        xattr::set(&app, FOCUS_XATTR, b"-1").unwrap();
        let mut policy = ForegroundPolicy::new(root.0.clone()).unwrap();
        policy.register(app.clone());
        policy.process_events();
        assert_eq!(policy.foreground.as_ref(), Some(&app));

        std::fs::remove_dir_all(&app).unwrap();
        std::fs::create_dir(&app).unwrap();
        std::fs::write(app.join("dmem.low"), "0 20").unwrap();
        xattr::set(&app, FOCUS_XATTR, b"-1").unwrap();
        // Overflow recovery replaces the watches without processing DELETE_SELF first.
        policy.rebuild_watches();
        policy.reconcile();
        assert!(policy.foreground.is_none());
        assert!(policy.pending_apply.contains(&app));
        policy.maintenance();
        assert_eq!(policy.foreground.as_ref(), Some(&app));
        assert_eq!(
            std::fs::read_to_string(app.join("dmem.low")).unwrap(),
            "0 100"
        );
        policy.shutdown();
        assert_eq!(
            std::fs::read_to_string(app.join("dmem.low")).unwrap(),
            "0 20"
        );
    }

    #[test]
    fn full_reconcile_keeps_cleanup_when_foreground_watch_is_lost() {
        let (mut policy, io, _, app) = setup();
        policy.activate(&app);
        policy.reconcile();
        assert!(policy.foreground.is_none());
        assert!(policy.pending_restore.contains(&app));
        policy.shutdown();
        assert_eq!(io.value(&app.join("dmem.low"), "0"), DmemValue::Finite(10));
        assert!(!io.has_xattr(&app, STATE_XATTR));
    }

    #[test]
    fn full_reconcile_keeps_cleanup_when_focus_read_fails() {
        let root = temp_root();
        let app = root.0.join("app");
        std::fs::create_dir(&app).unwrap();
        let io = FakeIo::default();
        io.file(
            root.0.join("dmem.capacity"),
            &[("0", DmemValue::Finite(100))],
        );
        io.file(app.join("dmem.low"), &[("0", DmemValue::Finite(10))]);
        io.xattr(&app, FOCUS_XATTR, b"-1");
        let mut policy = ForegroundPolicy::new(root.0.clone()).unwrap();
        policy.io = Box::new(io.clone());
        policy.register(app.clone());
        policy.process_events();
        assert_eq!(policy.foreground.as_ref(), Some(&app));
        io.0.borrow_mut().unreadable_focus.insert(app.clone());
        policy.reconcile();
        policy.maintenance();
        assert!(policy.foreground.is_none());
        assert!(policy.pending_apply.contains(&app));
        assert_eq!(io.0.borrow().write_calls, 1);
        policy.shutdown();
        assert_eq!(io.value(&app.join("dmem.low"), "0"), DmemValue::Finite(10));
        assert!(!io.has_xattr(&app, STATE_XATTR));
    }

    #[test]
    fn real_inotify_deleted_cgroup_drops_pending_restore_and_can_be_retracked() {
        let root = temp_root();
        let app = root.0.join("app");
        std::fs::create_dir(&app).unwrap();
        std::fs::write(app.join("dmem.low"), "0 10").unwrap();
        xattr::set(&app, FOCUS_XATTR, b"-1").unwrap();
        let mut policy = ForegroundPolicy::new(root.0.clone()).unwrap();
        policy.register(app.clone());
        policy.maintenance();
        assert_eq!(policy.foreground.as_ref(), Some(&app));
        std::fs::remove_file(app.join("dmem.low")).unwrap();
        policy.restore(&app);
        assert!(policy.pending_restore.contains(&app));
        std::fs::remove_dir(&app).unwrap();
        policy.process_events();
        assert!(policy.paths.is_empty());
        assert!(policy.watches.is_empty());
        assert!(policy.focus_values.is_empty());
        assert!(policy.pending_restore.is_empty());
        assert!(policy.pending_apply.is_empty());
        policy.maintenance();
        assert!(policy.pending_restore.is_empty());

        std::fs::create_dir(&app).unwrap();
        std::fs::write(app.join("dmem.low"), "0 20").unwrap();
        xattr::set(&app, FOCUS_XATTR, b"-1").unwrap();
        policy.process_events();
        policy.register(app.clone());
        policy.maintenance();
        assert_eq!(policy.foreground.as_ref(), Some(&app));
        assert_eq!(
            std::fs::read_to_string(app.join("dmem.low")).unwrap(),
            "0 100"
        );
        xattr::set(&app, FOCUS_XATTR, b"1").unwrap();
        policy.process_events();
        assert!(policy.foreground.is_none());
        assert_eq!(
            std::fs::read_to_string(app.join("dmem.low")).unwrap(),
            "0 20"
        );
        assert!(xattr::get(&app, STATE_XATTR).unwrap().is_none());
    }

    #[test]
    fn untracking_ambiguous_peer_applies_remaining_active_on_maintenance() {
        let (mut policy, io, root, app) = setup();
        let other = root.join("other");
        io.file(other.join("dmem.low"), &[("0", DmemValue::Finite(5))]);
        io.xattr(&other, FOCUS_XATTR, b"-1");
        policy.reconcile_paths(vec![app.clone(), other.clone()]);
        policy.untrack(&other);
        assert!(!policy.focus_values.contains_key(&other));
        policy.maintenance();
        assert!(policy.foreground.is_none());
        assert!(policy.pending_apply.contains(&app));
        policy.maintenance();
        assert_eq!(policy.foreground.as_ref(), Some(&app));
        assert_eq!(io.value(&app.join("dmem.low"), "0"), DmemValue::Finite(100));
    }

    #[test]
    fn real_inotify_self_attrib_and_multiple_active_paths_settle() {
        let root = temp_root();
        let mut policy = ForegroundPolicy::new(root.0.clone()).unwrap();
        let apps: Vec<_> = (0..3)
            .map(|index| root.0.join(format!("app{index}")))
            .collect();
        for app in &apps {
            std::fs::create_dir(app).unwrap();
            std::fs::write(app.join("dmem.low"), "0 10").unwrap();
            xattr::set(app, FOCUS_XATTR, b"-1").unwrap();
        }
        policy.register(apps[0].clone());
        policy.process_events();
        assert_eq!(policy.foreground.as_ref(), Some(&apps[0]));
        policy.process_events();
        assert_eq!(policy.foreground.as_ref(), Some(&apps[0]));
        // One active path has recovery state; the newly discovered ones do not.
        policy.register(apps[1].clone());
        policy.register(apps[2].clone());
        for _ in 0..5 {
            policy.process_events();
        }
        assert!(policy.foreground.is_none());
        assert_eq!(policy.ambiguous_active.len(), 3);
        xattr::set(&apps[0], FOCUS_XATTR, b"1").unwrap();
        policy.process_events();
        assert!(policy.foreground.is_none());
        assert_eq!(policy.ambiguous_active.len(), 2);
        xattr::set(&apps[1], FOCUS_XATTR, b"1").unwrap();
        policy.process_events();
        assert_eq!(policy.foreground.as_ref(), Some(&apps[2]));
        policy.process_events();
        let mut buffer = [0; 4096];
        match policy.inotify.as_mut().unwrap().read_events(&mut buffer) {
            Ok(events) => assert_eq!(events.count(), 0),
            Err(error) => assert_eq!(error.kind(), io::ErrorKind::WouldBlock),
        }
        policy.shutdown();
        for app in apps {
            assert_eq!(
                std::fs::read_to_string(app.join("dmem.low")).unwrap(),
                "0 10"
            );
            assert!(xattr::get(&app, STATE_XATTR).unwrap().is_none());
        }
    }
}
