//! Persist original limits before boosting, then restore or recover them.

use crate::cgroup::{DmemValue, parse_dmem_values, valid_region};
use crate::diagnostics::debug;
use crate::foreground::ForegroundPolicy;
use std::collections::BTreeMap;
use std::io;
use std::path::Path;

// Keep the historical name so upgrades recover records from the integrated daemon.
pub(crate) const STATE_XATTR: &str = "user.dmemcg-booster.dmem-low-state";

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct StateEntry {
    pub(crate) baseline: DmemValue,
    applied: DmemValue,
}

type RecoveryState = BTreeMap<String, StateEntry>;

pub(crate) fn parse_state(input: &[u8]) -> Result<RecoveryState, &'static str> {
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

impl ForegroundPolicy {
    pub(crate) fn activate(&mut self, path: &Path) {
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
                    self.diagnostics.warn(
                        "capacity",
                        format_args!("Could not parse root dmem.capacity: {error}"),
                    );
                    return;
                }
            },
            Err(error) => {
                self.diagnostics.warn("capacity", format_args!(
                    "Cannot read root dmem.capacity: {error}; check the dmem controller and driver"
                ));
                return;
            }
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
            debug(format_args!(
                "No additional dmem.low values to apply for {}",
                path.display()
            ));
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
            debug(format_args!(
                "Boosted {} region {region}: {} -> {}",
                path.display(),
                entry.baseline,
                entry.applied
            ));
        }
        self.foreground = Some(path.to_path_buf());
        self.pending_apply.remove(path);
    }

    pub(crate) fn restore(&mut self, path: &Path) {
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
            debug(format_args!(
                "No boosted values remain on {}; preserving current limits",
                path.display()
            ));
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
            match self.io.write_dmem(&low_path, region, entry.baseline) {
                Ok(()) => debug(format_args!(
                    "Restored {} region {region}: {} -> {}",
                    path.display(),
                    entry.applied,
                    entry.baseline
                )),
                Err(error) => {
                    self.diagnostics.warn("restore-write", format_args!(
                        "Cannot restore {} region {region}: {error}; retaining recovery state for retry",
                        path.display()
                    ));
                    retry.insert(region.clone(), entry.clone());
                }
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
        debug(format_args!(
            "Recovered foreground state for {}",
            path.display()
        ));
        true
    }
}
