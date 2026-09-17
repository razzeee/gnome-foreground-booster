//! Rate-limit prerequisite warnings independently of the policy's retry schedule.

use std::collections::HashMap;
use std::fmt;
use std::io;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

#[derive(Default)]
pub(crate) struct Diagnostics {
    warnings: HashMap<&'static str, Instant>,
}

impl Diagnostics {
    pub(crate) fn warn(&mut self, category: &'static str, message: fmt::Arguments<'_>) {
        if self.should_warn(category, Instant::now()) {
            eprintln!("WARNING: {message}");
        }
    }

    fn should_warn(&mut self, category: &'static str, now: Instant) -> bool {
        if self
            .warnings
            .get(category)
            .is_some_and(|last| now.duration_since(*last) < Duration::from_secs(60))
        {
            return false;
        }
        self.warnings.insert(category, now);
        true
    }
}

pub(crate) fn debug(message: fmt::Arguments<'_>) {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    if *ENABLED
        .get_or_init(|| std::env::var("GNOME_FOREGROUND_BOOSTER_DEBUG").as_deref() == Ok("1"))
    {
        eprintln!("DEBUG: {message}");
    }
}

pub(crate) fn inotify_error(error: io::Error) -> io::Error {
    let hint = match error.raw_os_error() {
        Some(libc::EMFILE) => {
            "; check fs.inotify.max_user_instances and the process open-file limit"
        }
        Some(libc::ENFILE) => "; the system-wide open-file limit has been reached",
        _ => "",
    };
    io::Error::new(
        error.kind(),
        format!("could not initialize inotify for application focus watches: {error}{hint}"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn warnings_are_bounded_per_category_without_delaying_new_categories() {
        let mut diagnostics = Diagnostics::default();
        let start = Instant::now();
        assert!(diagnostics.should_warn("registration", start));
        for second in 1..60 {
            assert!(!diagnostics.should_warn("registration", start + Duration::from_secs(second)));
        }
        assert!(diagnostics.should_warn("focus", start + Duration::from_secs(1)));
        assert!(diagnostics.should_warn("registration", start + Duration::from_secs(60)));
        assert!(!diagnostics.should_warn("registration", start + Duration::from_secs(61)));
    }
}
