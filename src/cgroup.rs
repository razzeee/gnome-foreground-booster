use std::collections::BTreeMap;
use std::fmt::{self, Display};
use std::io;
use std::path::{Path, PathBuf};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum DmemValue {
    Finite(u64),
    Max,
}

impl Display for DmemValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Finite(value) => value.fmt(formatter),
            Self::Max => formatter.write_str("max"),
        }
    }
}

impl DmemValue {
    pub(crate) fn parse(value: &str) -> Result<Self, &'static str> {
        if value == "max" {
            Ok(Self::Max)
        } else {
            value
                .parse::<u64>()
                .map(Self::Finite)
                .map_err(|_| "invalid dmem value")
        }
    }
}

pub(crate) type DmemValues = BTreeMap<String, DmemValue>;

pub(crate) fn valid_region(region: &str) -> bool {
    !region.is_empty() && !region.chars().any(char::is_whitespace)
}

pub(crate) fn parse_dmem_values(input: &str) -> Result<DmemValues, &'static str> {
    let mut values = DmemValues::new();
    for line in input.lines() {
        let mut words = line.split_ascii_whitespace();
        let region = words.next().ok_or("missing dmem region")?;
        let value = words.next().ok_or("missing dmem value")?;
        if words.next().is_some() || !valid_region(region) {
            return Err("invalid dmem line");
        }
        if values
            .insert(region.to_owned(), DmemValue::parse(value)?)
            .is_some()
        {
            return Err("duplicate dmem region");
        }
    }
    Ok(values)
}

pub(crate) fn write_dmem(path: &Path, region: &str, value: DmemValue) -> io::Result<()> {
    std::fs::write(path, format!("{region} {value}"))
}

pub(crate) fn is_application_cgroup(root: &Path, path: &Path) -> bool {
    path != root
        && path.starts_with(root)
        && !path
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir))
        && path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.ends_with(".scope") || name.ends_with(".service"))
}

pub(crate) fn application_cgroups(root: &Path) -> Vec<PathBuf> {
    let mut applications = Vec::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        let Ok(entries) = std::fs::read_dir(directory) else {
            continue;
        };
        for entry in entries.flatten() {
            // Never follow symlinks out of the application tree.
            if !entry.file_type().is_ok_and(|kind| kind.is_dir()) {
                continue;
            }
            let path = entry.path();
            if is_application_cgroup(root, &path) {
                applications.push(path.clone());
            }
            pending.push(path);
        }
    }
    applications
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_regions_without_conflating_max_and_u64_max() {
        let values =
            parse_dmem_values(&format!("0\t42\n0000:03:00.0/1 max\n2 {}\n", u64::MAX)).unwrap();
        assert_eq!(values["0"], DmemValue::Finite(42));
        assert_eq!(values["0000:03:00.0/1"], DmemValue::Max);
        assert_eq!(values["2"], DmemValue::Finite(u64::MAX));
        assert!(values["2"] < values["0000:03:00.0/1"]);
        assert!(parse_dmem_values("").unwrap().is_empty());
    }

    #[test]
    fn rejects_malformed_dmem_values() {
        for input in [
            "\n",
            "0",
            "0 1 extra",
            "0 1\n0 max",
            "0 -1",
            "0 18446744073709551616",
            "0 nope",
            "bad\u{a0}region 1",
        ] {
            assert!(parse_dmem_values(input).is_err(), "{input:?}");
        }
    }

    #[test]
    fn application_paths_stay_under_the_resolved_root() {
        let root =
            Path::new("/sys/fs/cgroup/user.slice/user-1000.slice/user@1000.service/app.slice");
        assert!(is_application_cgroup(root, &root.join("app.scope")));
        assert!(is_application_cgroup(
            root,
            &root.join("nested.slice/app.service")
        ));
        assert!(!is_application_cgroup(root, root));
        assert!(!is_application_cgroup(root, &root.join("nested.slice")));
        assert!(!is_application_cgroup(
            root,
            &root.join("../background.slice/app.scope")
        ));
        assert!(!is_application_cgroup(
            root,
            Path::new(
                "/sys/fs/cgroup/user.slice/user-1001.slice/user@1001.service/app.slice/app.scope"
            )
        ));
        assert!(!is_application_cgroup(
            root,
            &root.with_file_name("app.slice-other").join("app.scope")
        ));
    }

    #[test]
    fn discovery_recurses_without_following_symlinks() {
        let directory = std::env::temp_dir().join(format!(
            "gnome-foreground-discovery-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&directory).unwrap();
        let root = directory.join("app.slice");
        let nested = root.join("nested.slice/app.service");
        let app = root.join("app.scope");
        std::fs::create_dir_all(&nested).unwrap();
        std::fs::create_dir(&app).unwrap();
        std::fs::create_dir(directory.join("outside.scope")).unwrap();
        std::os::unix::fs::symlink(directory.join("outside.scope"), root.join("link.scope"))
            .unwrap();
        let mut paths = application_cgroups(&root);
        paths.sort();
        assert_eq!(paths, vec![app, nested]);
        assert!(application_cgroups(&directory.join("missing")).is_empty());
        std::fs::remove_dir_all(directory).unwrap();
    }
}
