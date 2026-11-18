use crate::defs;
use anyhow::{Context, Result, bail};
use jwalk::{Parallelism::Serial, WalkDir};
use std::path::Path;

use anyhow::Ok;
use extattr::{Flags as XattrFlags, lsetxattr};

pub const SYSTEM_CON: &str = "u:object_r:system_file:s0";
pub const KSU_CON: &str = "u:object_r:ksu_file:s0";
pub const UNLABEL_CON: &str = "u:object_r:unlabeled:s0";

const SELINUX_XATTR: &str = "security.selinux";

pub fn lsetfilecon<P: AsRef<Path>>(path: P, con: &str) -> Result<()> {
    lsetxattr(&path, SELINUX_XATTR, con, XattrFlags::empty()).with_context(|| {
        format!(
            "Failed to change SELinux context for {}",
            path.as_ref().display()
        )
    })?;
    Ok(())
}

pub fn lgetfilecon<P: AsRef<Path>>(path: P) -> Result<String> {
    let con = extattr::lgetxattr(&path, SELINUX_XATTR).with_context(|| {
        format!(
            "Failed to get SELinux context for {}",
            path.as_ref().display()
        )
    })?;
    let con = String::from_utf8_lossy(&con);
    Ok(con.to_string())
}

fn is_usable_existing_context(con: &str) -> bool {
    !con.is_empty() && con != UNLABEL_CON
}

pub fn label_ksud<P: AsRef<Path>>(path: P) -> Result<()> {
    let path = path.as_ref();
    let inherited = lgetfilecon(path).context("Failed to read inherited ksud SELinux context")?;

    match lsetxattr(path, SELINUX_XATTR, KSU_CON, XattrFlags::empty()) {
        std::result::Result::Ok(()) => {}
        Err(error) if error.0 == libc::EINVAL => {
            // Samsung SEPF can reject the dynamically added ksu_file type.
            // A newly copied file already has a context from the active policy,
            // so retain that context instead of forcing another vendor type.
            if is_usable_existing_context(&inherited) {
                log::warn!(
                    "SELinux policy rejected {KSU_CON}; retaining inherited context {inherited}"
                );
            } else {
                lsetfilecon(path, SYSTEM_CON).with_context(|| {
                    format!(
                        "ksu_file is unavailable and inherited context {inherited:?} is unusable; fallback to {SYSTEM_CON} failed"
                    )
                })?;
            }
        }
        Err(error) => {
            return Err(error).with_context(|| {
                format!(
                    "Failed to change SELinux context for {} to {KSU_CON}",
                    path.display()
                )
            });
        }
    }

    let actual = lgetfilecon(path).context("Failed to verify ksud SELinux context")?;
    if !is_usable_existing_context(&actual) {
        bail!("ksud has unusable SELinux context {actual:?}");
    }
    log::info!("ksud SELinux label: requested={KSU_CON}, inherited={inherited}, actual={actual}");
    Ok(())
}

pub fn setsyscon<P: AsRef<Path>>(path: P) -> Result<()> {
    lsetfilecon(path, SYSTEM_CON)
}

pub fn restore_syscon<P: AsRef<Path>>(dir: P) -> Result<()> {
    for dir_entry in WalkDir::new(dir).parallelism(Serial) {
        if let Some(path) = dir_entry.ok().map(|dir_entry| dir_entry.path()) {
            setsyscon(&path)?;
        }
    }
    Ok(())
}

fn restore_syscon_if_unlabeled<P: AsRef<Path>>(dir: P) -> Result<()> {
    for dir_entry in WalkDir::new(dir).parallelism(Serial) {
        if let Some(path) = dir_entry.ok().map(|dir_entry| dir_entry.path())
            && let anyhow::Result::Ok(con) = lgetfilecon(&path)
            && (con == UNLABEL_CON || con.is_empty())
        {
            lsetfilecon(&path, SYSTEM_CON)?;
        }
    }
    Ok(())
}

pub fn restorecon() -> Result<()> {
    label_ksud(defs::DAEMON_PATH)?;
    restore_syscon_if_unlabeled(defs::MODULE_DIR)?;
    Ok(())
}
