//! Whether a directory sits on a network or virtual filesystem.
//!
//! Counting every file in a subtree is cheap on a local disk and slow or endless on an NFS or SMB mount, a FUSE mount,
//! a WSL drive or `/proc`. `list_dir` lists such a directory's top level only and says why the counts are missing.

use std::path::Path;

/// Filesystem type names whose subtrees are not worth walking: network mounts, userspace (FUSE) mounts, shared-folder
/// mounts of virtual machines, and kernel-generated trees.
#[cfg(any(target_os = "linux", test))]
pub(super) fn is_remote_or_virtual_fstype(fstype: &str) -> bool {
    let f = fstype.to_ascii_lowercase();
    // `fuseblk` is a block device handled in user space (NTFS-3G on a local disk); `fusectl` is a control file system.
    if f == "fuseblk" || f == "fusectl" {
        return false;
    }
    f.starts_with("nfs")
        || f.starts_with("fuse")
        || f.starts_with("ceph")
        || f.starts_with("cifs")
        || f.starts_with("smb")
        || f.starts_with("cgroup")
        || matches!(
            f.as_str(),
            "9p" | "drvfs" | "virtiofs" | "vboxsf" | "vmhgfs" | "afs" | "afpfs" | "davfs" | "ncpfs" | "lustre"
                | "glusterfs" | "gpfs" | "beegfs" | "ocfs2" | "proc" | "sysfs" | "debugfs" | "tracefs"
                | "securityfs" | "pstore" | "bpf" | "configfs" | "autofs" | "webdav"
        )
}

/// Undo the octal escapes the kernel writes in `/proc/self/mountinfo` fields (space is `\040`, tab `\011`, ...).
#[cfg(any(target_os = "linux", test))]
fn unescape_mountinfo_field(s: &str) -> String {
    if !s.contains('\\') {
        return s.to_string();
    }
    let bytes = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(s.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\'
            && i + 4 <= bytes.len()
            && bytes[i + 1..i + 4].iter().all(u8::is_ascii_digit)
            && let Ok(code) = u8::from_str_radix(&s[i + 1..i + 4], 8)
        {
            out.push(code);
            i += 4;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// The filesystem type of the longest mount point in `mountinfo` that covers `path`.
#[cfg(any(target_os = "linux", test))]
fn longest_covering_fstype(mountinfo: &str, path: &Path) -> Option<String> {
    let path_s = path.to_string_lossy();
    let mut best: Option<(usize, String)> = None;
    for line in mountinfo.lines() {
        let mut sides = line.splitn(2, " - ");
        let (Some(left), Some(right)) = (sides.next(), sides.next()) else {
            continue;
        };
        let (Some(mount_point), Some(fstype)) = (left.split_whitespace().nth(4), right.split_whitespace().next()) else {
            continue;
        };
        let mount_point = unescape_mountinfo_field(mount_point);
        let covers = mount_point == "/" || path_s == mount_point || path_s.starts_with(&format!("{mount_point}/"));
        if covers && best.as_ref().is_none_or(|(len, _)| mount_point.len() >= *len) {
            best = Some((mount_point.len(), fstype.to_owned()));
        }
    }
    best.map(|(_, fstype)| fstype)
}

/// `Some(fstype)` when `path` is on a network or virtual filesystem. Linux reads the mount table; other platforms
/// report `None` (the full listing, as before).
pub(super) fn network_or_virtual_filesystem(path: &Path) -> Option<String> {
    #[cfg(target_os = "linux")]
    {
        let mountinfo = std::fs::read_to_string("/proc/self/mountinfo").ok()?;
        let resolved = dunce::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
        longest_covering_fstype(&mountinfo, &resolved).filter(|fstype| is_remote_or_virtual_fstype(fstype))
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = path;
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MOUNTINFO: &str = "\
22 1 8:2 / / rw,relatime shared:1 - ext4 /dev/sda2 rw
30 22 0:25 / /proc rw,nosuid shared:5 - proc proc rw
41 22 0:40 / /mnt/share\\040drive rw,relatime shared:9 - nfs4 server:/export rw
42 41 0:41 / /mnt/share\\040drive/local rw shared:10 - ext4 /dev/sdb1 rw
50 22 0:50 / /home/u/mnt rw - fuse.sshfs u@h:/ rw
";

    #[test]
    fn the_longest_covering_mount_decides() {
        let at = |p: &str| longest_covering_fstype(MOUNTINFO, Path::new(p));
        assert_eq!(at("/home/u/src").as_deref(), Some("ext4"));
        assert_eq!(at("/proc/self").as_deref(), Some("proc"));
        assert_eq!(at("/mnt/share drive/a/b").as_deref(), Some("nfs4"), "octal escapes in the mount point");
        assert_eq!(at("/mnt/share drive/local/x").as_deref(), Some("ext4"), "a local mount inside a network one");
        assert_eq!(at("/home/u/mnt/deep").as_deref(), Some("fuse.sshfs"));
        assert_eq!(at("/proceedings").as_deref(), Some("ext4"), "a prefix of the name is not a parent");
    }

    #[test]
    fn network_and_virtual_types_are_recognised_and_local_ones_are_not() {
        for yes in ["nfs", "nfs4", "cifs", "smb3", "smbfs", "fuse", "fuse.sshfs", "9p", "drvfs", "virtiofs", "proc", "sysfs", "cgroup2"] {
            assert!(is_remote_or_virtual_fstype(yes), "{yes}");
        }
        for no in ["ext4", "xfs", "btrfs", "tmpfs", "overlay", "zfs", "apfs", "ntfs", "fuseblk", "fusectl", "devtmpfs"] {
            assert!(!is_remote_or_virtual_fstype(no), "{no}");
        }
    }
}
