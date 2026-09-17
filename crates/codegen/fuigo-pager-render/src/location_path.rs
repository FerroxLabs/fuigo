use std::borrow::Cow;

/// Display-only middle-component shortener for already-abbreviated location paths.
///
/// After a `~` / `$FUIGO_HOME` prefix (or a leading `/` / drive letter / UNC
/// `\\server\share` / `//host/share` / `\\?\UNC\server\share`), the last two
/// components stay full and earlier ones become one letter. Leading dots are
/// kept plus the first non-dot character (`.fuigo` → `.f`, `..cache` → `..c`).
/// Literal `.` / `..` stay as-is. Drive-relative `C:foo\bar` does not gain a
/// root separator; rooted `\foo\bar` keeps one. Paths with 0–2 components
/// after the prefix are unchanged.
pub(crate) fn shorten_location_path(path: &str) -> Cow<'_, str> {
    Cow::Borrowed(path)
}

#[cfg(test)]
#[path = "location_path_tests.rs"]
mod tests;
