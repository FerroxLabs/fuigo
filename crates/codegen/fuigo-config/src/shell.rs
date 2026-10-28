//! Windows shell detection for terminal command execution.
//!
//! Default cascade: pwsh, then powershell.exe, then Git Bash, then powershell.exe as the fallback.
//!
//! PowerShell is preferred over Git Bash: MSYS2 path translation mangles every flag starting with `/` (e.g. MSBuild `/t:Build`, cl.exe `/nologo`).
//! This breaks native Windows C++/C#/.NET builds.
//!
//! Set `FUIGO_SHELL` to override auto-detection: `pwsh`, `powershell`, `bash`, or `cmd`.
//! The result is cached for the process lifetime, with the shell's ABSOLUTE path resolved once at
//! detection: a bare program name would be re-resolved through the child's own `PATH` at every
//! spawn, so a child environment with a broken `PATH` failed every shell spawn with "program not
//! found". The bare name is kept only as a last resort when no path can be resolved.
//!
//! Where each path comes from: `pwsh.exe` and Git Bash's `bash.exe` from this process's `PATH`
//! directories (absolute drive paths only, never the current directory, as `std` would resolve the
//! bare name), `powershell.exe` and `cmd.exe` from the system directory the OS reports
//! (`GetSystemDirectoryW`, not `%SystemRoot%`), `%ComSpec%` only inside the real Windows directory.

/// Detected Windows shell and how to invoke it.
#[cfg(not(unix))]
#[derive(Clone, Debug)]
pub enum WindowsShell {
    /// Git Bash, by its absolute `bash.exe` path.
    GitBash(String),
    /// PowerShell 7+, by its absolute `pwsh.exe` path (bare `pwsh` only as a last resort).
    Pwsh(String),
    /// Windows PowerShell 5.1, by its absolute `powershell.exe` path (bare name as a last resort).
    PowerShell(String),
    /// `cmd.exe`, by its absolute path (bare `cmd` as a last resort).
    Cmd(String),
}

/// Whether `path` is an absolute Windows path on a drive (`C:\...` or `C:/...`). A UNC or device
/// path (`\\server\share`, `\\?\...`), a root-relative path (`\x`) and a drive-relative path (`C:x`)
/// are not. Checked textually so it gives the Windows answer on every host.
#[cfg_attr(unix, allow(dead_code))]
fn is_drive_absolute(path: &str) -> bool {
    let b = path.as_bytes();
    b.len() >= 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && (b[2] == b'\\' || b[2] == b'/')
}

/// `path` normalised for comparison: `/` as `\`, `.` and `..` components resolved, empty components
/// and trailing separators dropped, lower-cased (Windows paths are case-insensitive).
#[cfg_attr(unix, allow(dead_code))]
fn normalize_windows_path(path: &str) -> String {
    let mut parts: Vec<&str> = Vec::new();
    for part in path.split(['\\', '/']) {
        match part {
            "" | "." => {}
            ".." => {
                if parts.len() > 1 {
                    parts.pop();
                }
            }
            part => parts.push(part),
        }
    }
    parts.join("\\").to_lowercase()
}

/// The final component of a Windows path.
#[cfg_attr(unix, allow(dead_code))]
fn windows_file_name(path: &str) -> &str {
    path.rsplit(['\\', '/']).next().unwrap_or(path)
}

/// Whether `path` lies inside the directory `dir` (or is `dir`), compared normalised.
#[cfg_attr(unix, allow(dead_code))]
fn is_inside(path: &str, dir: &str) -> bool {
    let (path, dir) = (normalize_windows_path(path), normalize_windows_path(dir));
    !dir.is_empty() && (path == dir || path.starts_with(&format!("{dir}\\")))
}

/// `PATH` split the way Windows reads it: `;`-separated, a double-quoted run may hold a `;`, the
/// quotes themselves dropped.
#[cfg_attr(unix, allow(dead_code))]
fn windows_path_entries(path_var: &str) -> Vec<String> {
    let mut entries = vec![String::new()];
    let mut quoted = false;
    for c in path_var.chars() {
        match c {
            '"' => quoted = !quoted,
            ';' if !quoted => entries.push(String::new()),
            c => entries.last_mut().expect("never empty").push(c),
        }
    }
    entries
}

/// Every existing `file_name` in the `PATH` directories, in `PATH` order, found the way Rust's
/// `std` resolves a bare program name: through the listed directories only, NEVER the current
/// directory. An empty entry, a relative one (`.`, `bin`, `\x`, `C:x`), a UNC or device path, and
/// an entry naming the current directory `cwd` are skipped, so a `pwsh.exe` dropped into the
/// repository Fuigo was started in cannot become the stored shell. (`where.exe`, used before,
/// searches the current directory first and ignores `NoDefaultCurrentDirectoryInExePath`.)
#[cfg_attr(unix, allow(dead_code))]
fn path_candidates(
    path_var: &str,
    file_name: &str,
    cwd: Option<&str>,
    exists: impl Fn(&str) -> bool,
) -> Vec<String> {
    windows_path_entries(path_var)
        .iter()
        .map(|entry| entry.trim())
        .filter(|entry| is_drive_absolute(entry))
        .filter(|entry| cwd.is_none_or(|cwd| normalize_windows_path(entry) != normalize_windows_path(cwd)))
        .map(|entry| format!("{}\\{file_name}", entry.trim_end_matches(['\\', '/'])))
        .filter(|candidate| exists(candidate))
        .collect()
}

/// The `pwsh.exe` to store: the first one on `PATH` (see [`path_candidates`]).
#[cfg_attr(unix, allow(dead_code))]
fn pwsh_from_path(path_var: &str, cwd: Option<&str>, exists: impl Fn(&str) -> bool) -> Option<String> {
    path_candidates(path_var, "pwsh.exe", cwd, exists).into_iter().next()
}

/// Whether `path` is a Git for Windows `bash.exe`: the file is `bash.exe` and a directory on its
/// path IS a Git install (`...\Git\bin`, `...\PortableGit\usr\bin`, scoop's `...\apps\git\...`,
/// the Git SDK's `git-sdk-64`), which leaves out WSL's `System32\bash.exe` and any directory that
/// merely contains the letters (`digital`, `GitHub`).
#[cfg_attr(unix, allow(dead_code))]
fn is_git_bash(path: &str) -> bool {
    let mut parts: Vec<&str> = path.split(['\\', '/']).collect();
    let file = parts.pop().unwrap_or_default();
    let is_git_dir = |dir: &str| {
        let dir = dir.to_ascii_lowercase();
        dir == "git" || dir == "portablegit" || dir.starts_with("git-")
    };
    file.eq_ignore_ascii_case("bash.exe") && parts.iter().any(|p| is_git_dir(p))
}

/// The Git Bash to store: the first install-location candidate (absolute drive paths only) that
/// exists, else the first Git `bash.exe` on `PATH` (see [`path_candidates`]).
#[cfg_attr(unix, allow(dead_code))]
fn git_bash_path(
    install_roots: &[Option<String>],
    path_var: &str,
    cwd: Option<&str>,
    exists: impl Fn(&str) -> bool,
) -> Option<String> {
    install_roots
        .iter()
        .flatten()
        .map(|root| root.trim())
        .filter(|root| is_drive_absolute(root))
        .map(|root| format!("{}\\bash.exe", root.trim_end_matches(['\\', '/'])))
        .find(|candidate| exists(candidate))
        .or_else(|| {
            path_candidates(path_var, "bash.exe", cwd, &exists)
                .into_iter()
                .find(|candidate| is_git_bash(candidate))
        })
}

/// `<system dir>\WindowsPowerShell\v1.0\powershell.exe` when that exists.
#[cfg_attr(unix, allow(dead_code))]
fn powershell_path(system_dir: &str, exists: impl Fn(&str) -> bool) -> Option<String> {
    let path = format!(
        "{}\\WindowsPowerShell\\v1.0\\powershell.exe",
        system_dir.trim_end_matches(['\\', '/'])
    );
    exists(&path).then_some(path)
}

/// `cmd.exe`: `<system dir>\cmd.exe` if it exists, else `%ComSpec%` when it is an absolute
/// `cmd.exe` (by its final component) inside the real Windows directory and exists, else the bare
/// `cmd` (last resort, resolved through `PATH` at spawn). A `ComSpec` pointing anywhere else (a
/// repository, a temp directory) is ignored.
#[cfg_attr(unix, allow(dead_code))]
fn cmd_path(
    system_dir: &str,
    windows_dir: &str,
    comspec: Option<&str>,
    exists: impl Fn(&str) -> bool,
) -> String {
    let system = format!("{}\\cmd.exe", system_dir.trim_end_matches(['\\', '/']));
    if exists(&system) {
        return system;
    }
    if let Some(comspec) = comspec.map(str::trim)
        && is_drive_absolute(comspec)
        && windows_file_name(comspec).eq_ignore_ascii_case("cmd.exe")
        && is_inside(comspec, windows_dir)
        && exists(comspec)
    {
        return comspec.to_string();
    }
    "cmd".to_string()
}

/// A directory the OS reports through `api` (`GetSystemDirectoryW` / `GetSystemWindowsDirectoryW`).
#[cfg(windows)]
fn os_directory(api: unsafe fn(Option<&mut [u16]>) -> u32) -> Option<String> {
    let mut buf = vec![0u16; 260];
    for _ in 0..4 {
        // SAFETY: `buf` is a live, writable buffer; the API writes at most `buf.len()` units and
        // returns the length written (without the NUL), the size needed (with it), or 0 on failure.
        let n = unsafe { api(Some(&mut buf)) } as usize;
        if n == 0 {
            return None;
        }
        if n < buf.len() {
            return String::from_utf16(&buf[..n]).ok();
        }
        buf.resize(n, 0);
    }
    None
}

/// The real system directory (`C:\Windows\System32`), from the OS, never from `%SystemRoot%`: a
/// parent process can set that variable to a directory holding its own `powershell.exe`.
#[cfg(not(unix))]
fn system_directory() -> String {
    #[cfg(windows)]
    {
        if let Some(dir) = os_directory(windows::Win32::System::SystemInformation::GetSystemDirectoryW) {
            return dir;
        }
    }
    "C:\\Windows\\System32".to_string()
}

/// The real Windows directory (`C:\Windows`), from the OS (shared one on a terminal server).
#[cfg(not(unix))]
fn windows_directory() -> String {
    #[cfg(windows)]
    {
        if let Some(dir) = os_directory(windows::Win32::System::SystemInformation::GetSystemWindowsDirectoryW) {
            return dir;
        }
    }
    "C:\\Windows".to_string()
}

#[cfg(not(unix))]
fn path_exists(path: &str) -> bool {
    std::path::Path::new(path).is_file()
}

/// The current directory as a string, for [`path_candidates`].
#[cfg(not(unix))]
fn current_dir_string() -> Option<String> {
    std::env::current_dir().ok().and_then(|d| d.into_os_string().into_string().ok())
}

/// Absolute `pwsh.exe` path from this process's `PATH` (never the current directory).
#[cfg(not(unix))]
fn find_pwsh() -> Option<String> {
    let path_var = std::env::var("PATH").unwrap_or_default();
    pwsh_from_path(&path_var, current_dir_string().as_deref(), path_exists)
}

#[cfg(not(unix))]
fn detect_powershell() -> WindowsShell {
    WindowsShell::PowerShell(
        powershell_path(&system_directory(), path_exists).unwrap_or_else(|| "powershell.exe".to_string()),
    )
}

#[cfg(not(unix))]
fn detect_cmd() -> WindowsShell {
    let comspec = std::env::var("ComSpec").ok();
    WindowsShell::Cmd(cmd_path(
        &system_directory(),
        &windows_directory(),
        comspec.as_deref(),
        path_exists,
    ))
}

/// Detect the best available shell on Windows.
///
/// If `FUIGO_SHELL` is set, it takes precedence over auto-detection.
/// Otherwise the cascade is: pwsh → powershell.exe → Git Bash → cmd.exe.
///
/// Result is cached for the process lifetime.
#[cfg(not(unix))]
pub fn detect_windows_shell() -> &'static WindowsShell {
    use std::sync::OnceLock;
    static CACHED: OnceLock<WindowsShell> = OnceLock::new();

    CACHED.get_or_init(|| {
        // Explicit override via FUIGO_SHELL.
        if let Ok(val) = std::env::var("FUIGO_SHELL") {
            match val.trim().to_ascii_lowercase().as_str() {
                "pwsh" => {
                    let path = find_pwsh().unwrap_or_else(|| "pwsh".to_string());
                    tracing::info!(shell = %path, "Windows shell (FUIGO_SHELL override): pwsh");
                    return WindowsShell::Pwsh(path);
                }
                "powershell" => {
                    let shell = detect_powershell();
                    tracing::info!(shell = %shell.program(), "Windows shell (FUIGO_SHELL override): powershell.exe");
                    return shell;
                }
                "bash" | "gitbash" | "git-bash" => {
                    if let Some(path) = find_git_bash() {
                        tracing::info!(
                            shell = path,
                            "Windows shell (FUIGO_SHELL override): Git Bash"
                        );
                        return WindowsShell::GitBash(path);
                    }
                    tracing::warn!(
                        "FUIGO_SHELL={val} but Git Bash not found; falling through to auto-detect"
                    );
                }
                "cmd" | "cmd.exe" => {
                    let shell = detect_cmd();
                    tracing::info!(shell = %shell.program(), "Windows shell (FUIGO_SHELL override): cmd.exe");
                    return shell;
                }
                other => {
                    tracing::warn!(
                        "FUIGO_SHELL={other} is not recognized \
                         (expected pwsh|powershell|bash|cmd); falling through to auto-detect"
                    );
                }
            }
        }

        // Auto-detect: prefer PowerShell over Git Bash
        // PowerShell passes `/flag` arguments through unchanged, which is required for native Windows toolchains (MSBuild, cl.exe, dotnet)

        // pwsh (PowerShell 7+), by its absolute path on `PATH`.
        if let Some(path) = find_pwsh() {
            tracing::info!(shell = %path, "Windows shell: pwsh");
            return WindowsShell::Pwsh(path);
        }

        // powershell.exe (Windows PowerShell 5.1), in the real system directory.
        if let Some(path) = powershell_path(&system_directory(), path_exists) {
            tracing::info!(shell = %path, "Windows shell: powershell.exe");
            return WindowsShell::PowerShell(path);
        }

        // Git Bash: available but not preferred (MSYS2 path translation breaks `/flag` arguments for native toolchains)
        if let Some(path) = find_git_bash() {
            tracing::info!(shell = path, "Windows shell: Git Bash");
            return WindowsShell::GitBash(path);
        }

        let shell = detect_powershell();
        tracing::info!(shell = %shell.program(), "Windows shell: powershell.exe (fallback)");
        shell
    })
}

/// Checks common install paths, then `PATH` for a Git `bash.exe` (never the current directory, never
/// WSL's `bash.exe`); see [`git_bash_path`].
#[cfg(not(unix))]
fn find_git_bash() -> Option<String> {
    let roots = [
        std::env::var("PROGRAMFILES").ok().map(|pf| format!("{pf}\\Git\\bin")),
        std::env::var("PROGRAMFILES(X86)").ok().map(|pf| format!("{pf}\\Git\\bin")),
        std::env::var("LOCALAPPDATA").ok().map(|la| format!("{la}\\Programs\\Git\\bin")),
    ];
    let path_var = std::env::var("PATH").unwrap_or_default();
    git_bash_path(&roots, &path_var, current_dir_string().as_deref(), path_exists)
}

#[cfg(not(unix))]
impl WindowsShell {
    /// Short display name for user-facing contexts (e.g. "bash", "pwsh").
    pub fn name(&self) -> &'static str {
        match self {
            Self::GitBash(_) => "bash",
            Self::Pwsh(_) => "pwsh",
            Self::PowerShell(_) => "powershell",
            Self::Cmd(_) => "cmd.exe",
        }
    }

    /// The program to spawn: the absolute path resolved at detection (a bare name only when none
    /// could be resolved).
    pub fn program(&self) -> &str {
        match self {
            Self::GitBash(path) | Self::Pwsh(path) | Self::PowerShell(path) | Self::Cmd(path) => path,
        }
    }

    /// Whether this shell supports the `&&` pipeline chain operator for error-propagating command chaining.
    /// True for pwsh (`&&` arrived in PS 7.0) and Git Bash; powershell.exe 5.1 has no `&&`.
    /// `cmd.exe` has `&&` but we use `;` there for uniformity with the `-Command` invocation style used elsewhere.
    pub fn supports_chain_operator(&self) -> bool {
        matches!(self, Self::Pwsh(_) | Self::GitBash(_))
    }

    /// Whether `grep`, `head`, `tail`, `sed`, `awk`, `find` are usable from this shell.
    /// True only for Git Bash, where MSYS2 bundles them inside the bash subprocess.
    pub fn has_unix_utilities(&self) -> bool {
        matches!(self, Self::GitBash(_))
    }

    /// How this shell interprets a bare `&` token.
    /// Drives the `run_terminal_cmd` background-operator validation, which must differ per shell.
    pub fn ampersand_semantics(&self) -> AmpersandSemantics {
        match self {
            Self::GitBash(_) => AmpersandSemantics::PosixBackground,
            Self::Pwsh(_) => AmpersandSemantics::PowerShellCore,
            Self::PowerShell(_) => AmpersandSemantics::WindowsPowerShell,
            Self::Cmd(_) => AmpersandSemantics::CmdSeparator,
        }
    }

    /// The shell's kind, without its details.
    pub fn family(&self) -> WindowsShellFamily {
        match self {
            Self::GitBash(_) => WindowsShellFamily::GitBash,
            Self::Pwsh(_) => WindowsShellFamily::Pwsh,
            Self::PowerShell(_) => WindowsShellFamily::PowerShell,
            Self::Cmd(_) => WindowsShellFamily::Cmd,
        }
    }
}

/// Returns the command chaining separator for the current platform and detected shell.
///
/// - Unix: always `"&&"` (bash/zsh).
/// - Windows with pwsh or Git Bash: `"&&"` (both support pipeline chain operators).
/// - Windows with powershell.exe (5.1) or cmd.exe: `";"`.
pub fn chain_separator() -> &'static str {
    #[cfg(unix)]
    {
        "&&"
    }
    #[cfg(not(unix))]
    {
        if detect_windows_shell().supports_chain_operator() {
            "&&"
        } else {
            ";"
        }
    }
}

/// Whether `grep`, `head`, `tail`, `sed`, `awk`, `find` are usable from the active shell.
/// True on Unix and on Windows with Git Bash; false on Windows with PowerShell or `cmd.exe`.
///
/// Tool descriptions branch on this to swap Unix-centric guidance for shell-aware guidance and avoid `'grep' is not recognized` failures.
pub fn has_unix_utilities() -> bool {
    #[cfg(unix)]
    {
        true
    }
    #[cfg(not(unix))]
    {
        detect_windows_shell().has_unix_utilities()
    }
}

/// Whether `name` resolves to an executable on the current `$PATH`.
///
/// The truncated-MCP steer uses this to name only tools present on the tool server's `$PATH`, with no "if available" hedge.
/// `which` handles the platform details (PATHEXT and App Execution Aliases on Windows).
/// Probes this process's environment (the tool server and the shell tool are co-located in production).
/// Per-session `export PATH` changes inside the persistent shell are not reflected (uncommon for `jq`/`python`/`sed`/`cut`).
pub fn is_command_available(name: &str) -> bool {
    which::which(name).is_ok()
}

/// How a shell interprets a bare `&` token.
/// Drives `run_terminal_cmd` background-operator detection and remediation, which must differ per shell.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AmpersandSemantics {
    /// Bash/POSIX: a bare `&` backgrounds the command (Unix shells, Git Bash).
    PosixBackground,
    /// PowerShell 7+ (`pwsh`): a *leading* `&` is the call/invocation operator; a *trailing* `&` starts a background job.
    PowerShellCore,
    /// Windows PowerShell 5.1 (`powershell.exe`): a *leading* `&` is the call operator; a *trailing* `&` is a parse error.
    WindowsPowerShell,
    /// `cmd.exe`: `&` is an unconditional sequential command separator.
    CmdSeparator,
}

/// How the active shell interprets a bare `&`.
/// Unix shells are always [`AmpersandSemantics::PosixBackground`]; on Windows it depends on the detected shell.
pub fn ampersand_semantics() -> AmpersandSemantics {
    #[cfg(unix)]
    {
        AmpersandSemantics::PosixBackground
    }
    #[cfg(not(unix))]
    {
        detect_windows_shell().ampersand_semantics()
    }
}

/// The Windows shell kinds, without their details: on every platform, so the per-shell lookup rule
/// below is tested on every host.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WindowsShellFamily {
    GitBash,
    Pwsh,
    PowerShell,
    Cmd,
}

impl WindowsShellFamily {
    /// u35 g11 (owner decision): whether the shell reads a command with bash's quoting, separators and
    /// redirects, which is what Fuigo's plain-text gate and read-only lists judge. Only Git Bash does;
    /// PowerShell and cmd.exe read the same text differently (cmd.exe does not treat single quotes as
    /// quotes, so `echo 'x & y'` runs `y`), so no command they run is approved without a grant.
    pub fn reads_bash_syntax(self) -> bool {
        matches!(self, Self::GitBash)
    }

    /// Short display name for user-facing text.
    pub fn name(self) -> &'static str {
        match self {
            Self::GitBash => "Git Bash",
            Self::Pwsh => "PowerShell (pwsh)",
            Self::PowerShell => "Windows PowerShell (powershell.exe)",
            Self::Cmd => "cmd.exe",
        }
    }
}

/// u35 g11: the Windows shell the command runner uses ([`shell_command_argv`]'s choice); `None` on
/// Unix, where commands run in bash or zsh.
pub fn runner_windows_shell_family() -> Option<WindowsShellFamily> {
    #[cfg(unix)]
    {
        None
    }
    #[cfg(not(unix))]
    {
        Some(detect_windows_shell().family())
    }
}

/// u35 g8 (Astra r7): with this variable set (any value: its existence is checked),
/// `NeedCurrentDirectoryForExePathW` returns FALSE, and cmd.exe, which calls it before its own
/// program search, searches `%PATH%` instead of `.;%PATH%` (Microsoft Learn,
/// NeedCurrentDirectoryForExePathW, Remarks).
pub const NO_CURRENT_DIRECTORY_EXE_SEARCH: (&str, &str) = ("NoDefaultCurrentDirectoryInExePath", "1");

/// u35 g8 (Astra r7): the variables that keep a Windows shell from running a program out of the
/// command's working directory (the repository) when the command names it bare (`rg`), so a
/// no-grant command runs the program the classifier judged. Only cmd.exe needs one: PowerShell
/// never runs a command from the current location without `.\` (about_Command_Precedence), and
/// Git Bash searches only `PATH`, which the classifier requires to be clean.
pub fn windows_shell_lookup_env(family: WindowsShellFamily) -> Vec<(&'static str, &'static str)> {
    match family {
        WindowsShellFamily::Cmd => vec![NO_CURRENT_DIRECTORY_EXE_SEARCH],
        WindowsShellFamily::GitBash | WindowsShellFamily::Pwsh | WindowsShellFamily::PowerShell => Vec::new(),
    }
}

/// How to invoke a command in the detected Windows shell.
#[cfg(not(unix))]
pub struct ShellInvocation {
    pub program: String,
    pub args: Vec<String>,
    /// Env vars that must be set on the child process, e.g. `MSYS_NO_PATHCONV` so Git Bash does not translate `/flags` to Windows paths.
    pub env: Vec<(&'static str, &'static str)>,
}

/// Build `(program, args, env)` for running `command` in the detected shell.
#[cfg(not(unix))]
pub fn shell_command_argv(command: &str) -> ShellInvocation {
    invocation_for(detect_windows_shell(), command)
}

/// Pure builder split out of `shell_command_argv` so tests can exercise every `WindowsShell` variant, not just the one installed on the test host.
#[cfg(not(unix))]
fn invocation_for(shell: &WindowsShell, command: &str) -> ShellInvocation {
    // Force UTF-8 for descendant tools
    // Windows' legacy ANSI codepage (cp1252) makes locale-sensitive children mis-decode UTF-8 subprocess output
    // Python's text-mode `subprocess`, for example, raised `UnicodeDecodeError` on `gh` output
    // `PYTHONUTF8=1` is the fix (forces `locale.getpreferredencoding` to utf-8)
    // `PYTHONIOENCODING` covers the interpreter's own stdio, with `surrogateescape` matching UTF-8 Mode's leniency
    // Applied before the per-request env, so an explicit caller value still overrides these defaults
    let utf8_env = [
        ("PYTHONUTF8", "1"),
        ("PYTHONIOENCODING", "utf-8:surrogateescape"),
    ];
    match shell {
        WindowsShell::GitBash(path) => ShellInvocation {
            program: path.clone(),
            args: vec!["-c".to_string(), command.to_string()],
            // Disable MSYS2 POSIX-to-Windows path translation so `/flag` arguments (MSBuild /t:, cl.exe /nologo, etc.) pass through
            env: vec![
                ("MSYS_NO_PATHCONV", "1"),
                ("MSYS2_ARG_CONV_EXCL", "*"),
                utf8_env[0],
                utf8_env[1],
            ],
        },
        WindowsShell::Pwsh(path) => ShellInvocation {
            program: path.clone(),
            args: vec![
                "-NoProfile".to_string(),
                "-NonInteractive".to_string(),
                "-Command".to_string(),
                command.to_string(),
            ],
            env: utf8_env.to_vec(),
        },
        WindowsShell::PowerShell(path) => ShellInvocation {
            program: path.clone(),
            args: vec![
                "-NoProfile".to_string(),
                "-NonInteractive".to_string(),
                "-Command".to_string(),
                command.to_string(),
            ],
            env: utf8_env.to_vec(),
        },
        WindowsShell::Cmd(path) => ShellInvocation {
            program: path.clone(),
            args: vec!["/C".to_string(), command.to_string()],
            env: utf8_env
                .into_iter()
                .chain(windows_shell_lookup_env(WindowsShellFamily::Cmd))
                .collect(),
        },
    }
}

// =============================================================================
// Unix shell resolution
// =============================================================================
//
// Locates an absolute path to a bash/zsh binary on Unix:
//
//   1. `$FUIGO_SHELL` override, if it names the requested kind and is runnable.
//   2. `$SHELL`, if it names the requested kind and is runnable.
//      Covers most NixOS / Homebrew / `nix-darwin` setups
//      There the user's login shell already lives at the resolved path (e.g. `/run/current-system/sw/bin/bash`, `/opt/homebrew/bin/bash`).
//   3. `which::which(name)` walks `$PATH`.
//      Catches NixOS profile shells in `/nix/store/...` or `/etc/profiles/per-user/<u>/bin/` when `/bin/bash` is absent
//   4. A fixed candidate list: `{/bin, /usr/bin, /usr/local/bin, /opt/homebrew/bin} × {bash,zsh}`.
//   5. Hardcoded `/bin/<name>`: historical behavior, only reached when every earlier step has failed.
//
// The result is cached per kind in a process-wide `OnceLock`, so the cascade is run at most once per shell kind per process

/// Bash and zsh are the only kinds supported by the persistent shell-state backend (the dump scripts are bash/zsh-specific).
/// Fish / dash / ksh users fall through to bash.
#[cfg(unix)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnixShellKind {
    Bash,
    Zsh,
}

#[cfg(unix)]
impl UnixShellKind {
    /// Binary file name (`"bash"` / `"zsh"`).
    pub fn name(self) -> &'static str {
        match self {
            Self::Bash => "bash",
            Self::Zsh => "zsh",
        }
    }

    /// Hardcoded historical default. Only used as the last-resort fallback.
    fn hardcoded_default(self) -> &'static str {
        match self {
            Self::Bash => "/bin/bash",
            Self::Zsh => "/bin/zsh",
        }
    }
}

/// Detect the user's preferred Unix shell kind from `$SHELL`.
/// Defaults to `Bash` when `$SHELL` is unset or unrecognized; cheap and not cached.
#[cfg(unix)]
pub fn detect_unix_shell_kind() -> UnixShellKind {
    match std::env::var("SHELL") {
        Ok(s) if s.contains("zsh") => UnixShellKind::Zsh,
        _ => UnixShellKind::Bash,
    }
}

/// Absolute path to the requested Unix shell binary, computed via the cascade above.
/// The result is cached for the process lifetime.
#[cfg(unix)]
pub fn unix_shell_path(kind: UnixShellKind) -> &'static str {
    use std::sync::OnceLock;
    static BASH: OnceLock<String> = OnceLock::new();
    static ZSH: OnceLock<String> = OnceLock::new();
    let cache = match kind {
        UnixShellKind::Bash => &BASH,
        UnixShellKind::Zsh => &ZSH,
    };
    cache.get_or_init(|| {
        let path = resolve_unix_shell_path(kind);
        tracing::debug!(kind = ?kind, resolved = %path, "resolved Unix shell path");
        path
    })
}

#[cfg(unix)]
fn resolve_unix_shell_path(kind: UnixShellKind) -> String {
    let name = kind.name();
    let matches_kind = |p: &std::path::Path| p.file_name().and_then(|n| n.to_str()) == Some(name);

    // 1) Explicit override via $FUIGO_SHELL.
    if let Ok(s) = std::env::var("FUIGO_SHELL") {
        let p = std::path::PathBuf::from(&s);
        if matches_kind(&p) && is_executable(&p) {
            return s;
        }
    }

    // 2) $SHELL, when it matches the requested kind.
    if let Ok(s) = std::env::var("SHELL") {
        let p = std::path::PathBuf::from(&s);
        if matches_kind(&p) && is_executable(&p) {
            return s;
        }
    }

    // 3) `which` walks $PATH (handles NixOS, Homebrew, custom profiles).
    if let Ok(p) = which::which(name)
        && is_executable(&p)
    {
        return p.to_string_lossy().into_owned();
    }

    // 4) Common install dirs.
    for dir in ["/bin", "/usr/bin", "/usr/local/bin", "/opt/homebrew/bin"] {
        let p = std::path::PathBuf::from(dir).join(name);
        if is_executable(&p) {
            return p.to_string_lossy().into_owned();
        }
    }

    // 5) Hardcoded fallback, same as historical behavior. Spawn will fail at runtime on a pure NixOS host with no bash.
    kind.hardcoded_default().to_string()
}

/// Whether `path` is an executable file.
///
/// First tries the file's mode bits (any-x); if that's inconclusive, falls back to invoking `<path> --version`.
/// The fallback exists for Nix: some overlay filesystems there expose binaries whose mode bits don't reflect their real executability.
#[cfg(unix)]
fn is_executable(path: &std::path::Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(meta) = std::fs::metadata(path)
        && meta.is_file()
        && meta.permissions().mode() & 0o111 != 0
    {
        return true;
    }

    // Nix fallback. Detach from the controlling TTY via fuigo_tty_utils so the probe cannot leak escapes onto the parent's terminal.
    // The resolver may run this during interactive TUI/pager startup; a misbehaving shell could otherwise spew garbage onto the pager screen
    // See `codegen-conventions` SKILL.md for the workspace-wide subprocess rule
    let mut cmd = std::process::Command::new(path);
    cmd.arg("--version")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    fuigo_tty_utils::detach_std_command(&mut cmd);
    cmd.status().map(|s| s.success()).unwrap_or(false)
}

#[cfg(test)]
mod tests {
    /// u35 g8 (Astra r7): cmd.exe runs with `NoDefaultCurrentDirectoryInExePath` set, so a bare
    /// program name is never taken from the working directory; the other shells need nothing.
    #[test]
    fn u35_cmd_does_not_search_the_working_directory_for_programs() {
        use super::{WindowsShellFamily, windows_shell_lookup_env};
        assert_eq!(
            windows_shell_lookup_env(WindowsShellFamily::Cmd),
            vec![("NoDefaultCurrentDirectoryInExePath", "1")]
        );
        for family in [
            WindowsShellFamily::GitBash,
            WindowsShellFamily::Pwsh,
            WindowsShellFamily::PowerShell,
        ] {
            assert!(windows_shell_lookup_env(family).is_empty(), "{family:?}");
        }
    }

    /// u35 g11 (owner decision): only Git Bash reads commands with bash syntax; Unix runs no Windows shell.
    #[test]
    fn u35_g11_only_git_bash_reads_bash_syntax() {
        use super::WindowsShellFamily as F;
        assert!(F::GitBash.reads_bash_syntax());
        for family in [F::Pwsh, F::PowerShell, F::Cmd] {
            assert!(!family.reads_bash_syntax(), "{family:?}");
        }
        #[cfg(unix)]
        assert_eq!(super::runner_windows_shell_family(), None);
    }

    /// The real Windows invocation of cmd.exe carries the lookup rule.
    #[cfg(not(unix))]
    #[test]
    fn u35_cmd_invocation_carries_the_lookup_rule() {
        let inv = super::invocation_for(&super::WindowsShell::Cmd("C:\\Windows\\System32\\cmd.exe".into()), "rg x");
        assert!(inv.env.contains(&("NoDefaultCurrentDirectoryInExePath", "1")), "{:?}", inv.env);
    }

    use super::*;

    #[cfg(not(unix))]
    const PWSH: &str = "C:\\Program Files\\PowerShell\\7\\pwsh.exe";
    #[cfg(not(unix))]
    const PS: &str = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
    #[cfg(not(unix))]
    const CMD: &str = "C:\\Windows\\System32\\cmd.exe";

    /// Every variant spawns the path detection stored, not a bare name re-resolved via `PATH`.
    #[cfg(not(unix))]
    #[test]
    fn invocation_for_spawns_the_stored_absolute_path() {
        for (shell, path) in [
            (WindowsShell::GitBash("C:\\Program Files\\Git\\bin\\bash.exe".into()), "C:\\Program Files\\Git\\bin\\bash.exe"),
            (WindowsShell::Pwsh(PWSH.into()), PWSH),
            (WindowsShell::PowerShell(PS.into()), PS),
            (WindowsShell::Cmd(CMD.into()), CMD),
        ] {
            assert_eq!(shell.program(), path);
            assert_eq!(invocation_for(&shell, "echo hi").program, path);
        }
        assert_eq!(WindowsShell::Pwsh(PWSH.into()).name(), "pwsh");
        assert_eq!(WindowsShell::Cmd(CMD.into()).name(), "cmd.exe");
    }

    /// `pwsh.exe` is found through the `PATH` directories only: an entry naming the current
    /// directory (in any spelling), an empty, relative or UNC entry is skipped, so a `pwsh.exe`
    /// planted in the repository Fuigo runs in is never stored. `where.exe` searched cwd first.
    /// The system and Windows directories come from the OS and exist; detection's
    /// `powershell.exe` / `cmd.exe` live in them, never under a `%SystemRoot%` a parent chose.
    #[cfg(windows)]
    #[test]
    fn system_directories_come_from_the_os() {
        let system = system_directory();
        let windows = windows_directory();
        assert!(std::path::Path::new(&system).is_dir(), "{system}");
        assert!(is_inside(&system, &windows), "{system} not in {windows}");
        assert!(windows_file_name(&system).eq_ignore_ascii_case("System32"), "{system}");
        let WindowsShell::Cmd(cmd) = detect_cmd() else { unreachable!() };
        assert!(is_inside(&cmd, &system), "{cmd}");
    }

    #[test]
    fn pwsh_from_path_never_takes_the_current_directory() {
        let pwsh = "C:\\Program Files\\PowerShell\\7\\pwsh.exe";
        let everywhere = |_: &str| true;
        let path = "C:\\repo;;.;bin;\\\\srv\\share;C:relative;C:\\Program Files\\PowerShell\\7\\";
        assert_eq!(pwsh_from_path(path, Some("C:\\repo"), everywhere).as_deref(), Some(pwsh));
        // The cwd entry in another spelling: case, `/`, a trailing `\.`, a `..` detour.
        for cwd_entry in ["c:\\REPO", "C:/repo/", "C:\\repo\\.", "C:\\other\\..\\repo"] {
            let path = format!("{cwd_entry};C:\\Program Files\\PowerShell\\7");
            assert_eq!(pwsh_from_path(&path, Some("C:\\Repo"), everywhere).as_deref(), Some(pwsh), "{cwd_entry}");
        }
        // Nothing but cwd and relative entries: no pwsh (detection moves on to powershell.exe).
        assert_eq!(pwsh_from_path("C:\\repo;.;tools", Some("C:\\repo"), everywhere), None);
        // A directory only counts when the file exists in it.
        let only_7 = |p: &str| p == pwsh;
        assert_eq!(
            pwsh_from_path("C:\\a;C:\\Program Files\\PowerShell\\7", None, only_7).as_deref(),
            Some(pwsh)
        );
        // A quoted entry may hold `;`.
        assert_eq!(
            pwsh_from_path("\"C:\\odd;dir\";C:\\x", None, |p: &str| p == "C:\\odd;dir\\pwsh.exe").as_deref(),
            Some("C:\\odd;dir\\pwsh.exe")
        );
        assert_eq!(pwsh_from_path("", None, everywhere), None);
    }

    /// Git Bash: install locations first (absolute drive paths only), then the first GIT `bash.exe`
    /// on `PATH`, never cwd's and never WSL's `System32\bash.exe`.
    #[test]
    fn git_bash_path_skips_cwd_wsl_and_relative_roots() {
        let everywhere = |_: &str| true;
        let path = "C:\\repo\\git;C:\\Windows\\System32;D:\\PortableGit\\bin";
        assert_eq!(
            git_bash_path(&[None, Some("relative\\Git\\bin".into())], path, Some("C:\\repo\\git"), everywhere).as_deref(),
            Some("D:\\PortableGit\\bin\\bash.exe")
        );
        assert_eq!(
            git_bash_path(&[Some("C:\\Program Files\\Git\\bin".into())], path, None, everywhere).as_deref(),
            Some("C:\\Program Files\\Git\\bin\\bash.exe")
        );
        assert_eq!(git_bash_path(&[Some("\\\\srv\\Git\\bin".into())], "C:\\Windows\\System32", None, everywhere), None);
        assert!(is_git_bash("C:\\Users\\me\\scoop\\apps\\git\\current\\bin\\bash.exe"));
        assert!(!is_git_bash("C:\\Windows\\System32\\bash.exe"));
        assert!(!is_git_bash("C:\\Git\\bin\\notbash.exe"));
        // A directory that only contains the letters is not Git (u35-winenv r2, Grok/Fable Low).
        assert!(!is_git_bash("C:\\Users\\me\\digital\\bin\\bash.exe"));
        assert!(!is_git_bash("C:\\Users\\me\\GitHub\\tools\\bash.exe"));
        assert!(is_git_bash("C:\\Program Files\\Git\\usr\\bin\\bash.exe"));
        assert!(is_git_bash("D:\\PortableGit\\bin\\bash.exe"));
        assert!(is_git_bash("C:\\git-sdk-64\\usr\\bin\\bash.exe"));
    }

    #[test]
    fn powershell_path_is_under_the_system_directory() {
        assert_eq!(
            powershell_path("D:\\WINDOWS\\system32\\", |_| true).as_deref(),
            Some("D:\\WINDOWS\\system32\\WindowsPowerShell\\v1.0\\powershell.exe")
        );
        assert_eq!(powershell_path("C:\\Windows\\System32", |_| false), None);
    }

    /// `cmd.exe` from the system directory; `ComSpec` only as an existing `cmd.exe` (by its final
    /// component) inside the real Windows directory; else the bare name.
    #[test]
    fn cmd_path_prefers_system_dir_then_comspec_inside_windows_dir() {
        let sys = "C:\\Windows\\System32";
        let win = "C:\\Windows";
        let all = |_: &str| true;
        assert_eq!(cmd_path(sys, win, Some("C:\\Windows\\SysWOW64\\cmd.exe"), all), "C:\\Windows\\System32\\cmd.exe");
        let no_system = |p: &str| p != "C:\\Windows\\System32\\cmd.exe";
        assert_eq!(
            cmd_path(sys, win, Some("C:\\Windows\\SysWOW64\\cmd.exe"), no_system),
            "C:\\Windows\\SysWOW64\\cmd.exe"
        );
        // Rejected ComSpecs: a bare name, outside the Windows directory, a look-alike file name,
        // a sibling directory that only shares the prefix, a UNC path.
        for comspec in [
            "cmd.exe",
            "D:\\repo\\cmd.exe",
            "C:\\Windows\\System32\\notcmd.exe",
            "C:\\WindowsX\\cmd.exe",
            "\\\\srv\\Windows\\cmd.exe",
        ] {
            assert_eq!(cmd_path(sys, win, Some(comspec), no_system), "cmd", "{comspec}");
        }
        assert_eq!(cmd_path(sys, win, None, |_| false), "cmd");
    }

    #[test]
    fn is_command_available_detects_present_and_absent() {
        // `cmd` resolves via PATHEXT on Windows, `sh` lives on $PATH on Unix
        #[cfg(windows)]
        let present = "cmd";
        #[cfg(not(windows))]
        let present = "sh";
        assert!(is_command_available(present));
        assert!(!is_command_available(
            "fuigo-definitely-not-a-real-command-xyz"
        ));
    }

    #[cfg(unix)]
    #[test]
    fn unix_shell_path_returns_a_bash() {
        // The resolver guarantees the result's file_name matches the requested kind, even for the hardcoded `/bin/bash` fallback
        let p = unix_shell_path(UnixShellKind::Bash);
        assert!(
            std::path::Path::new(p).file_name().and_then(|n| n.to_str()) == Some("bash"),
            "expected a path ending in 'bash', got {p}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn is_executable_recognizes_bin_sh() {
        // /bin/sh is the one path POSIX promises across every Unix variant we care about; on macOS and Linux distros it's always executable
        // (Pure NixOS images may lack it, in which case this test is skipped.)
        if !std::path::Path::new("/bin/sh").exists() {
            return;
        }
        assert!(is_executable(std::path::Path::new("/bin/sh")));
    }

    #[cfg(unix)]
    #[test]
    fn is_executable_rejects_non_executable() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(!is_executable(tmp.path()));
    }

    /// Only Git Bash bundles the Unix utilities; the PowerShell and cmd variants do not.
    #[cfg(not(unix))]
    #[test]
    fn has_unix_utilities_only_true_for_gitbash() {
        assert!(
            WindowsShell::GitBash("C:\\Program Files\\Git\\bin\\bash.exe".into())
                .has_unix_utilities()
        );
        assert!(!WindowsShell::Pwsh(PWSH.into()).has_unix_utilities());
        assert!(!WindowsShell::PowerShell(PS.into()).has_unix_utilities());
        assert!(!WindowsShell::Cmd(CMD.into()).has_unix_utilities());
    }

    /// Git Bash backgrounds with a bare `&`; PowerShell uses `&` as the call operator; `cmd.exe` uses it as a sequential separator.
    #[cfg(not(unix))]
    #[test]
    fn ampersand_semantics_per_windows_shell() {
        assert_eq!(
            WindowsShell::GitBash("C:\\Program Files\\Git\\bin\\bash.exe".into())
                .ampersand_semantics(),
            AmpersandSemantics::PosixBackground
        );
        assert_eq!(
            WindowsShell::Pwsh(PWSH.into()).ampersand_semantics(),
            AmpersandSemantics::PowerShellCore
        );
        assert_eq!(
            WindowsShell::PowerShell(PS.into()).ampersand_semantics(),
            AmpersandSemantics::WindowsPowerShell
        );
        assert_eq!(
            WindowsShell::Cmd(CMD.into()).ampersand_semantics(),
            AmpersandSemantics::CmdSeparator
        );
    }

    /// Every Windows shell variant injects the UTF-8 env defaults.
    /// Builds all four variants directly so it doesn't depend on the test host's shell.
    #[cfg(not(unix))]
    #[test]
    fn invocation_for_sets_utf8_env_on_every_variant() {
        let variants = [
            WindowsShell::GitBash("C:\\Program Files\\Git\\bin\\bash.exe".into()),
            WindowsShell::Pwsh(PWSH.into()),
            WindowsShell::PowerShell(PS.into()),
            WindowsShell::Cmd(CMD.into()),
        ];
        for shell in &variants {
            let inv = invocation_for(shell, "echo hi");
            assert!(
                inv.env.contains(&("PYTHONUTF8", "1")),
                "expected PYTHONUTF8=1 in env for {shell:?}, got {:?}",
                inv.env
            );
            assert!(
                inv.env
                    .contains(&("PYTHONIOENCODING", "utf-8:surrogateescape")),
                "expected PYTHONIOENCODING=utf-8:surrogateescape in env for {shell:?}, got {:?}",
                inv.env
            );
        }
    }

    /// GitBash keeps its MSYS2 path-translation guards in addition to the UTF-8 defaults (the UTF-8 entries are appended, not replacing).
    #[cfg(not(unix))]
    #[test]
    fn invocation_for_gitbash_keeps_msys_vars() {
        let inv = invocation_for(
            &WindowsShell::GitBash("C:\\Program Files\\Git\\bin\\bash.exe".into()),
            "echo hi",
        );
        assert!(
            inv.env.contains(&("MSYS_NO_PATHCONV", "1")),
            "{:?}",
            inv.env
        );
        assert!(
            inv.env.contains(&("MSYS2_ARG_CONV_EXCL", "*")),
            "{:?}",
            inv.env
        );
    }
}
