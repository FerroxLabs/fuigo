use super::*;

/// Writes of a program the generic word classifier does not see (P166 Grok r4 HIGH 3, r5 HIGH 1 and sweep): archive,
/// sync, in-place, patch, copy-over-ssh, download, split, decompress and `sed w` writers. `paths` are the places
/// written (an extraction directory, an archive file, a destination, a file edited in place, a downloaded file);
/// `generated` are name prefixes the program appends a suffix to (`split`); `unpinned` means some write may land where
/// the command line does not say (archive members, absolute or `..` member names, names the diff or the server picks),
/// which fails closed to the protected prompt. Archive members are not inspected (receipt R166, rounds 4 and 5).
#[derive(Debug, Default, PartialEq)]
pub(crate) struct ToolWrites {
    pub(crate) paths: Vec<String>,
    pub(crate) generated: Vec<String>,
    pub(crate) unpinned: bool,
}

/// [`ToolWrites`] for `tar`, `unzip`, `rsync`, `ditto`, `cpio`, `7z`, `pax`, `perl -i`, `ruby -i`, `patch`, `scp`,
/// `curl`, `wget`, `split`, `csplit`, the gzip/bzip2/xz/zstd/lz4 family and `sed`; `None` for any other program. An
/// extraction with no destination flag writes into the cwd (`.`).
pub(crate) fn tool_writes(program: &str, inner: &[String]) -> Option<ToolWrites> {
    let args = inner.get(1..).unwrap_or_default();
    let family = |name: &str| {
        program
            .strip_prefix(name)
            .is_some_and(|rest| rest.chars().all(|c| c.is_ascii_digit() || c == '.'))
    };
    Some(match program {
        "tar" | "gtar" | "bsdtar" => tar_writes(args),
        "unzip" => unzip_writes(args),
        "rsync" => {
            let (operands, _) = rsync_operands(inner);
            let mut writes = ToolWrites::default();
            // P166 r13: a host destination writes a remote tree; its path is judged by the destination-writes floor.
            if let [_, .., dest] = operands.as_slice()
                && !is_host_operand(dest)
            {
                writes.paths.push(operand_local_path(dest));
            }
            // P166 r7: the log and batch files rsync writes besides the destination.
            for (i, word) in inner.iter().enumerate().skip(1) {
                for flag in ["--log-file", "--write-batch", "--only-write-batch"] {
                    if word == flag {
                        writes.paths.extend(inner.get(i + 1).cloned());
                    } else if let Some(value) = word.strip_prefix(&format!("{flag}=")) {
                        writes.paths.push(value.to_owned());
                    }
                }
            }
            writes
        }
        "ditto" => ToolWrites {
            paths: match ditto_operands(inner).as_slice() {
                [_, .., dest] => vec![(*dest).to_owned()],
                _ => Vec::new(),
            },
            generated: Vec::new(),
            // Grok r5 MEDIUM 2: `ditto -x` extracts an archive whose members are not inspected.
            unpinned: ditto_extracts(inner),
        },
        "cpio" => cpio_writes(args),
        "7z" | "7za" | "7zz" | "7zr" => seven_zip_writes(args),
        "pax" => pax_writes(inner),
        // P166 r6 sweep: `ar rcs ARCHIVE FILE…` writes the archive (second word); `ar x` extracts members (not
        // inspected, like `tar -x`).
        "ar" => {
            let mode = inner
                .get(1)
                .map(|word| word.trim_start_matches('-'))
                .unwrap_or_default();
            // With a dashed mode word (`ar -r ARCHIVE`) the mode is not a file candidate, so the archive is the first.
            let skip = usize::from(!inner.get(1).is_some_and(|word| word.starts_with('-')));
            let archive = shell_file_candidates(inner)
                .into_iter()
                .nth(skip)
                .map(str::to_owned);
            ToolWrites {
                paths: if mode
                    .chars()
                    .any(|c| matches!(c, 'r' | 'q' | 'd' | 's' | 'm'))
                {
                    archive.into_iter().collect()
                } else {
                    Vec::new()
                },
                generated: Vec::new(),
                unpinned: mode.contains('x'),
            }
        }
        "patch" => patch_writes(args),
        "scp" => scp_writes(inner),
        "curl" => curl_writes(args),
        "wget" => wget_writes(args),
        "split" | "csplit" => split_writes(program, args),
        "sed" | "gsed" => sed_writes(inner),
        // `yq -i EXPR FILE…` rewrites each file in place (the first operand is the expression).
        "yq" => ToolWrites {
            paths: if inner.iter().skip(1).any(|word| {
                matches!(word.as_str(), "-i" | "--inplace") || word.starts_with("--inplace=")
            }) {
                shell_file_candidates(inner)
                    .into_iter()
                    .skip(1)
                    .map(str::to_owned)
                    .collect()
            } else {
                Vec::new()
            },
            ..ToolWrites::default()
        },
        _ if family("perl") => in_place_writes(args, &PERL_OPTIONS),
        _ if family("ruby") => in_place_writes(args, &RUBY_OPTIONS),
        _ => return decompress_writes(program, args),
    })
}

/// Peeled launch wrappers of a command, for the write classifiers (P166 Grok r5 sweep).
pub(super) struct WritePeel<'a> {
    /// The command that actually runs.
    pub(super) words: &'a [String],
    /// A wrapper moved the cwd or root (`env -C`, `sudo -D`/`-i`/`-R`, `chroot`): relative targets cannot be pinned.
    pub(super) moved: bool,
    /// The inner command is hidden (`env -S`, unreadable wrapper options, `flock -c`, `sudoedit`): fails closed.
    pub(super) opaque: bool,
    /// A wrapper's own output file (`time -o FILE`).
    pub(super) writes: Vec<&'a str>,
}

/// Peel the canonical wrappers and transparent prefixes (`env`, `timeout`, `nice`, `ionice`, `chrt`, `stdbuf`,
/// `command`, `exec`, `builtin`) and the launchers `sudo`, `doas`, `nohup`, `setsid`, `time`, `caffeinate`, `flock`,
/// `watch` and `chroot`, so `sudo cp evil .mcp.json` is judged as the `cp` it runs.
pub(super) fn peel_write_command(words: &[String]) -> WritePeel<'_> {
    let mut peel = WritePeel {
        words,
        moved: false,
        opaque: false,
        writes: Vec::new(),
    };
    for _ in 0..MAX_WRAPPER_DEPTH {
        let normalized = normalize_command_words(peel.words);
        peel.moved |= normalized.has_chdir;
        peel.opaque |= normalized.has_split_string
            || normalized.env_options_uncertain
            || normalized.exhausted
            || normalized.ambiguous;
        peel.words = normalized.words;
        if peel.opaque {
            return peel;
        }
        match strip_launch_wrapper(peel.words) {
            LaunchStrip::NotWrapper => return peel,
            LaunchStrip::Opaque => {
                peel.opaque = true;
                return peel;
            }
            LaunchStrip::Inner {
                inner,
                moved,
                writes,
            } => {
                peel.words = inner;
                peel.moved |= moved;
                peel.writes.extend(writes);
            }
        }
    }
    peel.opaque = true;
    peel
}

/// u35 r1: one segment's argv after the single bounded classifier normalisation ([`normalize_for_classification`]).
pub(crate) struct ClassifiedArgv<'a> {
    /// The command that actually runs (a tail of the input words).
    pub(crate) words: &'a [String],
    /// The program could not be pinned: an unmodelled wrapper option, `env -S`, a hidden command (`flock -c`,
    /// `sudo -e`), or the peel budget ran out. Callers floor the segment.
    pub(crate) fail_closed: bool,
    /// A launcher (`time`, `nohup`, `sudo`, ...) was peeled: the inner command runs under it, so no read-only list or
    /// routine approval rides through it.
    pub(crate) launched: bool,
    /// A peeled launcher is itself an exec vehicle (`nohup`, `sudo`, `watch`, ...): the segment keeps that floor.
    pub(crate) vehicle: bool,
    /// u35 g14: a wrapper moved the working directory or root (`env -C`, `sudo -D`, `chroot`), so the directory the
    /// command runs in is not the segment's.
    pub(crate) moved: bool,
}

/// u35 r1: the ONE bounded normalisation every classifier check runs on. It peels the canonical wrappers (`env`
/// with assignments, `timeout`, `nice`, `ionice`, `chrt`, `stdbuf`), the transparent prefixes (`command`, `builtin`,
/// `exec`; `command -v`/`-V` stay lookups) and the launchers (`time`, `nohup`, `setsid`, `caffeinate`, `sudo`, `doas`,
/// `flock`, `watch`, `chroot`) in any order, up to a fixed budget.
pub(crate) fn normalize_for_classification(words: &[String]) -> ClassifiedArgv<'_> {
    let mut out = ClassifiedArgv {
        words,
        fail_closed: false,
        launched: false,
        vehicle: false,
        moved: false,
    };
    for _ in 0..=MAX_WRAPPER_DEPTH {
        let normalized = normalize_command_words(out.words);
        out.words = normalized.words;
        out.moved |= normalized.has_chdir;
        if normalized.exhausted
            || normalized.ambiguous
            || normalized.has_split_string
            || normalized.env_options_uncertain
        {
            out.fail_closed = true;
            return out;
        }
        let vehicle = out
            .words
            .first()
            .is_some_and(|head| crate::permission::exec_surface::is_exec_vehicle(head));
        match strip_launch_wrapper(out.words) {
            LaunchStrip::NotWrapper => return out,
            LaunchStrip::Opaque => {
                out.fail_closed = true;
                out.vehicle |= vehicle;
                return out;
            }
            LaunchStrip::Inner { inner, moved, .. } => {
                out.words = inner;
                out.moved |= moved;
                out.launched = true;
                out.vehicle |= vehicle;
            }
        }
    }
    out.fail_closed = true;
    out
}

pub(super) enum LaunchStrip<'a> {
    NotWrapper,
    Opaque,
    Inner {
        inner: &'a [String],
        moved: bool,
        writes: Vec<&'a str>,
    },
}

/// Option grammar of one launcher, for [`strip_launch_wrapper`].
pub(super) struct LauncherOptions {
    /// Short options that take a value (the rest of the cluster, else the next word).
    pub(super) short_value: &'static str,
    pub(super) long_value: &'static [&'static str],
    /// Options that move the cwd or root.
    pub(super) short_moving: &'static str,
    pub(super) long_moving: &'static [&'static str],
    /// Options that hide the command (a shell string, an editor).
    pub(super) short_opaque: &'static str,
    pub(super) long_opaque: &'static [&'static str],
    /// Options whose value is a file the launcher itself writes.
    pub(super) short_write: &'static str,
    pub(super) long_write: &'static [&'static str],
}

pub(super) const NO_LAUNCHER_OPTIONS: LauncherOptions = LauncherOptions {
    short_value: "",
    long_value: &[],
    short_moving: "",
    long_moving: &[],
    short_opaque: "",
    long_opaque: &[],
    short_write: "",
    long_write: &[],
};

/// Strip one privilege/session launcher and its options.
pub(super) fn strip_launch_wrapper(words: &[String]) -> LaunchStrip<'_> {
    let Some(head) = words.first() else {
        return LaunchStrip::NotWrapper;
    };
    let options = match shell_program_name(head).to_ascii_lowercase().as_str() {
        "sudo" => LauncherOptions {
            short_value: "CDghpRrTtUu",
            long_value: &[
                "close-from",
                "chdir",
                "group",
                "host",
                "prompt",
                "chroot",
                "role",
                "type",
                "command-timeout",
                "other-user",
                "user",
            ],
            short_moving: "DiR",
            long_moving: &["chdir", "login", "chroot"],
            short_opaque: "e",
            long_opaque: &["edit"],
            ..NO_LAUNCHER_OPTIONS
        },
        "doas" => LauncherOptions {
            short_value: "uC",
            ..NO_LAUNCHER_OPTIONS
        },
        "nohup" | "setsid" => NO_LAUNCHER_OPTIONS,
        "caffeinate" => LauncherOptions {
            short_value: "tw",
            ..NO_LAUNCHER_OPTIONS
        },
        "time" => LauncherOptions {
            short_value: "fo",
            long_value: &["format", "output"],
            short_write: "o",
            long_write: &["output"],
            ..NO_LAUNCHER_OPTIONS
        },
        "watch" => LauncherOptions {
            short_value: "nq",
            long_value: &["interval", "equexit"],
            ..NO_LAUNCHER_OPTIONS
        },
        "flock" => LauncherOptions {
            short_value: "wEc",
            long_value: &["wait", "timeout", "conflict-exit-code", "command"],
            short_opaque: "c",
            long_opaque: &["command"],
            ..NO_LAUNCHER_OPTIONS
        },
        "chroot" => LauncherOptions {
            long_value: &["userspec", "groups"],
            ..NO_LAUNCHER_OPTIONS
        },
        _ => return LaunchStrip::NotWrapper,
    };
    let program = shell_program_name(head).to_ascii_lowercase();
    let (mut moved, mut writes, mut i) = (program == "chroot", Vec::new(), 1);
    while let Some(word) = words.get(i) {
        if word == "--" {
            i += 1;
            break;
        }
        if word == "-" || !word.starts_with('-') {
            break;
        }
        i += 1;
        if let Some(long) = word.strip_prefix("--") {
            let (name, glued) = match long.split_once('=') {
                Some((name, value)) => (name, Some(value)),
                None => (long, None),
            };
            let value = match glued {
                Some(value) => Some(value),
                None if options.long_value.contains(&name) => {
                    i += 1;
                    words.get(i - 1).map(String::as_str)
                }
                None => None,
            };
            if options.long_opaque.contains(&name) {
                return LaunchStrip::Opaque;
            }
            moved |= options.long_moving.contains(&name);
            if options.long_write.contains(&name) {
                writes.extend(value);
            }
            continue;
        }
        let cluster = &word[1..];
        for (at, option) in cluster.char_indices() {
            if options.short_opaque.contains(option) {
                return LaunchStrip::Opaque;
            }
            moved |= options.short_moving.contains(option);
            if options.short_value.contains(option) {
                let value = short_option_value(cluster, at, words, &mut i);
                if options.short_write.contains(option) {
                    writes.extend(value);
                }
                break;
            }
        }
    }
    // `sudo NAME=VALUE cmd`; `flock FILE cmd`; `chroot DIR cmd`.
    if program == "sudo" {
        while words.get(i).is_some_and(|word| {
            word.split_once('=')
                .is_some_and(|(name, _)| !name.is_empty() && !name.contains('/'))
        }) {
            i += 1;
        }
    }
    if matches!(program.as_str(), "flock" | "chroot") {
        i += 1;
    }
    match words.get(i..) {
        Some(inner) if !inner.is_empty() => LaunchStrip::Inner {
            inner,
            moved,
            writes,
        },
        // `sudo -l`, `sudo -v`: no command.
        _ => LaunchStrip::NotWrapper,
    }
}

/// The value of a short option at `cluster[at]`: the rest of the cluster, else the next word (`i` is advanced past it).
pub(super) fn short_option_value<'a>(
    cluster: &'a str,
    at: usize,
    args: &'a [String],
    i: &mut usize,
) -> Option<&'a str> {
    let rest = &cluster[crate::permission::shell_words::after_char(cluster, at)..];
    if rest.is_empty() {
        let value = args.get(*i).map(String::as_str);
        *i += 1;
        value
    } else {
        Some(rest)
    }
}

/// `tar`: extract (`x`, `--extract`, `--get`) writes into each `-C`/`--directory` (else `.`); create/append/update
/// (`c`, `r`, `u`, `A`, `--delete`) write the `-f`/`--file` archive (and `-g` snapshot); list/diff (`t`, `d`) write
/// nothing. An extraction's members are not inspected, so it is unpinned (Grok r5 MEDIUM 2; `-P` would also let them
/// land anywhere). A mode that cannot be told fails closed to `.`.
/// The old bundled form (`tar xzf a.tar`) takes option values from the following words.
pub(super) fn tar_writes(args: &[String]) -> ToolWrites {
    // Short options taking a value in both GNU tar and bsdtar (`-L`, `-H`, `-s` differ between them and are read as
    // flags: a value misread as an operand is ignored, while a flag misread as taking a value could hide `-f`).
    const TAKES_VALUE: &str = "bCfFgIKNTVX";
    #[derive(Default)]
    struct Tar<'a> {
        extract: bool,
        archive_write: bool,
        list: bool,
        file: Option<&'a str>,
        dirs: Vec<&'a str>,
        snapshot: Option<&'a str>,
        other: bool,
    }
    impl<'a> Tar<'a> {
        fn short(&mut self, option: char, value: Option<&'a str>) {
            match option {
                'x' => self.extract = true,
                'c' | 'r' | 'u' | 'A' => self.archive_write = true,
                't' | 'd' => self.list = true,
                'f' => self.file = value,
                'C' => self.dirs.extend(value),
                'g' => self.snapshot = value,
                _ => {}
            }
        }
        fn long(&mut self, name: &str, value: Option<&'a str>) {
            match name {
                "extract" | "get" => self.extract = true,
                "create" | "append" | "update" | "catenate" | "concatenate" | "delete" => {
                    self.archive_write = true
                }
                "list" | "diff" | "compare" => self.list = true,
                "file" => self.file = value,
                "directory" => self.dirs.extend(value),
                "listed-incremental" => self.snapshot = value,
                "help" | "usage" | "version" | "show-defaults" => {}
                _ => self.other = true,
            }
        }
    }
    let mut tar = Tar::default();
    let mut i = 0;
    if let Some(bundle) = args.first().filter(|word| !word.starts_with('-')) {
        i = 1;
        for option in bundle.chars() {
            let value = TAKES_VALUE.contains(option).then(|| {
                i += 1;
                args.get(i - 1).map(String::as_str)
            });
            tar.short(option, value.flatten());
        }
    }
    while i < args.len() {
        let word = &args[i];
        i += 1;
        if word == "--" {
            break;
        }
        if word == "-" || !word.starts_with('-') {
            continue;
        }
        if let Some(long) = word.strip_prefix("--") {
            let (name, value) = match long.split_once('=') {
                Some((name, value)) => (name, Some(value)),
                None if matches!(long, "file" | "directory" | "listed-incremental") => {
                    i += 1;
                    (long, args.get(i - 1).map(String::as_str))
                }
                None => (long, None),
            };
            tar.long(name, value);
            continue;
        }
        let cluster = &word[1..];
        for (at, option) in cluster.char_indices() {
            if TAKES_VALUE.contains(option) {
                let value = short_option_value(cluster, at, args, &mut i);
                tar.short(option, value);
                break;
            }
            tar.short(option, None);
        }
    }
    let mut writes = ToolWrites::default();
    writes.paths.extend(tar.snapshot.map(str::to_owned));
    if tar.archive_write {
        writes
            .paths
            .extend(tar.file.filter(|file| *file != "-").map(str::to_owned));
    }
    // Extraction, or a mode that cannot be told (other than help/version), writes into the target directories.
    let unknown_mode =
        !tar.extract && !tar.archive_write && !tar.list && (tar.other || tar.file.is_some());
    if tar.extract || unknown_mode {
        if tar.dirs.is_empty() {
            writes.paths.push(".".to_owned());
        } else {
            writes
                .paths
                .extend(tar.dirs.iter().map(|dir| (*dir).to_owned()));
        }
        writes.unpinned = true;
    }
    writes
}

/// `unzip`: extracts into `-d DIR` (else `.`); list/test/pipe/comment/zipinfo modes (`-l`, `-t`, `-p`, `-v`, `-z`,
/// `-Z`) write nothing. An extraction's members are not inspected (and `-:` keeps `../` names), so it is unpinned.
pub(super) fn unzip_writes(args: &[String]) -> ToolWrites {
    let mut dirs = Vec::new();
    let (mut no_write, mut i) = (false, 0);
    while i < args.len() {
        let word = &args[i];
        i += 1;
        let Some(cluster) = word.strip_prefix('-').filter(|cluster| !cluster.is_empty()) else {
            continue;
        };
        for (at, option) in cluster.char_indices() {
            match option {
                'd' => {
                    dirs.extend(short_option_value(cluster, at, args, &mut i));
                    break;
                }
                'l' | 't' | 'p' | 'v' | 'z' | 'Z' => no_write = true,
                _ => {}
            }
        }
    }
    if no_write {
        return ToolWrites::default();
    }
    if dirs.is_empty() {
        dirs.push(".");
    }
    ToolWrites {
        paths: dirs.into_iter().map(str::to_owned).collect(),
        generated: Vec::new(),
        unpinned: true,
    }
}

/// `cpio`: copy-in (`-i`, `--extract`) writes into `-D DIR` (else `.`); pass-through (`-p`) writes into its directory
/// operand; copy-out (`-o`) writes the `-O`/`-F` archive. Copy-in members and pass-through names (read from stdin) are
/// not inspected, so both are unpinned (Grok r5 MEDIUM 2; GNU also honours absolute member names by default).
pub(super) fn cpio_writes(args: &[String]) -> ToolWrites {
    const TAKES_VALUE: &str = "CDEFHIMOR";
    let (mut copy_in, mut pass, mut copy_out) = (false, false, false);
    let (mut dirs, mut archives, mut operands) = (Vec::new(), Vec::new(), Vec::new());
    let mut i = 0;
    while i < args.len() {
        let word = &args[i];
        i += 1;
        if let Some(long) = word.strip_prefix("--") {
            let (name, value) = match long.split_once('=') {
                Some((name, value)) => (name, Some(value)),
                None if matches!(long, "directory" | "file") => {
                    i += 1;
                    (long, args.get(i - 1).map(String::as_str))
                }
                None => (long, None),
            };
            match name {
                "extract" => copy_in = true,
                "pass-through" => pass = true,
                "create" => copy_out = true,
                "directory" => dirs.extend(value),
                "file" => archives.extend(value),
                _ => {}
            }
            continue;
        }
        let Some(cluster) = word.strip_prefix('-').filter(|cluster| !cluster.is_empty()) else {
            operands.push(word.as_str());
            continue;
        };
        for (at, option) in cluster.char_indices() {
            match option {
                'i' => copy_in = true,
                'p' => pass = true,
                'o' => copy_out = true,
                _ if TAKES_VALUE.contains(option) => {
                    let value = short_option_value(cluster, at, args, &mut i);
                    match option {
                        'D' => dirs.extend(value),
                        'F' | 'O' => archives.extend(value),
                        _ => {}
                    }
                    break;
                }
                _ => {}
            }
        }
    }
    let mut writes = ToolWrites::default();
    if copy_in {
        if dirs.is_empty() {
            dirs.push(".");
        }
        writes
            .paths
            .extend(dirs.iter().map(|dir| (*dir).to_owned()));
        writes.unpinned = true;
    }
    if pass {
        writes
            .paths
            .extend(operands.last().map(|dir| (*dir).to_owned()));
        writes.unpinned = true;
    }
    if copy_out {
        writes
            .paths
            .extend(archives.iter().map(|file| (*file).to_owned()));
    }
    writes
}

/// `7z`: `x`/`e` extract into `-oDIR` (else `.`), unpinned because members are not inspected (and `-spf` keeps
/// absolute paths); `a`/`u`/`d`/`rn` write the archive (the first operand after the command); other commands (`l`,
/// `t`, `h`, `i`, `b`) write nothing.
pub(super) fn seven_zip_writes(args: &[String]) -> ToolWrites {
    let operands: Vec<&str> = args
        .iter()
        .filter(|word| !word.starts_with('-'))
        .map(String::as_str)
        .collect();
    let switches = || args.iter().filter_map(|word| word.strip_prefix('-'));
    let mut writes = ToolWrites::default();
    match operands
        .first()
        .map(|command| command.to_ascii_lowercase())
        .as_deref()
    {
        Some("x" | "e") => {
            let dirs: Vec<String> = switches()
                .filter_map(|switch| switch.strip_prefix('o'))
                .map(str::to_owned)
                .collect();
            writes.paths = if dirs.is_empty() {
                vec![".".to_owned()]
            } else {
                dirs
            };
            writes.unpinned = true;
        }
        Some("a" | "u" | "d" | "rn") => {
            writes
                .paths
                .extend(operands.get(1).map(|archive| (*archive).to_owned()));
        }
        _ => {}
    }
    writes
}

/// Short-option grammar of an in-place-capable interpreter, for [`in_place_writes`].
pub(super) struct InterpreterOptions {
    /// Options whose value is the rest of the cluster (`-Mstrict`, `-I/dir`), so an `i` inside it is not `-i`.
    pub(super) glued_value: &'static str,
    /// Of those, the ones whose value may instead be the next word (`-e CODE`, `-I DIR`).
    pub(super) next_word_value: &'static str,
    /// Options carrying inline code, so the first operand is a file rather than the script.
    pub(super) code: &'static str,
}

pub(super) const PERL_OPTIONS: InterpreterOptions = InterpreterOptions {
    glued_value: "eEIMmFxdDCV",
    next_word_value: "eEI",
    code: "eE",
};

pub(super) const RUBY_OPTIONS: InterpreterOptions = InterpreterOptions {
    glued_value: "eIrCEFxKTW",
    next_word_value: "eIrCE",
    code: "e",
};

/// `perl -i` / `ruby -i` (also clustered: `-pi`, `-i.bak`, `-lpi`): every file operand is rewritten in place.
/// Without inline code (`-e`) the first operand is the script, not a write. `-l`/`-0` take only octal digits.
pub(super) fn in_place_writes(args: &[String], options: &InterpreterOptions) -> ToolWrites {
    let (mut in_place, mut inline_code, mut i) = (false, false, 0);
    while i < args.len() {
        let word = &args[i];
        if word == "--" {
            i += 1;
            break;
        }
        let Some(cluster) = word.strip_prefix('-').filter(|cluster| !cluster.is_empty()) else {
            break;
        };
        i += 1;
        let mut chars = cluster.char_indices().peekable();
        while let Some((at, option)) = chars.next() {
            if option == 'i' {
                // The rest of the cluster is the backup extension.
                in_place = true;
                break;
            }
            if matches!(option, 'l' | '0') {
                while chars.next_if(|(_, c)| ('0'..='7').contains(c)).is_some() {}
                continue;
            }
            if options.glued_value.contains(option) {
                inline_code |= options.code.contains(option);
                if cluster[crate::permission::shell_words::after_char(cluster, at)..].is_empty()
                    && options.next_word_value.contains(option)
                {
                    i += 1;
                }
                break;
            }
        }
    }
    if !in_place {
        return ToolWrites::default();
    }
    let operands = args.get(i..).unwrap_or_default();
    let files = if inline_code {
        operands
    } else {
        operands.get(1..).unwrap_or_default()
    };
    ToolWrites {
        paths: files.to_vec(),
        ..ToolWrites::default()
    }
}

/// Long options whose value is the next word unless glued with `=`, and every option seen, for the small getopt
/// parsers below. Returns `(name, value)`; `i` is advanced past a consumed value.
pub(super) fn long_option<'a>(
    long: &'a str,
    args: &'a [String],
    i: &mut usize,
    takes_value: &[&str],
) -> (&'a str, Option<&'a str>) {
    match long.split_once('=') {
        Some((name, value)) => (name, Some(value)),
        None if takes_value.contains(&long) => {
            *i += 1;
            (long, args.get(*i - 1).map(String::as_str))
        }
        None => (long, None),
    }
}

/// `ditto -x` (also clustered, `-xk`) extracts an archive.
pub(super) fn ditto_extracts(inner: &[String]) -> bool {
    inner.iter().skip(1).any(|word| {
        word.strip_prefix('-')
            .is_some_and(|cluster| !cluster.starts_with('-') && cluster.contains('x'))
    })
}

/// `pax` modes and operands (P166 Grok r5 HIGH 1).
pub(super) struct PaxArgs<'a> {
    pub(super) read: bool,
    pub(super) write: bool,
    pub(super) archive: Option<&'a str>,
    pub(super) operands: Vec<&'a str>,
    /// `-s` renames members, `-L` follows links.
    pub(super) renames: bool,
    pub(super) follow: bool,
}

pub(super) fn pax_args(inner: &[String]) -> PaxArgs<'_> {
    const TAKES_VALUE: &str = "bfopsxBEGTU";
    let args = inner.get(1..).unwrap_or_default();
    let mut pax = PaxArgs {
        read: false,
        write: false,
        archive: None,
        operands: Vec::new(),
        renames: false,
        follow: false,
    };
    let (mut i, mut end) = (0, false);
    while i < args.len() {
        let word = &args[i];
        i += 1;
        if end || word == "-" || !word.starts_with('-') {
            pax.operands.push(word);
            continue;
        }
        if word == "--" {
            end = true;
            continue;
        }
        let cluster = &word[1..];
        for (at, option) in cluster.char_indices() {
            match option {
                'r' => pax.read = true,
                'w' => pax.write = true,
                'L' => pax.follow = true,
                _ if TAKES_VALUE.contains(option) => {
                    let value = short_option_value(cluster, at, args, &mut i);
                    match option {
                        'f' => pax.archive = value,
                        's' => pax.renames = true,
                        _ => {}
                    }
                    break;
                }
                _ => {}
            }
        }
    }
    pax
}

/// `pax -r` extracts into the cwd (members not inspected: unpinned); `pax -rw` copies its operands' trees into the last
/// operand (from stdin without operands, or renamed by `-s`: unpinned); `pax -w -f FILE` writes the archive.
pub(super) fn pax_writes(inner: &[String]) -> ToolWrites {
    let pax = pax_args(inner);
    let mut writes = ToolWrites::default();
    match (pax.read, pax.write) {
        (true, true) => {
            writes
                .paths
                .extend(pax.operands.last().map(|dest| (*dest).to_owned()));
            writes.unpinned = pax.operands.len() < 2 || pax.renames;
        }
        (true, false) => {
            writes.paths.push(".".to_owned());
            writes.unpinned = true;
        }
        (false, true) => writes
            .paths
            .extend(pax.archive.filter(|file| *file != "-").map(str::to_owned)),
        (false, false) => {}
    }
    writes
}

/// `patch` (P166 Grok r5 HIGH 1): `-o`/`--output` is the only file written (`-` is stdout); otherwise the original-file
/// operand; with neither, the files named inside the diff (unpinned). `-r` writes the reject file. `-d DIR` moves the
/// cwd and `--dry-run`/`-C` writes nothing.
pub(super) fn patch_writes(args: &[String]) -> ToolWrites {
    const TAKES_VALUE: &str = "BDdFgioprVYz";
    const LONG_WITH_VALUE: &[&str] = &[
        "output",
        "input",
        "reject-file",
        "directory",
        "strip",
        "prefix",
        "basename-prefix",
        "suffix",
        "fuzz",
        "get",
        "ifdef",
        "version-control",
        "quoting-style",
        "reject-format",
    ];
    let (mut outputs, mut rejects, mut operands) = (Vec::new(), Vec::new(), Vec::new());
    let (mut dry_run, mut moved, mut end, mut i) = (false, false, false, 0);
    while i < args.len() {
        let word = &args[i];
        i += 1;
        if end || word == "-" || !word.starts_with('-') {
            operands.push(word.as_str());
            continue;
        }
        if word == "--" {
            end = true;
            continue;
        }
        if let Some(long) = word.strip_prefix("--") {
            let (name, value) = long_option(long, args, &mut i, LONG_WITH_VALUE);
            match name {
                "output" => outputs.extend(value),
                "reject-file" => rejects.extend(value),
                "directory" => moved = true,
                "dry-run" | "check" => dry_run = true,
                _ => {}
            }
            continue;
        }
        let cluster = &word[1..];
        for (at, option) in cluster.char_indices() {
            if option == 'C' {
                dry_run = true;
            } else if TAKES_VALUE.contains(option) {
                let value = short_option_value(cluster, at, args, &mut i);
                match option {
                    'o' => outputs.extend(value),
                    'r' => rejects.extend(value),
                    'd' => moved = true,
                    _ => {}
                }
                break;
            }
        }
    }
    let mut writes = ToolWrites::default();
    if dry_run {
        return writes;
    }
    writes.paths.extend(
        rejects
            .into_iter()
            .filter(|file| *file != "-")
            .map(str::to_owned),
    );
    match (outputs.last(), operands.first()) {
        (Some(output), _) => writes
            .paths
            .extend((*output != "-").then(|| (*output).to_owned())),
        (None, Some(original)) => writes.paths.push((*original).to_owned()),
        (None, None) => writes.unpinned = true,
    }
    writes.unpinned |= moved;
    writes
}

/// `scp`'s operands (the last is the destination) and whether it copies recursively (`-r`).
pub(super) fn scp_operands(inner: &[String]) -> (Vec<&str>, bool) {
    const TAKES_VALUE: &str = "cDFiJloPSX";
    let args = inner.get(1..).unwrap_or_default();
    let (mut operands, mut recursive, mut end, mut i) = (Vec::new(), false, false, 0);
    while i < args.len() {
        let word = &args[i];
        i += 1;
        if end || word == "-" || !word.starts_with('-') {
            operands.push(word.as_str());
            continue;
        }
        if word == "--" {
            end = true;
            continue;
        }
        let cluster = &word[1..];
        for (at, option) in cluster.char_indices() {
            if option == 'r' {
                recursive = true;
            } else if TAKES_VALUE.contains(option) {
                short_option_value(cluster, at, args, &mut i);
                break;
            }
        }
    }
    (operands, recursive)
}

/// `scp` writes its local destination; a remote tree (`-r host:dir`) or a remote glob lands unknown names (unpinned).
pub(super) fn scp_writes(inner: &[String]) -> ToolWrites {
    let (operands, recursive) = scp_operands(inner);
    let mut writes = ToolWrites::default();
    if let Some((dest, sources)) = operands.split_last()
        && !sources.is_empty()
        && !is_host_operand(dest)
    {
        writes.paths.push(operand_local_path(dest));
        writes.unpinned = sources
            .iter()
            .any(|source| is_host_operand(source) && (recursive || shell_arg_is_ambiguous(source)));
    }
    writes
}

/// The file name `curl -O` / `wget` derive from a URL: its last path segment, raw and percent-decoded. Empty when the
/// URL has no path segment; `None` when a curl glob (`[1-3]`, `{a,b}`) makes the names unknown.
pub(super) fn url_file_names(url: &str) -> Option<Vec<String>> {
    let rest = url.split_once("://").map_or(url, |(_, rest)| rest);
    let Some((_, path)) = rest.split_once('/') else {
        return Some(Vec::new());
    };
    let path = path.split(['?', '#']).next().unwrap_or_default();
    if path.contains(['[', '{']) {
        return None;
    }
    let name = path.rsplit('/').next().unwrap_or_default();
    if name.is_empty() {
        return Some(Vec::new());
    }
    let decoded = percent_decode(name);
    let mut names = vec![name.to_owned()];
    // A decoded `/` would not be a single name; the raw spelling is still checked.
    if decoded != name && !decoded.contains('/') {
        names.push(decoded);
    }
    Some(names)
}

pub(super) fn percent_decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && let Some(hex) = text.get(i + 1..i + 3)
            && let Ok(byte) = u8::from_str_radix(hex, 16)
        {
            out.push(byte);
            i += 3;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Join an output name to a directory option (`curl --output-dir`, `wget -P`) unless it is absolute.
pub(super) fn place_in_dir(dir: Option<&str>, name: &str) -> String {
    match dir {
        Some(dir) if !is_absolute_shell_path(name) => {
            Path::new(dir).join(name).to_string_lossy().into_owned()
        }
        _ => name.to_owned(),
    }
}

/// `curl` (P166 Grok r5 sweep): `-o FILE` (in `--output-dir`), `-O` names from the URLs, and the files it writes as
/// side outputs (`-D`, `-c`, `--trace`, `--stderr`, `--libcurl`, `--etag-save`, `--hsts`, `--alt-svc`). `-J` (the
/// server picks the name), a `-o` glob variable (`#1`), a URL glob and `-K` (a config file can set any output) are
/// unpinned. Only the known value-taking options consume a value, so an unknown option can only add a URL name.
pub(super) fn curl_writes(args: &[String]) -> ToolWrites {
    const TAKES_VALUE: &str = "AbcCdDeEFHKmoPQrtTuUwxXyYz";
    const LONG_WITH_VALUE: &[&str] = &[
        "output",
        "output-dir",
        "dump-header",
        "cookie-jar",
        "trace",
        "trace-ascii",
        "stderr",
        "libcurl",
        "etag-save",
        "etag-compare",
        "hsts",
        "alt-svc",
        "config",
        "url",
        "data",
        "data-raw",
        "data-binary",
        "data-urlencode",
        "data-ascii",
        "json",
        "header",
        "request",
        "user",
        "user-agent",
        "referer",
        "cookie",
        "form",
        "form-string",
        "upload-file",
        "proxy",
        "max-time",
        "connect-timeout",
        "write-out",
        "range",
        "cert",
        "key",
        "cacert",
        "capath",
        "continue-at",
        "retry",
        "retry-delay",
        "retry-max-time",
        "resolve",
        "connect-to",
        "interface",
        "limit-rate",
        "max-filesize",
        "oauth2-bearer",
        "proxy-user",
        "pass",
        "cert-type",
        "key-type",
        "ciphers",
        "tls-max",
        "expect100-timeout",
        "keepalive-time",
        "max-redirs",
        "netrc-file",
        "unix-socket",
        "abstract-unix-socket",
        "variable",
        "url-query",
        "aws-sigv4",
        "dns-servers",
        "doh-url",
        "local-port",
        "noproxy",
        "preproxy",
        "proto",
        "proto-redir",
        "proxy-header",
        "request-target",
        "speed-limit",
        "speed-time",
        "telnet-option",
        "time-cond",
        "create-file-mode",
        "ftp-port",
        "quote",
        "mail-from",
        "mail-rcpt",
        "mail-auth",
        "socks4",
        "socks4a",
        "socks5",
        "socks5-hostname",
        "engine",
        "crlfile",
        "pinnedpubkey",
        "proxy-cacert",
        "proxy-capath",
        "proxy-cert",
        "proxy-key",
        "proxy-pass",
        "login-options",
        "delegation",
        "ip-tos",
        "happy-eyeballs-timeout-ms",
    ];
    let (mut outputs, mut side, mut urls) = (Vec::new(), Vec::new(), Vec::new());
    let (mut output_dir, mut remote_name, mut header_name, mut config) =
        (None, false, false, false);
    let mut i = 0;
    while i < args.len() {
        let word = &args[i];
        i += 1;
        if word == "-" || !word.starts_with('-') {
            urls.push(word.as_str());
            continue;
        }
        if let Some(long) = word.strip_prefix("--") {
            let (name, value) = long_option(long, args, &mut i, LONG_WITH_VALUE);
            match name {
                "output" => outputs.extend(value),
                "output-dir" => output_dir = value,
                "remote-name" | "remote-name-all" => remote_name = true,
                "remote-header-name" => header_name = true,
                "dump-header" | "cookie-jar" | "trace" | "trace-ascii" | "stderr" | "libcurl"
                | "etag-save" | "hsts" | "alt-svc" => side.extend(value),
                "config" => config = true,
                "url" => urls.extend(value),
                _ => {}
            }
            continue;
        }
        let cluster = &word[1..];
        for (at, option) in cluster.char_indices() {
            match option {
                'O' => remote_name = true,
                'J' => header_name = true,
                _ if TAKES_VALUE.contains(option) => {
                    let value = short_option_value(cluster, at, args, &mut i);
                    match option {
                        'o' => outputs.extend(value),
                        'D' | 'c' => side.extend(value),
                        'K' => config = true,
                        _ => {}
                    }
                    break;
                }
                _ => {}
            }
        }
    }
    let mut writes = ToolWrites::default();
    for output in outputs.into_iter().filter(|output| *output != "-") {
        writes.unpinned |= output.contains('#');
        writes.paths.push(place_in_dir(output_dir, output));
    }
    writes.paths.extend(
        side.into_iter()
            .filter(|file| *file != "-")
            .map(str::to_owned),
    );
    if remote_name || header_name {
        writes.unpinned |= header_name;
        for url in urls {
            match url_file_names(url) {
                Some(names) => writes
                    .paths
                    .extend(names.iter().map(|name| place_in_dir(output_dir, name))),
                None => writes.unpinned = true,
            }
        }
    }
    writes.unpinned |= config;
    writes
}

/// `wget` (P166 Grok r5 sweep): `-O FILE` (`-` is stdout), else each URL's name (`index.html` for a bare URL) in `-P DIR`;
/// log and cookie files. Recursive and server-named downloads (`-r`, `-m`, `-p`, `-x`, `-i`, `--content-disposition`,
/// `--trust-server-names`) and `-e` (a `.wgetrc` command can set any output) are unpinned.
pub(super) fn wget_writes(args: &[String]) -> ToolWrites {
    const TAKES_VALUE: &str = "aABDeiIlOoPQRtTUwX";
    const LONG_WITH_VALUE: &[&str] = &[
        "output-document",
        "directory-prefix",
        "output-file",
        "append-output",
        "input-file",
        "base",
        "execute",
        "tries",
        "timeout",
        "dns-timeout",
        "connect-timeout",
        "read-timeout",
        "wait",
        "waitretry",
        "user-agent",
        "header",
        "post-data",
        "post-file",
        "body-data",
        "body-file",
        "method",
        "user",
        "password",
        "http-user",
        "http-password",
        "ftp-user",
        "ftp-password",
        "load-cookies",
        "save-cookies",
        "referer",
        "accept",
        "reject",
        "accept-regex",
        "reject-regex",
        "domains",
        "exclude-domains",
        "include-directories",
        "exclude-directories",
        "level",
        "quota",
        "limit-rate",
        "bind-address",
        "cut-dirs",
        "default-page",
        "ca-certificate",
        "ca-directory",
        "certificate",
        "private-key",
        "certificate-type",
        "private-key-type",
        "progress",
        "restrict-file-names",
        "local-encoding",
        "remote-encoding",
        "secure-protocol",
        "report-speed",
        "rejected-log",
        "warc-file",
        "warc-header",
        "warc-max-size",
        "config",
        "proxy-user",
        "proxy-password",
        "prefer-family",
        "crl-file",
        "pinnedpubkey",
        "ciphers",
        "hsts-file",
        "compression",
        "use-askpass",
        "retry-on-http-error",
        "max-redirect",
    ];
    let (mut document, mut prefix, mut side, mut urls) = (None, None, Vec::new(), Vec::new());
    let mut unpinned = false;
    let mut i = 0;
    while i < args.len() {
        let word = &args[i];
        i += 1;
        if !word.starts_with('-') || word == "-" {
            urls.push(word.as_str());
            continue;
        }
        if let Some(long) = word.strip_prefix("--") {
            let (name, value) = long_option(long, args, &mut i, LONG_WITH_VALUE);
            match name {
                "output-document" => document = value,
                "directory-prefix" => prefix = value,
                "output-file" | "append-output" | "save-cookies" | "rejected-log" | "hsts-file"
                | "warc-file" => side.extend(value),
                "recursive"
                | "mirror"
                | "page-requisites"
                | "force-directories"
                | "input-file"
                | "content-disposition"
                | "trust-server-names"
                | "execute"
                | "config" => unpinned = true,
                _ => {}
            }
            continue;
        }
        let cluster = &word[1..];
        for (at, option) in cluster.char_indices() {
            match option {
                'r' | 'm' | 'p' | 'x' => unpinned = true,
                _ if TAKES_VALUE.contains(option) => {
                    let value = short_option_value(cluster, at, args, &mut i);
                    match option {
                        'O' => document = value,
                        'P' => prefix = value,
                        'o' | 'a' => side.extend(value),
                        'i' | 'e' => unpinned = true,
                        _ => {}
                    }
                    break;
                }
                _ => {}
            }
        }
    }
    let mut writes = ToolWrites {
        unpinned,
        ..ToolWrites::default()
    };
    writes.paths.extend(side.into_iter().map(str::to_owned));
    match document {
        Some("-") => {}
        Some(file) => writes.paths.push(file.to_owned()),
        None => {
            for url in urls {
                match url_file_names(url) {
                    Some(names) if names.is_empty() => {
                        writes.paths.push(place_in_dir(prefix, "index.html"));
                    }
                    Some(names) => writes
                        .paths
                        .extend(names.iter().map(|name| place_in_dir(prefix, name))),
                    None => writes.unpinned = true,
                }
            }
        }
    }
    writes
}

/// `split [INPUT [PREFIX]]` and `csplit -f PREFIX` write files named PREFIX plus a suffix (`x`/`xx` by default).
pub(super) fn split_writes(program: &str, args: &[String]) -> ToolWrites {
    let (takes_value, long_with_value): (&str, &[&str]) = if program == "csplit" {
        ("bfn", &["suffix-format", "prefix", "digits"])
    } else {
        (
            "abClnt",
            &[
                "suffix-length",
                "additional-suffix",
                "bytes",
                "line-bytes",
                "lines",
                "number",
                "separator",
                "filter",
            ],
        )
    };
    let (mut prefix, mut operands, mut end, mut i) = (None, Vec::new(), false, 0);
    while i < args.len() {
        let word = &args[i];
        i += 1;
        if end || word == "-" || !word.starts_with('-') {
            operands.push(word.as_str());
            continue;
        }
        if word == "--" {
            end = true;
            continue;
        }
        if let Some(long) = word.strip_prefix("--") {
            let (name, value) = long_option(long, args, &mut i, long_with_value);
            if name == "prefix" {
                prefix = value;
            }
            continue;
        }
        let cluster = &word[1..];
        for (at, option) in cluster.char_indices() {
            if takes_value.contains(option) {
                let value = short_option_value(cluster, at, args, &mut i);
                if program == "csplit" && option == 'f' {
                    prefix = value;
                }
                break;
            }
        }
    }
    let prefix = match program {
        "csplit" => prefix.unwrap_or("xx"),
        _ => operands.get(1).copied().unwrap_or("x"),
    };
    ToolWrites {
        generated: vec![prefix.to_owned()],
        ..ToolWrites::default()
    }
}

/// The gzip/bzip2/xz/lzma/zstd/lz4/brotli family (P166 Grok r5 sweep): decompressing writes each operand without its
/// suffix (`.tgz` -> `.tar`), or `-o FILE` (zstd, brotli) or lz4's second operand; compressing writes the operand plus
/// the suffix. `-c`/`--stdout` writes nothing; gzip `-N` restores the name stored in the archive (unpinned).
pub(super) fn decompress_writes(program: &str, args: &[String]) -> Option<ToolWrites> {
    let always = matches!(
        program,
        "gunzip" | "bunzip2" | "unxz" | "unlzma" | "unzstd" | "unlz4" | "uncompress" | "unpigz"
    );
    let suffix = match program {
        "gzip" | "pigz" => ".gz",
        "bzip2" | "pbzip2" | "lbzip2" => ".bz2",
        "xz" => ".xz",
        "lzma" => ".lzma",
        "zstd" => ".zst",
        "lz4" => ".lz4",
        "brotli" => ".br",
        "compress" => ".Z",
        _ if always => "",
        _ => return None,
    };
    let takes_value = if program == "brotli" {
        "oSTDMqw"
    } else {
        "oSTDM"
    };
    const LONG_WITH_VALUE: &[&str] = &["suffix", "output", "threads", "dict", "memlimit", "format"];
    let (mut decompress, mut stdout, mut restore_name) = (always, false, false);
    let (mut output, mut custom_suffix, mut operands, mut end, mut i) =
        (None, None, Vec::new(), false, 0);
    while i < args.len() {
        let word = &args[i];
        i += 1;
        if end || word == "-" || !word.starts_with('-') {
            operands.push(word.as_str());
            continue;
        }
        if word == "--" {
            end = true;
            continue;
        }
        if let Some(long) = word.strip_prefix("--") {
            let (name, value) = long_option(long, args, &mut i, LONG_WITH_VALUE);
            match name {
                "decompress" | "uncompress" => decompress = true,
                "stdout" | "to-stdout" => stdout = true,
                "name" => restore_name = true,
                "output" => output = value,
                "suffix" => custom_suffix = value,
                _ => {}
            }
            continue;
        }
        let cluster = &word[1..];
        for (at, option) in cluster.char_indices() {
            match option {
                'd' => decompress = true,
                'c' => stdout = true,
                'N' if program.contains("gz") || program.contains("pigz") => restore_name = true,
                _ if takes_value.contains(option) => {
                    let value = short_option_value(cluster, at, args, &mut i);
                    match option {
                        'o' => output = value,
                        'S' => custom_suffix = value,
                        _ => {}
                    }
                    break;
                }
                _ => {}
            }
        }
    }
    let mut writes = ToolWrites::default();
    if stdout {
        return Some(writes);
    }
    if let Some(output) = output.filter(|output| *output != "-") {
        writes.paths.push(output.to_owned());
        return Some(writes);
    }
    if !decompress {
        let suffix = custom_suffix.unwrap_or(suffix);
        writes
            .paths
            .extend(operands.iter().map(|operand| format!("{operand}{suffix}")));
        return Some(writes);
    }
    writes.unpinned = restore_name;
    if program.contains("lz4")
        && let [_, output] = operands.as_slice()
    {
        writes.paths.push((*output).to_owned());
        return Some(writes);
    }
    const SUFFIXES: &[(&str, &str)] = &[
        (".tgz", ".tar"),
        (".taz", ".tar"),
        (".tbz2", ".tar"),
        (".tbz", ".tar"),
        (".txz", ".tar"),
        (".tlz", ".tar"),
        (".tzst", ".tar"),
        (".gz", ""),
        ("-gz", ""),
        (".z", ""),
        ("-z", ""),
        ("_z", ""),
        (".bz2", ""),
        (".bz", ""),
        (".xz", ""),
        (".lzma", ""),
        (".lz", ""),
        (".zst", ""),
        (".lz4", ""),
        (".br", ""),
    ];
    for operand in operands {
        let lower = operand.to_ascii_lowercase();
        let stripped = custom_suffix
            .filter(|suffix| !suffix.is_empty() && operand.ends_with(suffix))
            .map(|suffix| operand[..operand.len() - suffix.len()].to_owned())
            .or_else(|| {
                SUFFIXES.iter().find_map(|(suffix, replacement)| {
                    lower.ends_with(suffix).then(|| {
                        format!("{}{replacement}", &operand[..operand.len() - suffix.len()])
                    })
                })
            });
        writes.paths.extend(stripped);
    }
    Some(writes)
}

/// The scripts of one `sed` argv: `-e`/`--expression` values, else the first operand; whether a `-f`/`--file` script
/// file (never read) supplies code; and whether `--sandbox` (no `e`/`r`/`w`) is set.
pub(super) struct SedArgv<'a> {
    pub(super) scripts: Vec<&'a str>,
    pub(super) script_file: bool,
    pub(super) sandbox: bool,
}

/// GNU getopt accepts any unambiguous long-option abbreviation; these are the shortest unique stems.
pub(super) const SED_LONG_STEMS: &[(&str, usize)] = &[
    ("expression", 1),
    ("file", 2),
    ("line-length", 1),
    ("sandbox", 2),
];

pub(super) fn sed_argv(inner: &[String]) -> SedArgv<'_> {
    let args = inner.get(1..).unwrap_or_default();
    let (mut scripts, mut script_file, mut bare_in_place, mut sandbox) =
        (Vec::new(), false, false, false);
    let (mut operands, mut end, mut i) = (Vec::new(), false, 0);
    while i < args.len() {
        let word = &args[i];
        i += 1;
        if end || word == "-" || !word.starts_with('-') {
            operands.push(word.as_str());
            continue;
        }
        if word == "--" {
            end = true;
            continue;
        }
        if let Some(long) = word.strip_prefix("--") {
            let (name, glued) = match long.split_once('=') {
                Some((name, value)) => (name, Some(value)),
                None => (long, None),
            };
            let name = SED_LONG_STEMS
                .iter()
                .find(|(full, stem)| name.len() >= *stem && full.starts_with(name))
                .map_or(name, |(full, _)| *full);
            let value = match glued {
                Some(value) => Some(value),
                None if matches!(name, "expression" | "file" | "line-length") => {
                    i += 1;
                    args.get(i - 1).map(String::as_str)
                }
                None => None,
            };
            match name {
                "expression" => scripts.extend(value),
                "file" => script_file = true,
                "sandbox" => sandbox = true,
                _ => {}
            }
            continue;
        }
        let cluster = &word[1..];
        for (at, option) in cluster.char_indices() {
            match option {
                'e' | 'f' | 'l' => {
                    let value = short_option_value(cluster, at, args, &mut i);
                    match option {
                        'e' => scripts.extend(value),
                        'f' => script_file = true,
                        _ => {}
                    }
                    break;
                }
                'i' => {
                    bare_in_place = cluster
                        [crate::permission::shell_words::after_char(cluster, at)..]
                        .is_empty();
                    break;
                }
                _ => {}
            }
        }
    }
    if scripts.is_empty() && !script_file {
        // The first operand is the script; BSD `sed -i '' SCRIPT` puts the empty backup suffix first.
        let script = match operands.as_slice() {
            ["", script, ..] if bare_in_place => Some(*script),
            [script, ..] => Some(*script),
            [] => None,
        };
        scripts.extend(script);
    }
    SedArgv {
        scripts,
        script_file,
        sandbox,
    }
}

/// u35: whether a `sed` argv can run a command: the `e` command or `s///e` flag in a literal script, a script that
/// cannot be parsed but holds an `e` (fail closed), a script the normaliser could not pin (u35 r2), or a `-f` script
/// file (not read). `--sandbox` disables `e`.
pub(crate) fn sed_runs_code(inner: &[String]) -> bool {
    let argv = sed_argv(inner);
    if argv.sandbox {
        return false;
    }
    // u35 r2: a script the normaliser could not pin is not vouched for.
    argv.script_file
        || argv.scripts.iter().any(|script| {
            crate::permission::exec_surface::is_unresolved(script)
                || sed_script_parse(script)
                    .map_or_else(|| script.contains('e'), |parsed| parsed.exec)
        })
}

/// `sed` writes: every file operand of `-i` (as before), and the files of `w FILE`, `W FILE` and the `s///w FILE` flag
/// in a literal script (P166 Grok r5 LOW 4). A script that cannot be parsed but holds a `w` fails closed. A `-f` script
/// file is not read (interpreter-limit class).
pub(super) fn sed_writes(inner: &[String]) -> ToolWrites {
    let scripts = sed_argv(inner).scripts;
    let mut writes = ToolWrites::default();
    if shell_sed_in_place(inner) {
        writes
            .paths
            .extend(shell_file_candidates(inner).into_iter().map(str::to_owned));
    }
    for script in scripts {
        match sed_script_write_files(script) {
            Some(files) => writes.paths.extend(files),
            None => writes.unpinned |= script.contains(['w', 'W']),
        }
    }
    writes
}

/// A sed address: a line number (`N`, `first~step`), `$`, or `/regex/` / `\cregexc`, with `I`/`M` flags.
pub(super) fn sed_address(s: &[char], i: &mut usize) -> Option<()> {
    match s.get(*i) {
        Some(c) if c.is_ascii_digit() => {
            while s.get(*i).is_some_and(char::is_ascii_digit) {
                *i += 1;
            }
            if s.get(*i) == Some(&'~') {
                *i += 1;
                while s.get(*i).is_some_and(char::is_ascii_digit) {
                    *i += 1;
                }
            }
        }
        Some('$') => *i += 1,
        Some('/') => {
            *i += 1;
            sed_delimited(s, i, '/')?;
        }
        Some('\\') => {
            let delimiter = *s.get(*i + 1)?;
            *i += 2;
            sed_delimited(s, i, delimiter)?;
        }
        _ => return Some(()),
    }
    while matches!(s.get(*i), Some('I' | 'M')) {
        *i += 1;
    }
    Some(())
}

/// Skip to just past the next unescaped `delimiter`; a raw newline or the end of the script is a parse failure.
pub(super) fn sed_delimited(s: &[char], i: &mut usize, delimiter: char) -> Option<()> {
    while let Some(&c) = s.get(*i) {
        *i += 1;
        if c == '\\' {
            *i += 1;
        } else if c == delimiter {
            return Some(());
        } else if c == '\n' {
            return None;
        }
    }
    None
}

/// The files a sed script writes (`w`, `W`, `s///w`); `None` when it cannot be parsed.
pub(super) fn sed_script_write_files(script: &str) -> Option<Vec<String>> {
    sed_script_parse(script).map(|parsed| parsed.files)
}

/// What one literal sed script does beyond printing: the files it writes and whether it runs a command (`e`, `s///e`).
pub(super) struct SedScript {
    pub(super) files: Vec<String>,
    pub(super) exec: bool,
}

/// Parse a sed script; `None` when it cannot be parsed.
pub(super) fn sed_script_parse(script: &str) -> Option<SedScript> {
    let s: Vec<char> = script.chars().collect();
    let mut i = 0;
    let mut files = Vec::new();
    let mut exec = false;
    let skip_blanks = |i: &mut usize| {
        while matches!(s.get(*i), Some(' ' | '\t')) {
            *i += 1;
        }
    };
    let rest_of_line = |i: &mut usize| -> String {
        let start = *i;
        while s.get(*i).is_some_and(|c| *c != '\n') {
            *i += 1;
        }
        s[start..*i].iter().collect()
    };
    let until = |i: &mut usize, stops: &[char]| {
        while s.get(*i).is_some_and(|c| *c != '\n' && !stops.contains(c)) {
            *i += 1;
        }
    };
    loop {
        while s.get(i).is_some_and(|c| c.is_whitespace() || *c == ';') {
            i += 1;
        }
        let Some(&first) = s.get(i) else {
            return Some(SedScript { files, exec });
        };
        if first == '#' {
            rest_of_line(&mut i);
            continue;
        }
        sed_address(&s, &mut i)?;
        skip_blanks(&mut i);
        if s.get(i) == Some(&',') {
            i += 1;
            skip_blanks(&mut i);
            if matches!(s.get(i), Some('+' | '~')) {
                i += 1;
                while s.get(i).is_some_and(char::is_ascii_digit) {
                    i += 1;
                }
            } else {
                sed_address(&s, &mut i)?;
            }
            skip_blanks(&mut i);
        }
        while s.get(i) == Some(&'!') {
            i += 1;
            skip_blanks(&mut i);
        }
        let command = *s.get(i)?;
        i += 1;
        match command {
            '{' | '}' | '=' | 'd' | 'D' | 'g' | 'G' | 'h' | 'H' | 'n' | 'N' | 'p' | 'P' | 'x'
            | 'z' | 'F' => {}
            'l' | 'L' | 'q' | 'Q' => {
                skip_blanks(&mut i);
                while s.get(i).is_some_and(char::is_ascii_digit) {
                    i += 1;
                }
            }
            ':' | 'v' => until(&mut i, &[';']),
            'b' | 't' | 'T' => until(&mut i, &[';', '}']),
            'r' | 'R' => {
                rest_of_line(&mut i);
            }
            'e' => {
                exec = true;
                rest_of_line(&mut i);
            }
            'a' | 'i' | 'c' => {
                // Text to the end of the line; a line ending in an odd run of backslashes continues on the next.
                loop {
                    let line = rest_of_line(&mut i);
                    let trailing = line.chars().rev().take_while(|c| *c == '\\').count();
                    if trailing % 2 == 1 && i < s.len() {
                        i += 1;
                    } else {
                        break;
                    }
                }
            }
            'w' | 'W' => {
                skip_blanks(&mut i);
                let file = rest_of_line(&mut i);
                if file.is_empty() {
                    return None;
                }
                files.push(file);
            }
            's' | 'y' => {
                let delimiter = *s.get(i)?;
                if matches!(delimiter, '\n' | '\\') {
                    return None;
                }
                i += 1;
                sed_delimited(&s, &mut i, delimiter)?;
                sed_delimited(&s, &mut i, delimiter)?;
                if command == 's' {
                    while let Some(&flag) = s.get(i) {
                        if flag == 'w' {
                            i += 1;
                            skip_blanks(&mut i);
                            let file = rest_of_line(&mut i);
                            if file.is_empty() {
                                return None;
                            }
                            files.push(file);
                            break;
                        }
                        if !(flag.is_ascii_digit() || "gpiImMe".contains(flag)) {
                            break;
                        }
                        exec |= command == 's' && flag == 'e';
                        i += 1;
                    }
                }
            }
            _ => return None,
        }
    }
}

/// The literal programs of one awk argv (`-e`/`--source` values, else the first operand), and whether the argv can
/// run code the program-text check does not see. u35 r2 (conservative): a program file or library (`-f`/`--file`,
/// gawk `-E`/`--exec`, `-i`/`--include`, `-l`/`--load`), an inline `-e`/`--source` program, a `-W` option, and any
/// option outside a small known set (an abbreviation included, whose value it may consume) all count.
pub(super) struct AwkArgv<'a> {
    pub(super) programs: Vec<&'a str>,
    /// Code from a file or library, never read.
    pub(super) program_file: bool,
    /// Code or options the check does not model.
    pub(super) unmodelled: bool,
}

pub(super) fn awk_argv(inner: &[String]) -> AwkArgv<'_> {
    /// Long options that take a value and carry no code.
    const VALUE_LONG: &[&str] = &["assign", "field-separator"];
    /// Long flags that carry no code and write nothing.
    const FLAG_LONG: &[&str] = &[
        "posix",
        "traditional",
        "lint",
        "characters-as-bytes",
        "use-lc-numeric",
        "non-decimal-data",
        "re-interval",
        "bignum",
        "optimize",
        "no-optimize",
        "csv",
        "sandbox",
        "version",
        "help",
        "copyright",
    ];
    /// Short flags that carry no code and write nothing.
    const FLAG_SHORT: &str = "bcCghLMnNOPrsStV";
    let args = inner.get(1..).unwrap_or_default();
    let mut argv = AwkArgv {
        programs: Vec::new(),
        program_file: false,
        unmodelled: false,
    };
    let (mut operands, mut i) = (Vec::new(), 0);
    while i < args.len() {
        let word = &args[i];
        i += 1;
        if word == "--" {
            operands.extend(args[i..].iter().map(String::as_str));
            break;
        }
        if word == "-" || !word.starts_with('-') {
            operands.push(word.as_str());
            continue;
        }
        if let Some(long) = word.strip_prefix("--") {
            let (name, glued) = match long.split_once('=') {
                Some((name, value)) => (name, Some(value)),
                None => (long, None),
            };
            match name {
                _ if VALUE_LONG.contains(&name) => {
                    if glued.is_none() {
                        i += 1;
                    }
                }
                "source" => {
                    let value = glued.or_else(|| {
                        i += 1;
                        args.get(i - 1).map(String::as_str)
                    });
                    argv.programs.extend(value);
                    argv.unmodelled = true;
                }
                "file" | "exec" | "include" | "load" => argv.program_file = true,
                _ if FLAG_LONG.contains(&name) => {}
                _ => argv.unmodelled = true,
            }
            continue;
        }
        let cluster = &word[1..];
        for (at, option) in cluster.char_indices() {
            match option {
                'F' | 'v' => {
                    short_option_value(cluster, at, args, &mut i);
                    break;
                }
                'e' => {
                    argv.programs
                        .extend(short_option_value(cluster, at, args, &mut i));
                    argv.unmodelled = true;
                    break;
                }
                'f' | 'E' | 'i' | 'l' => {
                    short_option_value(cluster, at, args, &mut i);
                    argv.program_file = true;
                    break;
                }
                _ if FLAG_SHORT.contains(option) => {}
                _ => {
                    argv.unmodelled = true;
                    break;
                }
            }
        }
    }
    if argv.programs.is_empty() && !argv.program_file {
        argv.programs.extend(operands.first().copied());
    }
    argv
}

/// A literal `print … > "FILE"` / `printf … >> "FILE"` in an awk program (P166 Grok r5 sweep). awk is an interpreter
/// (the interpreter-limit class), so this is a tripwire for the plain case: it feeds only the protected-target check,
/// never the `FileWrite` floor, because `>` is also awk's comparison operator.
pub(super) fn awk_literal_redirects(inner: &[String]) -> Vec<String> {
    awk_argv(inner)
        .programs
        .into_iter()
        .flat_map(awk_print_redirect_files)
        .collect()
}

/// u35: whether an awk argv can run a command or read the environment. u35 r2 (conservative default): only a program
/// given as the first operand, with no option outside a small known set, whose text passes [`awk_program_is_plain`],
/// is vouched for; anything else (no program, a program file, `-e`/`--source`, a program the normaliser could not pin)
/// counts.
pub(crate) fn awk_runs_code(inner: &[String]) -> bool {
    let argv = awk_argv(inner);
    argv.program_file
        || argv.unmodelled
        || argv.programs.is_empty()
        || argv
            .programs
            .into_iter()
            .any(|program| !awk_program_is_plain(program))
}

/// u35 r2: an awk program (already through the shell word normaliser) is plain only when it holds none of `system`,
/// `|` (command pipes, `|&`), `getline`, `ENVIRON`, `PROCINFO`, u35 r3 `SYMTAB`/`FUNCTAB` (gawk's variable and function
/// tables, which reach `ENVIRON` without naming it), `>` (output redirection; also comparison, which then over-asks),
/// `@` (gawk `@load`/`@include` and indirect calls), a backslash escape, or a string literal spliced onto an identifier
/// (`sy"s"tem`). u35 r3 (Fable r2 M2, Astra r2 M): string contents are not judged, so `print "hello"` and
/// `$1=="foo"` stay plain; only an opening quote right after an identifier character, or a closing quote right before
/// one, is a splice, and an odd number of quotes asks. No awk parsing: a program that cannot be shown free of these asks.
pub(super) fn awk_program_is_plain(program: &str) -> bool {
    if crate::permission::exec_surface::is_unresolved(program)
        || program.contains(['|', '>', '@', '\\'])
        || [
            "system", "getline", "ENVIRON", "PROCINFO", "SYMTAB", "FUNCTAB",
        ]
        .iter()
        .any(|banned| program.contains(banned))
    {
        return false;
    }
    let is_ident = |c: char| c.is_ascii_alphanumeric() || c == '_';
    let chars: Vec<char> = program.chars().collect();
    let mut inside = false;
    for (at, &c) in chars.iter().enumerate() {
        if c != '"' {
            continue;
        }
        let spliced = if inside {
            chars.get(at + 1).is_some_and(|&after| is_ident(after))
        } else {
            at.checked_sub(1)
                .is_some_and(|before| is_ident(chars[before]))
        };
        if spliced {
            return false;
        }
        inside = !inside;
    }
    !inside
}

pub(super) fn awk_print_redirect_files(program: &str) -> Vec<String> {
    let c: Vec<char> = program.chars().collect();
    let mut files = Vec::new();
    let (mut i, mut in_print, mut depth) = (0, false, 0i32);
    let read_string = |i: &mut usize| -> String {
        // `c[*i]` is the opening quote.
        *i += 1;
        let start = *i;
        while let Some(&ch) = c.get(*i) {
            if ch == '\\' {
                *i += 2;
                continue;
            }
            if ch == '"' {
                break;
            }
            *i += 1;
        }
        let text: String = c[start..(*i).min(c.len())].iter().collect();
        *i += 1;
        text
    };
    while let Some(&ch) = c.get(i) {
        let at_word = i == 0 || !c[i - 1].is_ascii_alphanumeric() && c[i - 1] != '_';
        if ch == '"' {
            read_string(&mut i);
            continue;
        }
        if at_word && !in_print {
            let rest: String = c[i..].iter().take(7).collect();
            for keyword in ["printf", "print"] {
                if rest.starts_with(keyword)
                    && !rest[keyword.len()..]
                        .chars()
                        .next()
                        .is_some_and(|next| next.is_ascii_alphanumeric() || next == '_')
                {
                    in_print = true;
                    depth = 0;
                    i += keyword.len();
                    break;
                }
            }
            if in_print {
                continue;
            }
        }
        if in_print {
            match ch {
                '(' => depth += 1,
                ')' => depth -= 1,
                ';' | '\n' | '}' | '|' if depth <= 0 => in_print = false,
                '>' if depth <= 0 => {
                    i += 1;
                    if c.get(i) == Some(&'>') {
                        i += 1;
                    }
                    while matches!(c.get(i), Some(' ' | '\t')) {
                        i += 1;
                    }
                    if c.get(i) == Some(&'"') {
                        files.push(read_string(&mut i));
                    }
                    in_print = false;
                    continue;
                }
                _ => {}
            }
        }
        i += 1;
    }
    files
}

/// Output files named by a flag of a compiler, linker, converter or decoder (P166 Grok r5 sweep): `-o FILE` for the C
/// family, `as`/`ld`/`nasm`/`strip`/`swiftc`, `iconv`, `uudecode`, `pandoc`, `dot`, `base64`; `openssl … -out FILE`;
/// `xxd`'s second operand. Mirrors the existing `rustc`/`go -o` writes, so `cc -o .git/hooks/pre-commit x.c` is seen.
pub(super) fn flag_output_writes(program: &str, inner: &[String]) -> Vec<String> {
    let c_family = ["gcc", "g++", "clang", "clang++", "cc", "c++"]
        .iter()
        .any(|name| {
            program == *name
                || program.ends_with(&format!("-{name}"))
                || program
                    .strip_prefix(name)
                    .and_then(|rest| rest.strip_prefix('-'))
                    .is_some_and(|version| {
                        !version.is_empty()
                            && version.chars().all(|c| c.is_ascii_digit() || c == '.')
                    })
        });
    let output_flag = c_family
        || matches!(
            program,
            "tcc"
                | "swiftc"
                | "nasm"
                | "yasm"
                | "as"
                | "ld"
                | "ld.lld"
                | "ld64.lld"
                | "ld.gold"
                | "ld.bfd"
                | "lld"
                | "strip"
                | "iconv"
                | "uudecode"
                | "pandoc"
                | "dot"
                | "base64"
        );
    if output_flag {
        return simple_output_flag_values(inner)
            .filter(|output| *output != "-")
            .map(str::to_owned)
            .collect();
    }
    match program {
        "openssl" => inner
            .iter()
            .enumerate()
            .filter(|(_, word)| *word == "-out")
            .filter_map(|(i, _)| inner.get(i + 1).cloned())
            .collect(),
        "xxd" => {
            const TAKES_VALUE: &str = "cglnoRs";
            let mut operands = Vec::new();
            let mut i = 1;
            while let Some(word) = inner.get(i) {
                i += 1;
                if word == "-" || !word.starts_with('-') {
                    operands.push(word.clone());
                } else if word[1..]
                    .chars()
                    .next()
                    .is_some_and(|option| TAKES_VALUE.contains(option))
                    && word.len() == 2
                {
                    i += 1;
                }
            }
            operands
                .into_iter()
                .nth(1)
                .filter(|output| output != "-")
                .into_iter()
                .collect()
        }
        // P166 r6 sweep: editors and in-place filters write each file operand; FIFO/node makers and `rename` create or
        // move the names they are given; `mogrify` rewrites its images in place.
        "sponge" | "ed" | "ex" | "vi" | "vim" | "nvim" | "emacs" | "nano" | "mkfifo" | "mknod"
        | "rename" | "mogrify" => shell_file_candidates(inner)
            .into_iter()
            .map(str::to_owned)
            .collect(),
        // `zip ARCHIVE FILE…` writes its first operand.
        "zip" => shell_file_candidates(inner)
            .into_iter()
            .take(1)
            .map(str::to_owned)
            .collect(),
        // The output file is the last word (`ffmpeg … OUT`, `convert IN… OUT`).
        // P166 r7: ImageMagick `-write FILE` is an output wherever it stands; the rest of the outputs are caught by the
        // class tripwire ([`tripwire::tripwire`]).
        "ffmpeg" | "convert" | "magick" => {
            let mut outputs: Vec<String> = inner
                .last()
                .filter(|last| inner.len() > 1 && !last.starts_with('-') && *last != "-")
                .map(|last| vec![last.clone()])
                .unwrap_or_default();
            outputs.extend(
                inner
                    .windows(2)
                    .filter(|pair| pair[0] == "-write")
                    .map(|pair| pair[1].clone()),
            );
            outputs
        }
        // `docker|podman|kubectl cp SRC DEST`: a DEST without `host:` is a local file.
        "docker" | "podman" | "kubectl" if inner.get(1).is_some_and(|word| word == "cp") => {
            shell_file_candidates(inner)
                .into_iter()
                .skip(1)
                .last()
                .filter(|dest| !dest.contains(':'))
                .map(str::to_owned)
                .into_iter()
                .collect()
        }
        _ => Vec::new(),
    }
}

/// `--output=F`, `-oF`, `-o F` and `--output F` (compilers, linkers and converters: no short-option clusters).
pub(super) fn simple_output_flag_values(words: &[String]) -> impl Iterator<Item = &str> {
    words.iter().enumerate().filter_map(|(i, token)| {
        token
            .strip_prefix("--output=")
            .or_else(|| token.strip_prefix("-o").filter(|value| !value.is_empty()))
            .or_else(|| {
                (token == "--output" || token == "-o")
                    .then(|| words.get(i + 1).map(String::as_str))
                    .flatten()
            })
    })
}

/// The parts of a `find` that write: `-exec`/`-execdir`/`-ok`/`-okdir` commands (each up to its `;` or `+`), and the
/// `-fprint`/`-fprint0`/`-fls`/`-fprintf` output files.
pub(super) fn find_parts(inner: &[String]) -> (Vec<&[String]>, Vec<&str>) {
    let (mut commands, mut files, mut i) = (Vec::new(), Vec::new(), 1);
    while let Some(word) = inner.get(i) {
        i += 1;
        match word.as_str() {
            "-exec" | "-execdir" | "-ok" | "-okdir" => {
                let start = i;
                while inner.get(i).is_some_and(|word| word != ";" && word != "+") {
                    i += 1;
                }
                commands.push(&inner[start..i.min(inner.len())]);
                i += 1;
            }
            "-fprint" | "-fprint0" | "-fls" => {
                files.extend(inner.get(i).map(String::as_str));
                i += 1;
            }
            "-fprintf" => {
                files.extend(inner.get(i).map(String::as_str));
                i += 2;
            }
            _ => {}
        }
    }
    (commands, files)
}

/// The command `xargs` runs (after its options), `None` for the default `echo`.
pub(super) fn xargs_command(inner: &[String]) -> Option<&[String]> {
    const TAKES_VALUE: &str = "aEdILnPRsJS";
    const LONG_WITH_VALUE: &[&str] = &[
        "arg-file",
        "delimiter",
        "max-args",
        "max-procs",
        "process-slot-var",
        "max-chars",
    ];
    let mut i = 1;
    while let Some(word) = inner.get(i) {
        if word == "--" {
            i += 1;
            break;
        }
        if word == "-" || !word.starts_with('-') {
            break;
        }
        i += 1;
        if let Some(long) = word.strip_prefix("--") {
            long_option(long, inner, &mut i, LONG_WITH_VALUE);
            continue;
        }
        let cluster = &word[1..];
        for (at, option) in cluster.char_indices() {
            // `-e[EOF]`, `-i[REPLACE]`, `-l[MAX]` take only a glued value.
            if matches!(option, 'e' | 'i' | 'l') {
                break;
            }
            if TAKES_VALUE.contains(option) {
                short_option_value(cluster, at, inner, &mut i);
                break;
            }
        }
    }
    inner.get(i..).filter(|command| !command.is_empty())
}

/// Commands `xargs`/`find -exec` run with names the command line does not show (P166 Grok r5 sweep).
pub(super) fn launched_commands<'a>(program: &str, inner: &'a [String]) -> Vec<&'a [String]> {
    match program {
        "xargs" => xargs_command(inner).into_iter().collect(),
        "find" => find_parts(inner).0,
        _ => Vec::new(),
    }
}

/// Placeholder for a name `xargs` appends or `find` substitutes; a NUL never comes from a real shell word.
pub(super) const LAUNCHED_NAME_PROBE: &str = "\0launched-name";

/// Whether a command launched with unknown names writes a file: it writes something once a name is appended. Deleting
/// programs are excluded (a deletion plants nothing), as are reads.
pub(super) fn launched_command_writes(
    command: &[String],
    depth: usize,
    file_write_only: bool,
) -> bool {
    let peel = peel_write_command(command);
    let Some(program) = peel
        .words
        .first()
        .map(|word| shell_program_name(word).to_ascii_lowercase())
    else {
        return false;
    };
    if matches!(program.as_str(), "rm" | "rmdir" | "unlink" | "shred") {
        return false;
    }
    let mut probe = command.to_vec();
    probe.push(LAUNCHED_NAME_PROBE.to_owned());
    if file_write_only {
        return !command_words_write_paths_depth(&probe, depth).is_empty();
    }
    let shell_words: Vec<ShellWord<'_>> = peel.words.iter().map(ShellWord::from).collect();
    matches!(
        shell_dash_c_script(&shell_words),
        InlineShellScript::Untrusted
    ) || command_targets(&probe, depth, &CommandExtras::default()).has_writes()
}

/// Write paths from a SINGLE already-split command's words (no redirects; the caller handles those at the tree level).
/// Reused both per parsed command and to re-check the inner command of a package-manager launcher (`uv run`, `npm exec`, ...).
/// The outer program name would hide those inner writes.
pub(crate) fn command_words_write_paths(words: &[String]) -> Vec<String> {
    command_words_write_paths_depth(words, MAX_INLINE_SHELL_DEPTH)
}

pub(super) fn command_words_write_paths_depth(words: &[String], depth: usize) -> Vec<String> {
    // P166 Grok r5: `sudo`/`command`/`exec`/`nohup`/… are peeled too, and a launcher's own output (`time -o`) counts.
    let peel = peel_write_command(words);
    let inner = peel.words;
    let mut out: Vec<String> = peel.writes.iter().map(|path| (*path).to_owned()).collect();
    let Some(program) = inner.first().map(|w| shell_program_name(w)) else {
        return out;
    };
    let program = program.to_ascii_lowercase();

    // Flag-named write operands (`dd of=`, `sort`/`go`/`rustc -o`, `git --output`).
    for (path, mode) in special_file_operands(&program, inner) {
        if matches!(mode, ShellFileMode::Write) {
            out.push(path);
        }
    }
    // P166 Grok r5 sweep: compiler/converter `-o`, `openssl -out`, `xxd` output operand.
    out.extend(flag_output_writes(&program, inner));
    // P166 Grok r5 sweep: `find -fprint FILE`, and what `xargs`/`find -exec` run. Names they append or substitute are
    // unknown, so a command that writes once a name is appended writes somewhere (`.`).
    if program == "find" {
        out.extend(find_parts(inner).1.into_iter().map(str::to_owned));
    }
    if depth > 0 {
        for command in launched_commands(&program, inner) {
            out.extend(command_words_write_paths_depth(command, depth - 1));
            if launched_command_writes(command, depth - 1, true) {
                out.push(".".to_owned());
            }
        }
    }
    // P166 Grok r4/r5: archive extraction/creation, sync destinations, in-place edits, patch/scp/pax/curl/wget/split,
    // decompressors and `sed w`.
    if let Some(writes) = tool_writes(&program, inner) {
        out.extend(writes.paths);
        out.extend(writes.generated);
        if writes.unpinned && out.is_empty() {
            out.push(".".to_owned());
        }
        return out;
    }
    // Path-moving destinations (`cp`/`mv`/`ln`/`install` dest; `rm`/`touch`/…; `uniq` output operand)
    if let Some(operands) = shell_path_command_operands(&program, inner) {
        for (path, mode) in operands {
            if matches!(mode, ShellFileMode::Write) {
                out.push(path.to_owned());
            }
        }
        return out;
    }
    // Named-argument writers (`tee`/`truncate`/...) and in-place `sed -i`, which rewrites each file operand
    let writes_operands = matches!(shell_file_mode(&program), Some(ShellFileMode::Write))
        || (program == "sed" && shell_sed_in_place(inner));
    if writes_operands {
        for token in shell_file_candidates(inner) {
            out.push(token.to_owned());
        }
    }
    out
}

/// Every path a shell command WRITES, from an ALREADY-PARSED tree so a caller that already parsed `src` shares the one parse.
/// Output redirects plus the per-command writers from [`command_words_write_paths`]. No safe-sink filtering; the caller decides.
pub(crate) fn command_write_paths_in_tree(root: Node<'_>, src: &str) -> Vec<String> {
    let split = command_write_paths_split(root, src);
    let mut out = split.redirect_paths;
    out.extend(split.word_paths);
    out
}

/// [`command_write_paths_in_tree`] split by provenance: redirect targets (`> f`, `>> f`) vs command-word operands (`touch f`, `sed -i`).
/// Redirect targets are invisible to allow-rule word matching, while command words are what a rule matches.
/// The distinction decides whether a narrow allow rule can vouch for the write.
pub(crate) struct WritePathsSplit {
    pub(crate) redirect_paths: Vec<String>,
    /// A write redirect had no extractable target (`> $OUT`, `> "$(…)"`).
    /// Fail-closed signal: the write exists but nothing can vouch for it.
    pub(crate) unextracted_write_redirect: bool,
    pub(crate) word_paths: Vec<String>,
    /// A command rewrites unspecified files of the working tree (`git checkout main`, `git pull`, `git stash pop`): the
    /// ordinary FileWrite floor, not a protected-path hit (P166 r8B).
    pub(crate) worktree_rewrite: bool,
}

pub(crate) fn command_write_paths_split(root: Node<'_>, src: &str) -> WritePathsSplit {
    // Output redirects (`> f`, `>> f`); fd-dups/heredocs are already skipped.
    let mut redirect_paths = Vec::new();
    let mut unextracted_write_redirect = false;
    for r in shell_redirect_targets(root, src) {
        if matches!(r.mode, ShellFileMode::Write) {
            match r.path {
                Some(path) => redirect_paths.push(path),
                None => unextracted_write_redirect = true,
            }
        }
    }
    // Per-command writers, after peeling env/timeout/... wrappers.
    let mut word_paths = Vec::new();
    let mut worktree_rewrite = false;
    for invocation in shell_command_invocations(root, src) {
        let words = InvocationSlice {
            words: &invocation.words,
        }
        .literal_words();
        word_paths.extend(command_words_write_paths(&words));
        worktree_rewrite |= git_words_rewrite_worktree(&words);
    }
    WritePathsSplit {
        redirect_paths,
        unextracted_write_redirect,
        word_paths,
        worktree_rewrite,
    }
}

/// A `git` command whose verb rewrites working-tree files it does not name: a branch switch, `pull`, `merge`,
/// `rebase`, `stash pop/apply`, `reset --hard`, `clean`, `rm`, `apply`, `am`, ... (P166 r8B, Grok r7 MEDIUM 1). It gets
/// the ordinary FileWrite floor. Whether the other branch's tree holds a protected file is not knowable without
/// running git, so that residual stays outside a path-naming floor.
pub(crate) fn git_words_rewrite_worktree(words: &[String]) -> bool {
    let inner = peel_write_command(words).words;
    if inner
        .first()
        .map(|word| shell_program_name(word).to_ascii_lowercase())
        .as_deref()
        != Some("git")
    {
        return false;
    }
    let Some(verb_at) = git_verb_index(inner) else {
        return false;
    };
    let args = &inner[verb_at + 1..];
    let has = |names: &[&str]| args.iter().any(|arg| names.contains(&arg.as_str()));
    match inner[verb_at].as_str() {
        "checkout" | "switch" | "merge" | "pull" | "rebase" | "cherry-pick" | "revert" | "am"
        | "checkout-index" | "clone" | "clean" | "rm" | "sparse-checkout" => true,
        "reset" => has(&["--hard", "--merge", "--keep"]),
        "restore" => !has(&["--staged", "-S"]) || has(&["--worktree", "-W"]),
        "stash" => !matches!(
            args.iter()
                .find(|arg| !arg.starts_with('-'))
                .map(String::as_str),
            Some("list" | "show" | "drop" | "clear" | "create" | "store")
        ),
        "apply" => {
            !has(&["--check", "--stat", "--numstat", "--summary", "--cached"])
                || has(&["--apply", "--index"])
        }
        "read-tree" => has(&["-u"]),
        "worktree" => args.first().map(String::as_str) == Some("add"),
        "submodule" => matches!(args.first().map(String::as_str), Some("update" | "add")),
        "bisect" => !matches!(
            args.first().map(String::as_str),
            Some("log" | "visualize" | "view" | "terms" | "help")
        ),
        _ => false,
    }
}

/// The creation set, shared by the write-path classifier and the auto-allow so they can't drift.
pub(crate) fn is_creation_program(program: &str) -> bool {
    CREATION_PROGRAMS.contains(&program)
}

/// The programs [`is_creation_program`] accepts.
pub(crate) const CREATION_PROGRAMS: &[&str] = &["mkdir", "touch"];

/// The `Create`-mode operands that [`command_words_write_paths`] omits.
pub(crate) fn command_words_creation_paths(words: &[String]) -> Vec<String> {
    let inner = peel_write_command(words).words;
    let Some(program) = inner.first().map(|w| shell_program_name(w)) else {
        return Vec::new();
    };
    shell_path_command_operands(&program.to_ascii_lowercase(), inner)
        .into_iter()
        .flatten()
        .filter(|(_, mode)| matches!(mode, ShellFileMode::Create))
        .map(|(path, _)| path.to_owned())
        .collect()
}
