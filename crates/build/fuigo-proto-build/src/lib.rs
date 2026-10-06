// Build-time helper: runs only inside build scripts, where stdout is cargo's `cargo:` directive
// protocol and stderr is cargo's build log. Nothing here ships (R077 workspace print deny).
#![allow(clippy::print_stdout, clippy::print_stderr)]
mod debug_redact;
pub mod find_protoc;

use anyhow::Context;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// Find the protoc well-known types include directory.
///
/// When PROTOC is set (e.g., in Bazel), the include directory is typically
/// at `../include` relative to the `bin/protoc` binary. For example:
/// - PROTOC = `/path/to/external/protoc_linux_x86_64/bin/protoc`
/// - Include = `/path/to/external/protoc_linux_x86_64/include`
///
/// This is needed because Bazel places the protoc binary and include files
/// in separate locations within the sandbox, and protoc doesn't automatically
/// find them without an explicit -I flag.
fn find_protoc_include_dir(protoc: Option<&Path>) -> Option<PathBuf> {
    let protoc = protoc?;

    // protoc is typically at .../bin/protoc, so include is at .../include
    let parent = protoc.parent()?; // .../bin
    let grandparent = parent.parent()?; // .../
    let include_dir = grandparent.join("include");

    if include_dir.is_dir() {
        Some(include_dir)
    } else {
        None
    }
}

/// The path to hand cargo as `rerun-if-changed` for `protoc`.
///
/// A path with a directory part (`$PROTOC`, the `bin/protoc` wrapper) is a real file relative to
/// the build script's directory and is used as given. A bare name (`protoc`, found on `PATH`) is
/// NOT: cargo would look for `<package>/protoc`, never find it, and treat the build script as
/// stale on every invocation -- rebuilding this crate's dependents each time. A bare name is
/// therefore resolved through `path_var` the way `execvp` does (first directory holding an
/// executable file of that name; an empty entry is the current directory) and the absolute path
/// returned; when it cannot be resolved there is nothing to track and `None` is returned.
///
/// `PATH` itself is deliberately not tracked (`rerun-if-env-changed=PATH`): shells, IDEs and
/// test harnesses routinely run cargo with different `PATH`s that select the same protoc, and
/// every such difference would rerun the build script and rebuild all of its dependents -- the
/// very cost this function removes. Switching to a different protoc via `PATH` (or by setting
/// `PROTOC`, which is not a rerun trigger either) needs a `cargo clean -p` of the generating crate.
fn protoc_rerun_path(protoc: &Path, path_var: Option<&std::ffi::OsStr>) -> Option<PathBuf> {
    let mut components = protoc.components();
    let bare = matches!(
        (components.next(), components.next()),
        (Some(std::path::Component::Normal(_)), None)
    );
    if !bare {
        return Some(protoc.to_path_buf());
    }
    let candidates: Vec<PathBuf> = if cfg!(windows) && protoc.extension().is_none() {
        vec![protoc.with_extension("exe"), protoc.to_path_buf()]
    } else {
        vec![protoc.to_path_buf()]
    };
    search_dirs(path_var?)
        .flat_map(|dir| candidates.iter().map(move |name| dir.join(name)))
        .find(|candidate| is_executable_file(candidate))
        .and_then(|found| std::path::absolute(found).ok())
}

/// The directories `PATH` names, in order; an empty entry is the current directory.
fn search_dirs(path_var: &std::ffi::OsStr) -> impl Iterator<Item = PathBuf> + '_ {
    env::split_paths(path_var).map(|dir| {
        if dir.as_os_str().is_empty() {
            PathBuf::from(".")
        } else {
            dir
        }
    })
}

#[cfg(unix)]
fn is_executable_file(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    fs::metadata(path).is_ok_and(|meta| meta.is_file() && meta.permissions().mode() & 0o111 != 0)
}

#[cfg(not(unix))]
fn is_executable_file(path: &Path) -> bool {
    path.is_file()
}

pub struct FuigoProtoBuilder {
    builder: tonic_prost_build::Builder,
    file_descriptor_set_path: Option<PathBuf>,
    gen_pbjson: bool,
    pbjson_ignore_unknown_fields: bool,
    pbjson_preserve_proto_field_names: bool,
    pbjson_exclude: Vec<String>,
    honor_debug_redact: bool,
}

impl FuigoProtoBuilder {
    fn map_builder(
        self,
        f: impl FnOnce(tonic_prost_build::Builder) -> tonic_prost_build::Builder,
    ) -> Self {
        Self {
            builder: f(self.builder),
            ..self
        }
    }

    pub fn btree_map<S: AsRef<str>>(self, paths: impl IntoIterator<Item = S>) -> Self {
        self.map_builder(|b| paths.into_iter().fold(b, |b, path| b.btree_map(path)))
    }

    pub fn bytes<S: AsRef<str>>(self, paths: impl IntoIterator<Item = S>) -> Self {
        self.map_builder(|b| paths.into_iter().fold(b, |b, path| b.bytes(path)))
    }

    pub fn extern_path(self, proto_path: impl AsRef<str>, rust_path: impl AsRef<str>) -> Self {
        self.map_builder(|b| b.extern_path(proto_path, rust_path))
    }

    pub fn file_descriptor_set_path(mut self, path: impl AsRef<Path>) -> Self {
        self.file_descriptor_set_path = Some(path.as_ref().to_path_buf());
        self.map_builder(|b| b.file_descriptor_set_path(path))
    }

    pub fn gen_pbjson(mut self) -> Self {
        self.gen_pbjson = true;
        self
    }

    pub fn pbjson_ignore_unknown_fields(mut self) -> Self {
        self.pbjson_ignore_unknown_fields = true;
        self
    }

    /// Serialize JSON using the original proto field names (snake_case) instead
    /// of the proto3-JSON default (camelCase). Deserialization still accepts
    /// both casings, so this is backward-compatible with already-stored
    /// camelCase documents.
    pub fn pbjson_preserve_proto_field_names(mut self) -> Self {
        self.pbjson_preserve_proto_field_names = true;
        self
    }

    /// Skip pbjson serde generation for these fully-qualified proto type
    /// prefixes (e.g. `.model_config.RateLimit`). Use when a type is
    /// `extern_path`'d into another crate that already provides its pbjson serde
    /// impls, but the enclosing package's serde is still generated here —
    /// otherwise pbjson would emit an orphan `impl Serialize for <foreign type>`.
    /// Matching is segment-based, so `.pkg.Foo` does not match `.pkg.FooBar`.
    pub fn pbjson_exclude<S: Into<String>>(
        mut self,
        prefixes: impl IntoIterator<Item = S>,
    ) -> Self {
        self.pbjson_exclude
            .extend(prefixes.into_iter().map(Into::into));
        self
    }

    pub fn generate_default_stubs(self, enable: bool) -> Self {
        self.map_builder(|b| b.generate_default_stubs(enable))
    }

    /// Honor the protobuf `debug_redact` field option: annotated fields
    /// print as `***` in `Debug`. The crate must also depend on `veil`.
    pub fn honor_debug_redact(mut self) -> Self {
        self.honor_debug_redact = true;
        self
    }

    pub fn type_attribute(self, path: impl AsRef<str>, attr: impl AsRef<str>) -> Self {
        self.map_builder(|b| b.type_attribute(path, attr))
    }

    pub fn field_attribute(self, path: impl AsRef<str>, attr: impl AsRef<str>) -> Self {
        self.map_builder(|b| b.field_attribute(path, attr))
    }

    // tonic-build generation of `rerun-if-changed` is lazy and incorrect.
    // - everything is invalidated when anything inside include directories is changed
    // - also they compute paths incorrectly: assuming paths are relative to current directory
    //   rather than
    fn emit_rerun_if_changed<'a>(
        protoc: Option<&Path>,
        protoc_include_dir: Option<&Path>,
        protos: impl IntoIterator<Item = &'a Path>,
        includes: impl IntoIterator<Item = &'a Path>,
    ) -> anyhow::Result<()> {
        let includes = Vec::from_iter(includes);

        if let Some(protoc) = protoc {
            match protoc_rerun_path(protoc, env::var_os("PATH").as_deref()) {
                Some(tracked) if tracked.as_path() == protoc => println!(
                    "cargo:rerun-if-changed={}",
                    protoc.to_str().context("protoc path not UTF-8")?
                ),
                // Resolved from PATH: a non-UTF-8 directory cannot be printed to cargo, and
                // must not fail a build that previously succeeded; just do not track it.
                Some(tracked) => {
                    if let Some(tracked) = tracked.to_str() {
                        println!("cargo:rerun-if-changed={tracked}");
                    }
                }
                None => {}
            }
        }

        // protoc writes the dependency list to a real file, and we read it
        // back. Upstream passed `--dependency_out=/dev/stdout` and
        // `--descriptor_set_out=/dev/null` and parsed protoc's stdout, which
        // is a Unix-only trick: on Windows those paths do not exist and protoc
        // exits with `/dev/stdout: No such file or directory`, failing the
        // build of fuigo-tools-api before a single line of Rust is compiled.
        //
        // OUT_DIR is the correct home for both files -- cargo owns it, gives
        // each build script its own, and cleans it up.
        let out_dir = PathBuf::from(
            env::var_os("OUT_DIR").context("OUT_DIR not set; not running under cargo?")?,
        );
        let dep_path = out_dir.join("protoc-dependency-out.d");
        let descriptor_path = out_dir.join("protoc-descriptor-out.bin");

        // Can only process one input file when using --dependency_out=FILE.
        for proto in protos {
            let mut command = Command::new(protoc.unwrap_or(Path::new("protoc")));
            command
                .arg(format!(
                    "--dependency_out={}",
                    dep_path.to_str().context("OUT_DIR not UTF-8")?
                ))
                .arg(format!(
                    "--descriptor_set_out={}",
                    descriptor_path.to_str().context("OUT_DIR not UTF-8")?
                ));

            // Add protoc's well-known types include directory first (if found).
            // This is needed for Bazel sandboxed builds where protoc and its
            // include files are in different locations.
            if let Some(include_dir) = protoc_include_dir {
                command.arg(format!(
                    "-I{}",
                    include_dir.to_str().context("include path not UTF-8")?
                ));
            }

            for include in &includes {
                command.arg(format!("-I{}", include.to_str().context("path not UTF-8")?));
            }

            command.arg(proto);

            command.stdin(Stdio::null());
            command.stderr(Stdio::inherit());

            let output = command.output().context("protoc command failed")?;
            if !output.status.success() {
                return Err(anyhow::anyhow!("protoc command failed"));
            }

            let output = fs::read_to_string(&dep_path)
                .with_context(|| format!("reading {}", dep_path.display()))?;

            // Make-style: `<target>: <dep> \<newline> <dep> ...`. We want only
            // the dependency list, so find where the target ends.
            //
            // Do NOT strip a fixed prefix. The target is now a real path, and
            // on Windows it starts `C:\...` -- the drive-letter colon is not
            // the separator. The separator is the first colon followed by
            // whitespace (or end of input), which `C:` never is.
            let sep = output
                .char_indices()
                .find(|&(i, c)| {
                    c == ':'
                        && output[i + 1..]
                            .chars()
                            .next()
                            .is_none_or(|next| next.is_whitespace())
                })
                .map(|(i, _)| i)
                .with_context(|| {
                    format!("protoc dependency output has no target separator: {output:?}")
                })?;

            for line in output[sep + 1..].lines() {
                let line = line.trim();
                let line = line.strip_suffix("\\").unwrap_or(line).trim();
                if line.is_empty() {
                    continue;
                }
                // Depending on absolute paths like
                // /Users/user/homebrew/Cellar/protobuf/29.1/include/google/protobuf/timestamp.proto
                // is valid, but we want to have output more deterministic.
                // Windows protoc emits backslashes, so match either separator.
                if line.contains("/include/google/protobuf/")
                    || line.contains("\\include\\google\\protobuf\\")
                {
                    continue;
                }

                if !fs::exists(line)? {
                    return Err(anyhow::anyhow!("dependency file not found: {line}"));
                }

                println!("cargo:rerun-if-changed={line}");
            }
        }

        Ok(())
    }

    pub fn compile_protos(
        self,
        protos: &[impl AsRef<Path>],
        includes: &[impl AsRef<Path>],
    ) -> anyhow::Result<()> {
        for proto in protos {
            let proto = proto.as_ref();
            if proto.is_absolute() {
                return Err(anyhow::anyhow!(
                    "Absolute paths are not allowed: {}",
                    proto.display()
                ));
            }
        }

        let FuigoProtoBuilder {
            builder,
            gen_pbjson,
            file_descriptor_set_path,
            pbjson_ignore_unknown_fields,
            pbjson_preserve_proto_field_names,
            pbjson_exclude,
            honor_debug_redact,
        } = self;
        let mut config = prost_build::Config::new();
        config.enable_type_names();

        let protoc = find_protoc::find_protoc()?;

        // Use fixed version of `protoc` binary.
        if let Some(protoc) = &protoc {
            config.protoc_executable(protoc);
        }

        // Find the protoc's well-known types include directory.
        // This is needed for Bazel sandboxed builds where protoc and its
        // include files are placed in different sandbox locations.
        let protoc_include_dir = find_protoc_include_dir(protoc.as_deref());

        let mut builder = builder.emit_rerun_if_changed(false);
        Self::emit_rerun_if_changed(
            protoc.as_deref(),
            protoc_include_dir.as_deref(),
            protos.iter().map(|p| p.as_ref()),
            includes.iter().map(|i| i.as_ref()),
        )?;

        let tempfile;

        let file_descriptor_set_path: Option<PathBuf> =
            if let Some(file_descriptor_set_path) = file_descriptor_set_path {
                Some(file_descriptor_set_path)
            } else if gen_pbjson {
                tempfile = tempfile::TempDir::new()?;
                let file_descriptor_set_path = tempfile.path().join("fuigo-proto-build.pbbin");
                builder = builder.file_descriptor_set_path(&file_descriptor_set_path);
                Some(file_descriptor_set_path)
            } else {
                None
            };

        // Build the full includes list, prepending the protoc include directory
        // if found (for well-known types like google/protobuf/timestamp.proto).
        let all_includes: Vec<&Path> = protoc_include_dir
            .as_deref()
            .into_iter()
            .chain(includes.iter().map(|i| i.as_ref()))
            .collect();

        let protos: Vec<&Path> = protos.iter().map(|p| p.as_ref()).collect();

        {
            let plain_includes: Vec<&Path> = includes.iter().map(|i| i.as_ref()).collect();
            if honor_debug_redact {
                debug_redact::apply(
                    &mut config,
                    protoc.as_deref(),
                    protoc_include_dir.as_deref(),
                    &plain_includes,
                    &protos,
                )?;
            } else if let Some(field) = debug_redact::first_marked_field(
                protoc.as_deref(),
                protoc_include_dir.as_deref(),
                &plain_includes,
                &protos,
            )? {
                anyhow::bail!(
                    "{field} sets `debug_redact = true` but redaction is not active: \
                     call `.honor_debug_redact()` on the builder"
                );
            }
        }

        builder
            .compile_with_config(config, &protos, &all_includes)
            .context("tonic_build failed")?;

        if gen_pbjson {
            let file_descriptor_set_path =
                file_descriptor_set_path.context("fds must be set at this moment")?;
            let descriptor_set = fs::read(&file_descriptor_set_path).with_context(|| {
                format!(
                    "Failed to read file descriptor set {}",
                    file_descriptor_set_path.display()
                )
            })?;
            let mut builder = pbjson_build::Builder::new();
            builder
                .register_descriptors(&descriptor_set)
                .context("Failed to register descriptors in pbjson_build")?;
            if pbjson_ignore_unknown_fields {
                builder.ignore_unknown_fields();
            }
            if pbjson_preserve_proto_field_names {
                builder.preserve_proto_field_names();
            }
            if !pbjson_exclude.is_empty() {
                builder.exclude(pbjson_exclude);
            }
            builder
                .build(&["."])
                .context("Failed to build descriptor set")?;
        }

        Ok(())
    }
}

pub fn configure() -> FuigoProtoBuilder {
    let builder = tonic_prost_build::configure()
        .compile_well_known_types(true)
        .extern_path(".google.protobuf", "::pbjson_types")
        .extern_path(".google.protobuf.Empty", "()")
        .protoc_arg("--experimental_allow_proto3_optional");
    FuigoProtoBuilder {
        builder,
        gen_pbjson: false,
        pbjson_ignore_unknown_fields: false,
        pbjson_preserve_proto_field_names: false,
        pbjson_exclude: Vec::new(),
        file_descriptor_set_path: None,
        honor_debug_redact: false,
    }
}

#[cfg(test)]
mod protoc_rerun_path_tests {
    use super::protoc_rerun_path;
    use std::path::{Path, PathBuf};

    /// An executable stand-in for protoc at `path`.
    fn executable(path: &Path) {
        std::fs::write(path, "").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
    }

    fn exe_name() -> &'static str {
        if cfg!(windows) {
            "protoc.exe"
        } else {
            "protoc"
        }
    }

    /// P74: a bare `protoc` from PATH must be tracked by its absolute location, never as the
    /// relative `protoc` that does not exist next to the package (which made cargo rerun the
    /// build script, and rebuild every dependent, on every invocation).
    #[test]
    fn bare_name_resolves_to_the_absolute_path_on_path() {
        let empty = tempfile::tempdir().unwrap();
        let bin = tempfile::tempdir().unwrap();
        let protoc = bin.path().join(exe_name());
        executable(&protoc);
        let path_var = std::env::join_paths([empty.path(), bin.path()]).unwrap();

        let tracked = protoc_rerun_path(Path::new("protoc"), Some(&path_var))
            .expect("protoc on PATH must be tracked");

        assert!(tracked.is_absolute(), "{}", tracked.display());
        assert_eq!(tracked, std::path::absolute(&protoc).unwrap());
        assert!(tracked.exists());
    }

    #[test]
    fn first_path_entry_wins() {
        let first = tempfile::tempdir().unwrap();
        let second = tempfile::tempdir().unwrap();
        executable(&first.path().join(exe_name()));
        executable(&second.path().join(exe_name()));
        let path_var = std::env::join_paths([first.path(), second.path()]).unwrap();

        assert_eq!(
            protoc_rerun_path(Path::new("protoc"), Some(&path_var)),
            Some(std::path::absolute(first.path().join(exe_name())).unwrap())
        );
    }

    #[test]
    fn a_directory_named_protoc_on_path_is_skipped() {
        let first = tempfile::tempdir().unwrap();
        let second = tempfile::tempdir().unwrap();
        std::fs::create_dir(first.path().join(exe_name())).unwrap();
        executable(&second.path().join(exe_name()));
        let path_var = std::env::join_paths([first.path(), second.path()]).unwrap();

        assert_eq!(
            protoc_rerun_path(Path::new("protoc"), Some(&path_var)),
            Some(std::path::absolute(second.path().join(exe_name())).unwrap())
        );
    }

    /// Astra P74 LOW: `execvp` skips a non-executable file, so the tracked file must too.
    #[cfg(unix)]
    #[test]
    fn a_non_executable_file_on_path_is_skipped() {
        let first = tempfile::tempdir().unwrap();
        let second = tempfile::tempdir().unwrap();
        std::fs::write(first.path().join("protoc"), "").unwrap();
        executable(&second.path().join("protoc"));
        let path_var = std::env::join_paths([first.path(), second.path()]).unwrap();

        assert_eq!(
            protoc_rerun_path(Path::new("protoc"), Some(&path_var)),
            Some(std::path::absolute(second.path().join("protoc")).unwrap())
        );
    }

    /// Astra P74 LOW: an empty PATH entry is the current directory.
    #[cfg(unix)]
    #[test]
    fn an_empty_path_entry_is_the_current_directory() {
        let dirs: Vec<PathBuf> =
            super::search_dirs(std::ffi::OsStr::new(":/usr/bin::/bin:")).collect();
        assert_eq!(
            dirs,
            ["", "/usr/bin", "", "/bin", ""]
                .map(|d| PathBuf::from(if d.is_empty() { "." } else { d }))
                .to_vec()
        );
    }

    #[test]
    fn bare_name_not_on_path_is_not_tracked() {
        let empty = tempfile::tempdir().unwrap();
        let path_var = std::env::join_paths([empty.path()]).unwrap();
        assert_eq!(
            protoc_rerun_path(Path::new("protoc"), Some(&path_var)),
            None
        );
        assert_eq!(protoc_rerun_path(Path::new("protoc"), None), None);
    }

    #[test]
    fn a_path_with_a_directory_part_is_kept_as_given() {
        for given in ["../../bin/protoc", "/opt/protoc/bin/protoc", "bin/protoc"] {
            assert_eq!(
                protoc_rerun_path(Path::new(given), None),
                Some(PathBuf::from(given))
            );
        }
    }
}
