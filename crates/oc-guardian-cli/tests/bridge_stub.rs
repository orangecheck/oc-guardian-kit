//! The portal bridge is not built. Each `oc-guardian bridge` command says so
//! and changes nothing, rather than promising a release that already shipped
//! without it.

use std::path::PathBuf;
use std::process::Command;

struct Sandbox(PathBuf);

impl Sandbox {
    fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("oc-guardian-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Sandbox(dir)
    }

    /// stdout of the kit run with an empty home and its own config dir.
    fn kit_stdout(&self, args: &[&str]) -> String {
        String::from_utf8_lossy(&self.kit(args).stdout).into_owned()
    }

    /// stderr of the kit run with an empty home and its own config dir.
    fn kit_stderr(&self, args: &[&str]) -> String {
        String::from_utf8_lossy(&self.kit(args).stderr).into_owned()
    }

    fn kit(&self, args: &[&str]) -> std::process::Output {
        let home = self.0.join("home");
        let out = Command::new(env!("CARGO_BIN_EXE_oc-guardian"))
            .env("OC_GUARDIAN_CONFIG_DIR", self.0.join("guardian"))
            .env("HOME", &home)
            .env("XDG_CONFIG_HOME", home.join(".config"))
            .env_remove("RUST_LOG")
            .args(args)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        out
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn every_bridge_command_says_it_is_not_built_and_changes_nothing() {
    let sb = Sandbox::new("bridge");
    for (args, says) in [
        (&["bridge", "enable"][..], "nothing changed"),
        (
            &["bridge", "allow", "federation.join"][..],
            "no allowlist was written",
        ),
        (&["bridge", "disable"][..], "nothing to turn off"),
        (&["bridge", "status"][..], "no action is allowed"),
    ] {
        let err = sb.kit_stderr(args);
        assert!(err.contains("not built yet"), "{args:?}:\n{err}");
        assert!(err.contains(says), "{args:?} should say {says:?}:\n{err}");
        assert!(
            !err.contains("v0.2.0"),
            "{args:?} promises a shipped release:\n{err}"
        );
    }
    // Nothing was written anywhere: not the config dir, not $HOME.
    let left: Vec<_> = std::fs::read_dir(&sb.0)
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .collect();
    assert!(left.is_empty(), "the bridge commands wrote {left:?}");
}

#[test]
fn the_help_says_the_bridge_is_not_built() {
    let sb = Sandbox::new("bridge-help");
    for args in [&["--help"][..], &["bridge", "--help"][..]] {
        let out = sb.kit_stdout(args);
        assert!(out.contains("not built yet"), "{args:?}:\n{out}");
        for promise in [
            "opt in to portal-mediated",
            "Opt in to portal-mediated",
            "Allowlist a specific portal action",
            "Show the current allowlist",
        ] {
            assert!(
                !out.contains(promise),
                "{args:?} still says {promise:?}:\n{out}"
            );
        }
    }
}
