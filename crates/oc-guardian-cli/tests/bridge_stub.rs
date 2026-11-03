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

    /// stderr of the kit run with an empty home and its own config dir.
    fn kit_stderr(&self, args: &[&str]) -> String {
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
        String::from_utf8_lossy(&out.stderr).into_owned()
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
    for args in [
        &["bridge", "enable"][..],
        &["bridge", "allow", "federation.join"][..],
        &["bridge", "disable"][..],
        &["bridge", "status"][..],
    ] {
        let err = sb.kit_stderr(args);
        assert!(err.contains("not built yet"), "{args:?}:\n{err}");
        assert!(
            !err.contains("v0.2.0"),
            "{args:?} promises a shipped release:\n{err}"
        );
    }
    // Nothing was written: no config dir appeared.
    assert!(!sb.0.join("guardian").exists());
}
