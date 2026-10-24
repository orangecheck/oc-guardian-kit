//! Every command reads the config dir that `--config-dir` (or
//! `OC_GUARDIAN_CONFIG_DIR`) names, and logs go to stderr, so a command's
//! stdout is only its output.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

struct Sandbox(PathBuf);

impl Sandbox {
    fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("oc-guardian-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Sandbox(dir)
    }

    /// The kit with an empty home, so the platform default dir is never the operator's own.
    fn kit(&self, args: &[&str], config_env: Option<&Path>) -> Output {
        let home = self.0.join("home");
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_oc-guardian"));
        cmd.env_remove("OC_GUARDIAN_CONFIG_DIR")
            .env("HOME", &home)
            .env("XDG_CONFIG_HOME", home.join(".config"))
            .args(args);
        if let Some(dir) = config_env {
            cmd.env("OC_GUARDIAN_CONFIG_DIR", dir);
        }
        let out = cmd.output().unwrap();
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

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

#[test]
fn every_command_reads_the_config_dir_init_wrote() {
    let sb = Sandbox::new("cfg");
    let dir = sb.0.join("guardian-1");
    let key = sb.0.join("operator.key");
    let (dir_s, key_s) = (dir.to_str().unwrap(), key.to_str().unwrap());

    sb.kit(&["init", "--key-file", key_s, "--config-dir", dir_s], None);
    let id = std::fs::read_to_string(dir.join("operator.id")).unwrap();

    for out in [
        sb.kit(&["--config-dir", dir_s, "status"], None),
        sb.kit(&["status", "--config-dir", dir_s], None),
        sb.kit(&["status"], Some(&dir)),
    ] {
        let text = stdout(&out);
        assert!(
            text.contains(id.trim()),
            "status did not read {dir_s}:\n{text}"
        );
        assert!(!text.contains("NOT INITIALIZED"), "{text}");
    }

    // Without it, the empty platform default holds no identity.
    assert!(stdout(&sb.kit(&["status"], None)).contains("NOT INITIALIZED"));
}

#[test]
fn logs_go_to_stderr() {
    let sb = Sandbox::new("logs");
    let out = sb.kit(&["status"], None);
    assert!(String::from_utf8_lossy(&out.stderr).contains("done"));
    assert!(!stdout(&out).contains("done"), "{}", stdout(&out));
}
