//! Optional validation with an actual sing-box executable.

use std::path::Path;

use anyhow::{Context, Result, bail};
use tokio::process::Command;
use tracing::info;

use super::helpers::expand_tilde;

/// Validate generated JSON with `sing-box check`.
///
/// Schema-backed targets require an exact binary release match. The caller
/// remains responsible for selecting matching build tags.
pub async fn validate(
    binary: &str,
    json: &str,
    working_directory: &Path,
    expected_release: Option<&str>,
) -> Result<()> {
    let binary = expand_tilde(binary);
    if let Some(expected_release) = expected_release {
        validate_binary_release(&binary, expected_release).await?;
    }

    let working_directory = std::fs::canonicalize(working_directory).with_context(|| {
        format!(
            "Failed to resolve native validation directory {:?}",
            working_directory
        )
    })?;
    let temp_directory = tempfile::Builder::new()
        .prefix(".turntable-check-")
        .tempdir_in(&working_directory)
        .with_context(|| {
            format!(
                "Failed to create native validation directory in {:?}",
                working_directory
            )
        })?;
    let config_path = temp_directory.path().join("config.json");
    tokio::fs::write(&config_path, json)
        .await
        .with_context(|| {
            format!(
                "Failed to write temporary native validation config {:?}",
                config_path
            )
        })?;

    info!(
        binary,
        "Validating configuration with the configured sing-box binary"
    );
    let output = Command::new(&binary)
        .arg("check")
        .arg("--disable-color")
        .arg("-D")
        .arg(&working_directory)
        .arg("-c")
        .arg(&config_path)
        .kill_on_drop(true)
        .output()
        .await
        .with_context(|| format!("Failed to execute sing-box binary '{binary}'"))?;

    if output.status.success() {
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let details = if stderr.trim().is_empty() {
        stdout.trim()
    } else {
        stderr.trim()
    };
    bail!(
        "sing-box native validation failed with status {}: {}",
        output.status,
        if details.is_empty() {
            "no diagnostic output"
        } else {
            details
        }
    )
}

async fn validate_binary_release(binary: &str, expected_release: &str) -> Result<()> {
    let output = Command::new(binary)
        .arg("version")
        .arg("--name")
        .kill_on_drop(true)
        .output()
        .await
        .with_context(|| format!("Failed to query sing-box binary '{binary}'"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!(
            "failed to query sing-box binary version with status {}: {}",
            output.status,
            stderr.trim()
        );
    }

    let actual_release = String::from_utf8_lossy(&output.stdout);
    let actual_release = actual_release.trim();
    if actual_release != expected_release {
        bail!(
            "sing-box binary release mismatch: expected '{expected_release}', found '{actual_release}'"
        );
    }

    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    fn checker_script(directory: &Path, body: &str) -> std::path::PathBuf {
        let path = directory.join("checker.sh");
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        let mut permissions = std::fs::metadata(&path).unwrap().permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&path, permissions).unwrap();
        path
    }

    #[tokio::test]
    async fn passes_the_expected_check_arguments() {
        let directory = tempfile::tempdir().unwrap();
        let checker = checker_script(
            directory.path(),
            r#"if [ "$1" = "version" ]; then
  echo "1.14.0-beta.2"
  exit 0
fi
test "$1" = "check" &&
test "$2" = "--disable-color" &&
test "$3" = "-D" &&
test -d "$4" &&
test "$5" = "-c" &&
test -f "$6""#,
        );
        validate(
            checker.to_str().unwrap(),
            "{}",
            directory.path(),
            Some("1.14.0-beta.2"),
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn reports_a_failed_checker_diagnostic() {
        let directory = tempfile::tempdir().unwrap();
        let checker = checker_script(
            directory.path(),
            r#"echo "invalid outbound reference" >&2
exit 2"#,
        );
        let error = validate(checker.to_str().unwrap(), "{}", directory.path(), None)
            .await
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("sing-box native validation failed")
        );
        assert!(error.to_string().contains("invalid outbound reference"));
    }

    #[tokio::test]
    async fn rejects_a_mismatched_schema_release() {
        let directory = tempfile::tempdir().unwrap();
        let checker = checker_script(
            directory.path(),
            r#"if [ "$1" = "version" ]; then
  echo "1.14.0-beta.1"
  exit 0
fi
exit 0"#,
        );
        let error = validate(
            checker.to_str().unwrap(),
            "{}",
            directory.path(),
            Some("1.14.0-beta.2"),
        )
        .await
        .unwrap_err();

        assert!(error.to_string().contains("release mismatch"));
        assert!(error.to_string().contains("1.14.0-beta.1"));
    }
}
