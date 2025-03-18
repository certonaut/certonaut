use std::collections::HashMap;
use std::ffi::{OsStr, OsString};
use std::io;
use std::process::ExitStatus;
use tokio::process::Command;

/// Runs a shell command with environment variables.
///
/// # Arguments
/// * `command` - The command to execute.
/// * `env_vars` - A map of environment variables to set.
///
/// # Returns
/// `ExitStatus` of the executed command.
///
/// # Errors
/// When the command cannot launch, or the command's status cannot be determined.
pub async fn run_shell_command<S: std::hash::BuildHasher>(
    command: &OsStr,
    env_vars: HashMap<OsString, OsString, S>,
) -> io::Result<ExitStatus> {
    let shell = if cfg!(target_os = "windows") {
        "cmd.exe"
    } else {
        "/bin/sh"
    };
    let shell_arg = if cfg!(target_os = "windows") {
        "/C"
    } else {
        "-c"
    };

    let mut cmd = Command::new(shell);
    cmd.arg(shell_arg).arg(command);

    cmd.stdout(std::process::Stdio::inherit());
    cmd.stderr(std::process::Stdio::inherit());

    for (key, value) in env_vars {
        cmd.env(key, value);
    }

    cmd.status().await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_run_shell_command() {
        let status = run_shell_command("echo Hello, World!".as_ref(), HashMap::new())
            .await
            .expect("Failed to execute command");
        assert!(status.success());
    }
}
