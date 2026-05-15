use crate::cli::silent_cli_error;
use crate::design::render::error_block;

const CONTROL_SOCKET_EXPLANATION: &str = "The daemon control socket is mode 0660 root:permitlayer-clients, so your user account already has access.";

pub(crate) fn should_refuse_root_shell(
    effective_uid: u32,
    sudo_user: Option<&str>,
    allow_root: bool,
) -> bool {
    effective_uid == 0 && sudo_user.is_some_and(|user| !user.trim().is_empty()) && !allow_root
}

pub(crate) fn root_shell_refusal_message(verb: &str, command_hint: &str) -> String {
    format!(
        "refusing to {verb} as root (uid 0). Re-run from your user shell: '{command_hint}' (no sudo). {CONTROL_SOCKET_EXPLANATION}"
    )
}

pub(crate) fn ensure_not_sudo_root_shell_with(
    verb: &str,
    command_hint: &str,
    allow_root: bool,
    effective_uid: u32,
    sudo_user: Option<&str>,
) -> anyhow::Result<()> {
    if should_refuse_root_shell(effective_uid, sudo_user, allow_root) {
        let message = root_shell_refusal_message(verb, command_hint);
        eprint!("{}", error_block("cli.refusing_root_shell", &message, command_hint, None,));
        return Err(silent_cli_error(message));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refuses_effective_root_with_sudo_user_unless_allowed() {
        assert!(should_refuse_root_shell(0, Some("austinlowry"), false));
        assert!(!should_refuse_root_shell(0, Some("austinlowry"), true));
        assert!(!should_refuse_root_shell(501, Some("austinlowry"), false));
        assert!(!should_refuse_root_shell(0, None, false));
        assert!(!should_refuse_root_shell(0, Some("   "), false));
    }

    #[test]
    fn root_shell_refusal_message_names_user_shell_and_socket_mode() {
        let message = root_shell_refusal_message(
            "register agent",
            "agentsso agent register openclaw --policy gmail-read-only",
        );
        assert!(message.contains("refusing to register agent as root (uid 0)"));
        assert!(message.contains("Re-run from your user shell"));
        assert!(message.contains("no sudo"));
        assert!(message.contains("0660 root:permitlayer-clients"));
    }
}
