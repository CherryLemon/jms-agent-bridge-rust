//! The exact local guard the bridge has always shipped, plus a read-only diagnosis.
//!
//! `check` never returns an executable replacement for the caller's script. When a
//! script matches, the caller must pass `allow_dangerous` (which acknowledges only
//! this local guard). The Python implementation additionally proves that a match
//! sits inside a literal Python heredoc comment and exempts exactly that case; this
//! port keeps the original substring test and therefore fails closed — it can refuse
//! a script the Python guard would allow, never the reverse.

use serde_json::{json, Value};

pub const DANGEROUS_PATTERNS: [&str; 8] = [
    "rm -rf /",
    "mkfs",
    "dd if=",
    ":(){:|:&};:",
    "shutdown",
    "reboot",
    "> /dev/sda",
    "chmod -R 777 /",
];

/// Python `" ".join(text.split())`: collapse all whitespace runs to one space.
pub fn flatten(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

pub fn matches(text: &str) -> Vec<&'static str> {
    let flat = flatten(text);
    DANGEROUS_PATTERNS
        .iter()
        .copied()
        .filter(|pattern| flat.contains(pattern))
        .collect()
}

pub fn is_dangerous(script: &str) -> bool {
    !matches(script).is_empty()
}

/// Advisory decision; contains no executable text and performs no work.
pub fn check(script: &str) -> Value {
    let original = matches(script);
    let blocked = !original.is_empty();
    json!({
        "blocked": blocked,
        "original_patterns": original,
        "effective_patterns": original,
        "ignored_comment_matches": [],
        "analysis": if blocked { "original_denial_retained" } else { "no_original_match" },
        "execution_performed": false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flatten_collapses_whitespace_like_python() {
        assert_eq!(flatten("  rm   -rf\n\t/ "), "rm -rf /");
        assert_eq!(flatten(""), "");
    }

    #[test]
    fn matches_are_reported_once_in_pattern_order() {
        let found = matches("echo hi; rm -rf /; mkfs.ext4 /dev/sdb");
        assert_eq!(found, vec!["rm -rf /", "mkfs"]);
    }

    #[test]
    fn check_is_read_only_and_blocks_known_patterns() {
        let decision = check("reboot now");
        assert_eq!(decision["blocked"], true);
        assert_eq!(decision["execution_performed"], false);
        assert_eq!(decision["analysis"], "original_denial_retained");

        let clean = check("ls -la /tmp");
        assert_eq!(clean["blocked"], false);
        assert_eq!(clean["analysis"], "no_original_match");
        assert_eq!(clean["ignored_comment_matches"], json!([]));
    }

    #[test]
    fn split_across_lines_is_still_detected() {
        // The guard flattens first, so a line break cannot hide the pattern.
        assert!(is_dangerous("rm -rf\n/\n"));
    }
}
