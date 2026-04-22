//! Error types for the scrub engine.

/// Errors produced by the scrubbing pipeline.
#[derive(thiserror::Error, Debug)]
#[non_exhaustive]
pub enum ScrubError {
    /// Input bytes are not valid UTF-8.
    #[error("input is not valid UTF-8")]
    InvalidUtf8,

    /// A regex pattern failed to compile.
    #[error("regex pattern failed to compile: {pattern}")]
    RegexCompile {
        /// The pattern string that failed.
        pattern: String,
        /// The underlying regex error.
        #[source]
        source: regex::Error,
    },

    /// The aho-corasick automaton could not be built.
    #[error("aho-corasick automaton build failed")]
    AhoCorasickBuild {
        /// The underlying build error.
        #[source]
        source: aho_corasick::BuildError,
    },

    /// Internal state inconsistency (should never occur in production).
    #[error("engine internal state is poisoned")]
    EnginePoisoned,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let e = ScrubError::InvalidUtf8;
        assert_eq!(e.to_string(), "input is not valid UTF-8");

        let bad_pattern = "("; // intentionally invalid regex
        let e = ScrubError::RegexCompile {
            pattern: bad_pattern.to_string(),
            source: regex::Regex::new(bad_pattern).unwrap_err(),
        };
        assert!(e.to_string().contains("regex pattern failed to compile"));

        let e = ScrubError::EnginePoisoned;
        assert_eq!(e.to_string(), "engine internal state is poisoned");
    }
}
