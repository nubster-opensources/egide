//! LIKE pattern escaping shared by every storage backend.
//!
//! A bound parameter protects against SQL injection but not against pattern
//! injection: `LIKE` still interprets `%` and `_` inside the bound value.
//! Callers building a pattern from user input must escape it here so both
//! backends behave identically.

/// Escape character paired with every `LIKE ... ESCAPE` clause.
pub const LIKE_ESCAPE_CHAR: char = '\\';

/// Escapes the LIKE metacharacters in a literal.
///
/// The escape character itself is escaped first, so the mapping stays
/// injective and no escaped sequence can be forged from the input.
#[must_use]
pub fn escape_like_pattern(literal: &str) -> String {
    let mut escaped = String::with_capacity(literal.len());
    for character in literal.chars() {
        if character == LIKE_ESCAPE_CHAR || character == '%' || character == '_' {
            escaped.push(LIKE_ESCAPE_CHAR);
        }
        escaped.push(character);
    }
    escaped
}

/// Builds a prefix-match pattern from a literal prefix.
#[must_use]
pub fn prefix_pattern(prefix: &str) -> String {
    let mut pattern = escape_like_pattern(prefix);
    pattern.push('%');
    pattern
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plain_literal_is_unchanged() {
        assert_eq!(escape_like_pattern("prod/app"), "prod/app");
    }

    #[test]
    fn test_wildcards_are_escaped() {
        assert_eq!(escape_like_pattern("prod_"), r"prod\_");
        assert_eq!(escape_like_pattern("100%"), r"100\%");
        assert_eq!(escape_like_pattern("a_b%c"), r"a\_b\%c");
    }

    #[test]
    fn test_escape_character_is_itself_escaped() {
        // Escaping the escape first is what keeps the mapping injective.
        assert_eq!(escape_like_pattern(r"a\b"), r"a\\b");
        assert_eq!(escape_like_pattern(r"a\_b"), r"a\\\_b");
    }

    #[test]
    fn test_prefix_pattern_appends_a_single_wildcard() {
        assert_eq!(prefix_pattern("prod_"), r"prod\_%");
        assert_eq!(prefix_pattern(""), "%");
    }
}
