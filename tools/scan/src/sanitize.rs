//! Sanitiser for feed text. Feed text is untrusted data: before it is stored
//! in a report it has control characters stripped and whitespace collapsed,
//! so it cannot smuggle formatting or control sequences downstream.

/// Strip control characters and collapse all whitespace runs to a single
/// space, trimming the ends.
pub fn sanitize(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut pending_space = false;
    for c in input.chars() {
        if c.is_control() {
            // Control chars are stripped entirely; if the stripped char was
            // whitespace-like, collapse it into the pending separator.
            if c.is_whitespace() {
                pending_space = !out.is_empty();
            }
            continue;
        }
        if c.is_whitespace() {
            pending_space = !out.is_empty();
            continue;
        }
        if pending_space {
            out.push(' ');
            pending_space = false;
        }
        out.push(c);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_control_and_collapses_whitespace() {
        assert_eq!(sanitize("  hello\u{00}\u{01} world\n\t again  "), "hello world again");
    }

    #[test]
    fn empty_and_all_control() {
        assert_eq!(sanitize(""), "");
        assert_eq!(sanitize("\u{00}\u{07}\n\r\t"), "");
    }

    #[test]
    fn keeps_normal_text() {
        assert_eq!(sanitize("CVE-2021-44228: Log4Shell"), "CVE-2021-44228: Log4Shell");
    }
}
