//! Redaction helpers for diagnostics.
//!
//! Keystone's debug output describes signed requests, which contain the
//! authorization header and the certificate. These helpers keep that output
//! useful without printing the parts that grant access.

/// The marker substituted for withheld values.
pub const REDACTED: &str = "<redacted>";

/// Header names whose values are never printed in full.
const SENSITIVE_HEADERS: &[&str] = &["authorization", "x-amz-security-token"];

/// Whether a header's value must be redacted before display.
pub fn is_sensitive_header(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    SENSITIVE_HEADERS.contains(&name.as_str())
}

/// Render a header for diagnostics, redacting the value when sensitive.
pub fn header_for_display(name: &str, value: &str) -> String {
    if is_sensitive_header(name) {
        format!("{name}: {REDACTED}")
    } else {
        format!("{name}: {value}")
    }
}

/// Show only enough of a long opaque value to correlate it across logs.
///
/// Applied to certificate bodies and signatures: the prefix identifies which
/// value was used without disclosing it.
pub fn truncate_opaque(value: &str) -> String {
    const KEEP: usize = 12;
    if value.len() <= KEEP {
        return REDACTED.to_string();
    }
    format!("{}... ({} bytes, redacted)", &value[..KEEP], value.len())
}

/// Redact the `Signature=` component of an AWS authorization header.
///
/// The credential scope and signed-header list are the parts worth seeing when
/// comparing against the official helper; the signature itself is not.
pub fn redact_authorization(header: &str) -> String {
    match header.find("Signature=") {
        Some(index) => format!("{}Signature={REDACTED}", &header[..index]),
        None => header.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authorization_headers_are_recognized_regardless_of_case() {
        assert!(is_sensitive_header("Authorization"));
        assert!(is_sensitive_header("authorization"));
        assert!(!is_sensitive_header("x-amz-date"));
        assert!(!is_sensitive_header("x-amz-x509"));
    }

    #[test]
    fn sensitive_header_values_are_withheld_but_names_are_kept() {
        let rendered = header_for_display("Authorization", "AWS4-X509-ECDSA-SHA256 Credential=1/x");
        assert_eq!(rendered, format!("Authorization: {REDACTED}"));
        assert!(!rendered.contains("Credential"));
    }

    #[test]
    fn ordinary_header_values_are_shown() {
        assert_eq!(
            header_for_display("x-amz-date", "20260726T011500Z"),
            "x-amz-date: 20260726T011500Z"
        );
    }

    #[test]
    fn authorization_redaction_keeps_the_diagnosable_parts() {
        let header = "AWS4-X509-ECDSA-SHA256 Credential=4837201/20260726/us-east-1/rolesanywhere/\
                      aws4_request, SignedHeaders=content-type;host;x-amz-date, Signature=deadbeef";
        let redacted = redact_authorization(header);
        assert!(redacted.contains("Credential=4837201"));
        assert!(redacted.contains("SignedHeaders=content-type;host;x-amz-date"));
        assert!(!redacted.contains("deadbeef"));
        assert!(redacted.ends_with(REDACTED));
    }

    #[test]
    fn a_header_without_a_signature_is_left_alone() {
        assert_eq!(redact_authorization("Bearer abc"), "Bearer abc");
    }

    #[test]
    fn opaque_values_are_truncated_and_labeled() {
        let truncated = truncate_opaque(&"a".repeat(100));
        assert!(truncated.starts_with("aaaaaaaaaaaa..."));
        assert!(truncated.contains("100 bytes"));
        // Short values reveal proportionally too much, so they are dropped entirely.
        assert_eq!(truncate_opaque("short"), REDACTED);
    }
}
