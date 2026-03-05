# Static adversarial test cases derived directly from detector_spec.md out-of-scope
# positions.  Each case asserts that a specific pattern does NOT trigger auto-redaction
# above the confidence threshold for the named category.

from dataclasses import dataclass


@dataclass
class AdversarialCase:
    name: str
    text: str
    category_not_expected: str  # snake_case — must NOT appear above auto-redact threshold
    description: str            # matches the "Position" column in detector_spec.md


# ── Out-of-scope obfuscation patterns ────────────────────────────────────────
# These are patterns the detectors explicitly do not cover.
# Tests verify they produce no auto-redact false positives.

OOS_CASES: list[AdversarialCase] = [
    # email
    AdversarialCase(
        name="email_spelled_out",
        text="Reach us at support at company dot com for help.",
        category_not_expected="email",
        description="Spelled-out form. OOS — no regex coverage.",
    ),
    AdversarialCase(
        name="email_html_entity",
        text="Contact user&#64;domain.com for billing questions.",
        category_not_expected="email",
        description="HTML entity encoding of @. OOS — requires HTML decode pre-pass.",
    ),
    AdversarialCase(
        name="email_dot_bracket_notation",
        text="Reach john [dot] smith [at] company [dot] com for support.",
        category_not_expected="email",
        description="Bracket/word notation for dots and @. OOS — no regex coverage.",
    ),

    # ip_address
    AdversarialCase(
        name="ipv4_hex_encoded",
        text="Connecting to host 0xC0A80132 on port 5432.",
        category_not_expected="ip_address",
        description="Hex-encoded IP. OOS — requires format-aware parsing.",
    ),
    AdversarialCase(
        name="ipv4_integer_encoded",
        text="Production database host is 3232235826.",
        category_not_expected="ip_address",
        description="Integer-encoded IP. OOS — ambiguous with any large integer.",
    ),
    AdversarialCase(
        name="ipv4_octal_encoded",
        text="Host: 0300.0250.01.062",
        category_not_expected="ip_address",
        description="Octal IP notation. OOS — rare format.",
    ),

    # api_key
    AdversarialCase(
        name="api_key_base64_encoded",
        text="Set the API token to c2steGFiYzEyMw== in your environment.",
        category_not_expected="api_key",
        description="Base64-encoded key. OOS — requires decode-and-recheck.",
    ),
    AdversarialCase(
        name="api_key_hex_encoded",
        text="Token bytes (hex): 736b2d616263313233343536373839",
        category_not_expected="api_key",
        description="Hex-encoded key. OOS — ambiguous with any hex string.",
    ),
    AdversarialCase(
        name="api_key_split_across_lines",
        text=(
            "ANTHROPIC_API_KEY=sk-ant-api03-abc123def456\n"
            "ghi789jkl012mno345pqr678stu901vwx234yz"
        ),
        category_not_expected="api_key",
        description=(
            "Key split across two lines with no concatenation operator. "
            "OOS — detector works on raw text without line joining."
        ),
    ),
    AdversarialCase(
        name="api_key_unicode_homoglyph",
        text=(
            # Replace 's' with Cyrillic 'с' (U+0441), 'k' with 'к' (U+043A)
            # so the prefix looks like sk- but uses non-ASCII chars
            "ANTHROPIC_API_KEY=\u0441\u043a-ant-api03-abcdefghijklmnopqrstuvwxyz01234567"
        ),
        category_not_expected="api_key",
        description=(
            "Unicode homoglyph substitution in the key prefix. "
            "OOS — regex patterns are ASCII-only; homoglyphs break pattern matching."
        ),
    ),

    # url_credential
    AdversarialCase(
        name="url_credentials_as_query_params",
        text="GET https://api.example.com/v1/data?api_key=mysecretkey&user=admin",
        category_not_expected="url_credential",
        description="Credentials in query params, not userinfo. OOS — different pattern.",
    ),

    # credit_card
    AdversarialCase(
        name="credit_card_dot_separated",
        text="Card number 4111.1111.1111.1111 was flagged.",
        category_not_expected="credit_card",
        description="Non-standard dot separators. OOS.",
    ),
]

# ── Look-alike false positive candidates ─────────────────────────────────────
# These are NOT obfuscated — they are legitimate non-sensitive values that
# superficially resemble sensitive ones.  Detectors must not fire on these.

LOOKALIKE_CASES: list[AdversarialCase] = [
    AdversarialCase(
        name="version_string_not_ip",
        text="Requires version 1.2.3.4 or higher to run.",
        category_not_expected="ip_address",
        description="Version string resembling IPv4. Must not match.",
    ),
    AdversarialCase(
        name="loopback_not_auto_redacted",
        text="The service binds to 127.0.0.1 on port 8080 by default.",
        category_not_expected="ip_address",
        description="Loopback address. Low confidence — must not auto-redact.",
    ),
    AdversarialCase(
        name="example_dot_com_email",
        text="For testing purposes use user@example.com as the address.",
        category_not_expected="email",
        description="Placeholder domain. Low confidence — must not auto-redact.",
    ),
    AdversarialCase(
        name="placeholder_api_key",
        text="Add your key: OPENAI_API_KEY=sk-yourkey",
        category_not_expected="api_key",
        description="Obvious placeholder text. Must not auto-redact.",
    ),
    AdversarialCase(
        name="uuid_not_api_key",
        text="Correlation ID: 550e8400-e29b-41d4-a716-446655440000",
        category_not_expected="api_key",
        description="UUID. Must not match API key patterns.",
    ),
    AdversarialCase(
        name="sha256_hash_not_api_key",
        text="File checksum: a3f5c2d8e9b4c1a7f2e6d3b8c5a9f4e2d7b1c8a5f3e6d2b9c4a7f1e5d8b2c6a9",
        category_not_expected="api_key",
        description="SHA256 hash. Must not match API key patterns.",
    ),
    AdversarialCase(
        name="masked_card_not_re_detected",
        text="Card ending in **** **** **** 4242 was declined.",
        category_not_expected="credit_card",
        description="Already-masked card number. Must not be re-detected.",
    ),
    AdversarialCase(
        name="url_no_credentials",
        text="Documentation is at https://docs.company.com/api/v1/reference",
        category_not_expected="url_credential",
        description="URL with no userinfo component. Must not match.",
    ),
    AdversarialCase(
        name="at_sign_in_url_path",
        text="Profile page: https://social.example.com/users/@john/settings",
        category_not_expected="url_credential",
        description="@ in URL path, not userinfo. Must not match.",
    ),
    AdversarialCase(
        name="luhn_invalid_number",
        text="Order reference: 4111 1111 1111 1112",
        category_not_expected="credit_card",
        description="16-digit number failing Luhn. Must not match.",
    ),
]

ALL_ADVERSARIAL_CASES: list[AdversarialCase] = OOS_CASES + LOOKALIKE_CASES
