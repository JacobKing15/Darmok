# Faker-based synthetic test case generator — produces realistic prompts with
# embedded entities and full ground truth labels for precision/recall evaluation.
# No real data anywhere in this file.

from __future__ import annotations

import base64
import json
import random
import secrets
import string
from datetime import datetime, timedelta

from faker import Faker

from tests.harness import GroundTruthEntity, TestCase

fake = Faker()
rng = random.Random()  # unseeded — different values per run, reproducible with rng.seed()


# ── Fake value generators ─────────────────────────────────────────────────────


def _fake_openai_key() -> str:
    chars = string.ascii_letters + string.digits
    return "sk-" + "".join(secrets.choice(chars) for _ in range(48))


def _fake_github_pat() -> str:
    chars = string.ascii_letters + string.digits
    return "ghp_" + "".join(secrets.choice(chars) for _ in range(36))


def _fake_aws_key_id() -> str:
    chars = string.ascii_uppercase + string.digits
    return "AKIA" + "".join(secrets.choice(chars) for _ in range(16))


def _fake_stripe_key() -> str:
    chars = string.ascii_letters + string.digits
    return "sk_live_" + "".join(secrets.choice(chars) for _ in range(24))


def _fake_api_key() -> str:
    return rng.choice([_fake_openai_key, _fake_github_pat, _fake_aws_key_id, _fake_stripe_key])()


def _fake_jwt() -> str:
    header = base64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').rstrip(b"=").decode()
    payload_data = {
        "sub": f"user_{rng.randint(1000, 9999)}",
        "iat": 1700000000,
        "exp": 1700086400,
    }
    payload = base64.urlsafe_b64encode(json.dumps(payload_data).encode()).rstrip(b"=").decode()
    signature = base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode()
    return f"{header}.{payload}.{signature}"


def _fake_private_key() -> str:
    # Structurally valid PEM format — random bytes, not a real key
    body = base64.b64encode(secrets.token_bytes(1200)).decode()
    lines = [body[i : i + 64] for i in range(0, len(body), 64)]
    return (
        "-----BEGIN RSA PRIVATE KEY-----\n"
        + "\n".join(lines)
        + "\n-----END RSA PRIVATE KEY-----"
    )


def _fake_url_with_credentials() -> str:
    user = fake.user_name()
    password = secrets.token_urlsafe(12)
    host = f"db-{fake.word()}.internal"
    scheme, port = rng.choice([
        ("postgresql", 5432),
        ("mysql", 3306),
        ("mongodb", 27017),
    ])
    db = fake.word()
    return f"{scheme}://{user}:{password}@{host}:{port}/{db}"


def _luhn_checksum(digits: list[int]) -> int:
    total = sum(digits[-1::-2])
    for d in digits[-2::-2]:
        total += sum(divmod(d * 2, 10))
    return total % 10


def _make_luhn_valid(prefix: str, total_length: int) -> str:
    """Generate a Luhn-valid number string with the given prefix and total digit length."""
    fill_length = total_length - len(prefix) - 1  # -1 for check digit
    num = prefix + "".join(str(rng.randint(0, 9)) for _ in range(fill_length))
    partial = [int(d) for d in num + "0"]
    check = (10 - _luhn_checksum(partial)) % 10
    return num + str(check)


def _fake_visa() -> str:
    raw = _make_luhn_valid("4", 16)
    return f"{raw[:4]} {raw[4:8]} {raw[8:12]} {raw[12:]}"


def _fake_mastercard() -> str:
    prefix = str(rng.randint(51, 55))
    raw = _make_luhn_valid(prefix, 16)
    return f"{raw[:4]} {raw[4:8]} {raw[8:12]} {raw[12:]}"


def _fake_credit_card() -> str:
    return rng.choice([_fake_visa, _fake_mastercard])()


def _fake_timestamp() -> str:
    dt = datetime.now() - timedelta(seconds=rng.randint(0, 86400))
    return dt.strftime("[%Y-%m-%d %H:%M:%S]")


# ── Per-category template banks ───────────────────────────────────────────────
# Each template is a callable (value) -> (text, ground_truth_value).
# ground_truth_value is what we expect the detector to return — usually == value.

_EMAIL_TEMPLATES = [
    lambda e: (f"{_fake_timestamp()} Authentication failed for user {e} from {fake.ipv4_private()}", e),
    lambda e: (f'ADMIN_EMAIL = "{e}"', e),
    lambda e: (f"# Send deployment alerts to {e}", e),
    lambda e: (f"Please contact {e} for access requests to the production environment.", e),
    lambda e: (f"No account found for email address {e}. Verify the directory.", e),
    lambda e: (f"Reply-To: {e}", e),
    lambda e: (f"[ALERT] Disk usage 95% — notify: {e}", e),
]

_IPV4_TEMPLATES = [
    lambda ip: (f"{_fake_timestamp()} Connection from {ip} rejected by firewall rule 42", ip),
    lambda ip: (f'DB_HOST = "{ip}"', ip),
    lambda ip: (f"Connecting to database at {ip}:{rng.randint(1024, 65535)}", ip),
    lambda ip: (f"FATAL: Could not connect to server at {ip}, connection refused (errno 111)", ip),
    lambda ip: (f"upstream backend {{ server {ip}:{rng.randint(8000, 9000)}; }}", ip),
    lambda ip: (f"ssh deploy@{ip} -p 22 -i ~/.ssh/deploy_key", ip),
    lambda ip: (f"[NGINX] upstream {ip} is unreachable, removing from pool", ip),
]

_API_KEY_TEMPLATES = [
    lambda k: (f"OPENAI_API_KEY={k}", k),
    lambda k: (f'client = OpenAI(api_key="{k}")', k),
    lambda k: (f"X-API-Key: {k}", k),
    lambda k: (f"api_key: {k}", k),
    lambda k: (f"export STRIPE_SECRET_KEY={k}", k),
    lambda k: (f'headers = {{"Authorization": "Bearer {k}"}}', k),
    lambda k: (f"token: {k}", k),
]

_JWT_TEMPLATES = [
    lambda j: (f"Authorization: Bearer {j}", j),
    lambda j: (f'token = "{j}"', j),
    lambda j: (f"{_fake_timestamp()} [INFO] Processing request with JWT {j}", j),
    lambda j: (f"Set-Cookie: auth={j}; HttpOnly; Secure; SameSite=Strict", j),
    lambda j: (f"curl -H 'Authorization: Bearer {j}' https://api.internal/v1/users", j),
]

_PRIVATE_KEY_TEMPLATES = [
    lambda k: (f'PRIVATE_KEY="{k}"', k),
    lambda k: (f"Loaded private key:\n{k}", k),
    lambda k: (k, k),  # bare PEM block
    lambda k: (f"# DO NOT COMMIT\nSSH_PRIVATE_KEY={k}", k),
    lambda k: (f'private_key = """\n{k}\n"""', k),
]

_URL_CRED_TEMPLATES = [
    lambda u: (u, u),
    lambda u: (f"DATABASE_URL={u}", u),
    lambda u: (f'conn = create_engine("{u}")', u),
    lambda u: (f"db_url: {u}", u),
    lambda u: (f"{_fake_timestamp()} [INFO] Establishing connection to {u}", u),
    lambda u: (f"export DATABASE_URL='{u}'", u),
]

_CC_TEMPLATES = [
    lambda c: (f"Customer reported charge issue on card {c}", c),
    lambda c: (f"Transaction declined for card number {c}. Error: insufficient funds.", c),
    lambda c: (f"Billing info: card {c}, exp 12/27, CVV provided", c),
    lambda c: (f"{_fake_timestamp()} [WARN] Payment failed — card {c} returned code 51", c),
    lambda c: (f"can you refund {c}? customer says it was charged twice", c),
]


# ── Per-category generators ────────────────────────────────────────────────────


def generate_email_cases(n: int) -> list[TestCase]:
    cases = []
    templates = _EMAIL_TEMPLATES
    for i in range(n):
        email = fake.email()
        text, value = templates[i % len(templates)](email)
        cases.append(TestCase(
            name=f"email_{i:03d}",
            prompt_type="mixed",
            text=text,
            entities=[GroundTruthEntity(value=value, category="email")],
        ))
    return cases


def generate_ipv4_cases(n: int) -> list[TestCase]:
    cases = []
    templates = _IPV4_TEMPLATES
    for i in range(n):
        # Mix of private and public IPs; both should be detected
        ip = rng.choice([fake.ipv4_private, fake.ipv4_public])()
        text, value = templates[i % len(templates)](ip)
        cases.append(TestCase(
            name=f"ip_address_{i:03d}",
            prompt_type="devops_log" if i % 2 == 0 else "config",
            text=text,
            entities=[GroundTruthEntity(value=value, category="ip_address")],
        ))
    return cases


def generate_api_key_cases(n: int) -> list[TestCase]:
    cases = []
    templates = _API_KEY_TEMPLATES
    for i in range(n):
        key = _fake_api_key()
        text, value = templates[i % len(templates)](key)
        cases.append(TestCase(
            name=f"api_key_{i:03d}",
            prompt_type="code_snippet" if i % 2 == 0 else "config",
            text=text,
            entities=[GroundTruthEntity(value=value, category="api_key")],
        ))
    return cases


def generate_jwt_cases(n: int) -> list[TestCase]:
    cases = []
    templates = _JWT_TEMPLATES
    for i in range(n):
        jwt = _fake_jwt()
        text, value = templates[i % len(templates)](jwt)
        cases.append(TestCase(
            name=f"jwt_{i:03d}",
            prompt_type="mixed",
            text=text,
            entities=[GroundTruthEntity(value=value, category="jwt")],
        ))
    return cases


def generate_private_key_cases(n: int) -> list[TestCase]:
    cases = []
    templates = _PRIVATE_KEY_TEMPLATES
    for i in range(n):
        key = _fake_private_key()
        text, value = templates[i % len(templates)](key)
        cases.append(TestCase(
            name=f"private_key_{i:03d}",
            prompt_type="config",
            text=text,
            entities=[GroundTruthEntity(value=value, category="private_key")],
        ))
    return cases


def generate_url_credential_cases(n: int) -> list[TestCase]:
    cases = []
    templates = _URL_CRED_TEMPLATES
    for i in range(n):
        url = _fake_url_with_credentials()
        text, value = templates[i % len(templates)](url)
        cases.append(TestCase(
            name=f"url_credential_{i:03d}",
            prompt_type="config",
            text=text,
            entities=[GroundTruthEntity(value=value, category="url_credential")],
        ))
    return cases


def generate_credit_card_cases(n: int) -> list[TestCase]:
    cases = []
    templates = _CC_TEMPLATES
    for i in range(n):
        cc = _fake_credit_card()
        text, value = templates[i % len(templates)](cc)
        cases.append(TestCase(
            name=f"credit_card_{i:03d}",
            prompt_type="support_email",
            text=text,
            entities=[GroundTruthEntity(value=value, category="credit_card")],
        ))
    return cases


def generate_mixed_cases(n: int) -> list[TestCase]:
    """
    Multi-entity prompts — realistic DevOps/incident scenarios with 3 entity
    types in a single prompt.  Tests for cross-detector interference.
    """
    cases = []
    for i in range(n):
        email = fake.email()
        ip = fake.ipv4_private()
        key = _fake_api_key()
        text = (
            f"Production incident — {_fake_timestamp()}\n"
            f"Alert sent to: {email}\n"
            f"Affected server: {ip}:8080\n"
            f"Service API key in use: {key}\n"
            f"Please investigate and rotate credentials immediately."
        )
        cases.append(TestCase(
            name=f"mixed_{i:03d}",
            prompt_type="mixed",
            text=text,
            entities=[
                GroundTruthEntity(value=email, category="email"),
                GroundTruthEntity(value=ip, category="ip_address"),
                GroundTruthEntity(value=key, category="api_key"),
            ],
        ))
    return cases


def generate_negative_cases(n: int = 100) -> list[TestCase]:
    """
    Prompts containing no sensitive data — used for precision testing.
    Any detection above the auto-redact threshold in these cases is a false positive.
    Ground truth entities list is empty for all cases.

    Coverage: documentation, prose, placeholder values, loopback IPs, version
    strings, public reference content, and other common false-positive surfaces.
    """
    cases: list[TestCase] = []

    static_negatives = [
        # Documentation prose
        ("neg_docs_api_overview",
         "This guide explains how to authenticate with the REST API using OAuth 2.0 tokens.",
         "code_snippet"),
        ("neg_docs_version",
         "Compatible with library version 1.2.3.4 or above. Not compatible with 0.9.x.",
         "code_snippet"),
        ("neg_docs_uuid_concept",
         "Each request is assigned a correlation ID in UUID format for distributed tracing.",
         "code_snippet"),
        # Placeholder / example values
        ("neg_placeholder_email",
         "# Example: send results to user@example.com",
         "code_snippet"),
        ("neg_placeholder_email2",
         "Replace YOUR_EMAIL@domain.com with your actual address.",
         "code_snippet"),
        ("neg_placeholder_key",
         "Set OPENAI_API_KEY=sk-yourkey in your .env file before running.",
         "config"),
        ("neg_placeholder_key2",
         "export GITHUB_TOKEN=<your_token_here>",
         "config"),
        ("neg_placeholder_url",
         "DATABASE_URL=postgres://user:password@localhost/dbname",
         "config"),
        ("neg_placeholder_url2",
         "mongodb://username:password@host:port/database",
         "config"),
        # Loopback and well-known addresses
        ("neg_loopback",
         "The server binds to 127.0.0.1 on port 8080 by default.",
         "config"),
        ("neg_loopback2",
         "Use localhost (127.0.0.1) for local development; never expose to 0.0.0.0 in prod.",
         "code_snippet"),
        ("neg_broadcast",
         "Packets sent to 255.255.255.255 are broadcast to all hosts on the local network.",
         "mixed"),
        # Version strings that look like IPs
        ("neg_version_string",
         "Requires version 1.2.3.4 or higher to run this feature.",
         "mixed"),
        ("neg_version_string2",
         "Tested with Python 3.11.0 and 3.12.1; older versions are not supported.",
         "mixed"),
        # UUIDs (must not match API key patterns)
        ("neg_uuid",
         "Correlation ID: 550e8400-e29b-41d4-a716-446655440000",
         "devops_log"),
        ("neg_uuid2",
         "Request trace: f47ac10b-58cc-4372-a567-0e02b2c3d479",
         "devops_log"),
        # SHA / MD5 hashes
        ("neg_sha256",
         "File checksum: a3f5c2d8e9b4c1a7f2e6d3b8c5a9f4e2d7b1c8a5f3e6d2b9c4a7f1e5d8b2c6a9",
         "code_snippet"),
        ("neg_md5",
         "MD5: d41d8cd98f00b204e9800998ecf8427e",
         "code_snippet"),
        # URLs without credentials
        ("neg_url_no_creds",
         "Documentation is at https://docs.company.com/api/v1/reference",
         "mixed"),
        ("neg_url_no_creds2",
         "POST https://api.example.com/v2/events HTTP/1.1",
         "mixed"),
        ("neg_url_at_in_path",
         "Profile page: https://social.example.com/users/@john/settings",
         "mixed"),
        # Masked card numbers
        ("neg_masked_card",
         "Card ending in **** **** **** 4242 was charged $49.99.",
         "support_email"),
        ("neg_masked_card2",
         "Last 4 digits of the card on file: 1234",
         "support_email"),
        # Luhn-invalid numbers
        ("neg_luhn_invalid",
         "Order reference number: 4111 1111 1111 1112",
         "support_email"),
        # Generic prose with no sensitive data
        ("neg_prose_infra",
         "Our infrastructure uses auto-scaling groups across three availability zones.",
         "mixed"),
        ("neg_prose_git",
         "git checkout -b feature/add-login-flow && git push origin HEAD",
         "code_snippet"),
        ("neg_prose_docker",
         "docker build -t myapp:latest . && docker push registry.company.com/myapp:latest",
         "code_snippet"),
        ("neg_prose_kubectl",
         "kubectl apply -f deployment.yaml --namespace production",
         "code_snippet"),
        ("neg_prose_npm",
         "npm install --save-dev eslint prettier typescript",
         "code_snippet"),
        # Example.com domains that must not fire
        ("neg_example_domain",
         "For testing purposes use admin@example.com as the address.",
         "code_snippet"),
        ("neg_example_domain2",
         "SMTP server: mail.example.org, From: noreply@test.com",
         "config"),
    ]

    for name, text, prompt_type in static_negatives:
        cases.append(TestCase(
            name=name,
            prompt_type=prompt_type,
            text=text,
            entities=[],  # nothing should be detected above threshold
        ))

    # Fill remaining cases with Faker-generated neutral prose
    prose_templates = [
        lambda: f"The {fake.bs()} initiative will be reviewed by {fake.job()} teams next quarter.",
        lambda: f"Deploy the {fake.word()} service to the {fake.word()}-cluster region.",
        lambda: f"Error code {rng.randint(1000, 9999)}: {fake.sentence()}",
        lambda: f"Ticket #{rng.randint(10000, 99999)}: {fake.sentence()} Assigned to on-call.",
        lambda: f"# {fake.catch_phrase()}\n# This module handles {fake.bs()}.",
        lambda: f"terraform plan -var 'region={fake.word()}' -var 'env=staging'",
        lambda: f"helm upgrade {fake.word()}-app ./chart --set replicas={rng.randint(2, 8)}",
        lambda: f"Scaling down deployment/{fake.word()}-api from 4 to 2 replicas.",
        lambda: f"Retry attempt {rng.randint(1, 5)} of 5 for job {fake.word()}-processor.",
        lambda: f"Cache hit rate: {rng.randint(60, 99)}%. Eviction policy: LRU.",
    ]

    generated = len(cases)
    while len(cases) < n:
        i = len(cases)
        template = prose_templates[i % len(prose_templates)]
        cases.append(TestCase(
            name=f"neg_{i:03d}",
            prompt_type="mixed",
            text=template(),
            entities=[],
        ))

    return cases[:n]


# ── Main entry point ──────────────────────────────────────────────────────────


def generate_all(n_per_category: int = 50) -> list[TestCase]:
    """
    Generate the full synthetic test suite.
    Returns n_per_category cases for each entity category, mixed prompts,
    and ~100 negative cases (no sensitive data) for precision measurement.
    """
    cases: list[TestCase] = []
    cases.extend(generate_email_cases(n_per_category))
    cases.extend(generate_ipv4_cases(n_per_category))
    cases.extend(generate_api_key_cases(n_per_category))
    cases.extend(generate_jwt_cases(n_per_category))
    cases.extend(generate_private_key_cases(n_per_category))
    cases.extend(generate_url_credential_cases(n_per_category))
    cases.extend(generate_credit_card_cases(n_per_category))
    cases.extend(generate_mixed_cases(n_per_category // 5))
    cases.extend(generate_negative_cases(100))
    return cases
