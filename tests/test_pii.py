from opsguard.pii import find_pii, redact_fields


def redact(text: str) -> tuple[str, dict[str, int]]:
    fields, counts = redact_fields({"t": text})
    return fields["t"], counts


def test_email_phone_card_are_redacted() -> None:
    text, counts = redact("Mail jane.doe@example.com or call +44 20 7946 0958, card 4111 1111 1111 1111")
    assert "example.com" not in text and "4111" not in text and "7946" not in text
    assert counts == {"EMAIL": 1, "CARD": 1, "PHONE": 1}


def test_card_requires_luhn_so_order_numbers_survive() -> None:
    text, counts = redact("Order 1234567890123456 failed")
    assert "1234567890123456" in text
    assert "CARD" not in counts


def test_secrets_keep_their_label_but_lose_the_value() -> None:
    text, counts = redact("password=Hunter2! and api_key: sk-demo-abcdefghijklmnop1234")
    assert "Hunter2" not in text and "sk-demo" not in text
    assert text.startswith("password=[SECRET_")
    assert counts == {"SECRET": 2}


def test_bearer_token_and_private_key() -> None:
    key = "-----BEGIN RSA PRIVATE KEY-----\nMIIEabc\n-----END RSA PRIVATE KEY-----"
    text, counts = redact(f"Authorization: Bearer abcdefghijklmnopqrstuvwx\n{key}")
    assert "abcdefghijklmnop" not in text and "MIIE" not in text
    assert counts == {"SECRET": 1, "PRIVATE_KEY": 1}


def test_same_value_gets_same_placeholder_across_fields() -> None:
    fields, counts = redact_fields({"title": "a@example.com down", "body": "a@example.com, b@example.org"})
    assert fields["title"] == "[EMAIL_1] down"
    assert fields["body"] == "[EMAIL_1], [EMAIL_2]"
    assert counts["EMAIL"] == 3


def test_ip_redacted_but_timestamps_and_versions_not_mistaken_for_phones() -> None:
    text, counts = redact("At 2026-01-15 09:05 host 10.1.2.3 on build 4.2.1 failed")
    assert "[IP_ADDRESS_1]" in text and "2026-01-15 09:05" in text and "4.2.1" in text
    assert counts == {"IP_ADDRESS": 1}


def test_placeholders_are_not_rescanned_as_pii() -> None:
    assert find_pii("Contact [EMAIL_1] about [SECRET_2]") == {}
