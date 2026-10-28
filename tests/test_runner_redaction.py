import json

import pytest

from heel.runner.redaction import Redactor, safe_json_value


def test_bounded_deterministic_secret_and_secret_shaped_json_fields():
    redactor = Redactor(configured=("live-password",))
    value = (
        '{"a":"live-password","authorization":"Bearer abc.def.ghi",'
        '"Set-Cookie":"sid=secret; HttpOnly","api_key":"sk-live-123456789012"}'
    )
    redacted, count = redactor.redact(value)
    assert count == 4
    for secret in ("live-password", "abc.def.ghi", "sid=", "sk-live-"):
        assert secret not in redacted
    assert redactor.redact(value) == (redacted, count)


@pytest.mark.parametrize(
    "sample",
    [
        "Authorization: Bearer eyJh.eyJi.sig",
        "cookie: session=value; other=two",
        "Set-Cookie: sid=value; HttpOnly",
        "x-api-key: abcd1234ef567890abcd1234ef567890",
        "token=eyJh.eyJi.sig",
        "password=hunter-two-secret",
        "sk-live-12345678901234567890",
    ],
)
def test_common_token_forms_are_redacted_without_reflection(sample):
    output, count = Redactor().redact(sample)
    assert count >= 1
    assert sample not in output
    assert "[REDACTED:" in output


def test_redaction_is_output_bounded_and_configuration_is_closed():
    output, _ = Redactor().redact("x" * 100_000)
    assert len(output.encode("utf-8")) <= 4096
    maximum_secret = "s" * (16 * 1024)
    redactor = Redactor((maximum_secret,))
    assert redactor.count_bytes(b"prefix" + maximum_secret.encode() + b"suffix") == 1
    with pytest.raises(ValueError):
        Redactor(("x" * (16 * 1024 + 1),))
    with pytest.raises(ValueError):
        Redactor(tuple(str(index).zfill(4) for index in range(65)))
    with pytest.raises(ValueError):
        Redactor(("abc",))
    with pytest.raises(ValueError):
        Redactor().redact("x" * 300_000)


def test_safe_serialization_is_recursive_closed_bounded_and_nonreflective():
    secret = "super-secret-value"
    value = {
        "safe": [1, True, False, None],
        "password": secret,
        "nested": {"authorization": f"Bearer {secret}"},
        "tuple": (secret,),
        "huge": "x" * 5000,
    }
    result = safe_json_value(value, Redactor((secret,)))
    serialized = json.dumps(result, separators=(",", ":"))
    assert secret not in serialized and len(serialized.encode()) < 12_000
    assert isinstance(result, dict) and isinstance(result["safe"], list)
    assert result["tuple"][0].startswith("[REDACTED:")
    assert safe_json_value(value, Redactor()) == safe_json_value(value, Redactor())
    with pytest.raises(TypeError):
        safe_json_value({object(): "value"}, Redactor())
    with pytest.raises(ValueError):
        safe_json_value({"huge_integer": 2**60}, Redactor())
    with pytest.raises(ValueError):
        safe_json_value({"huge": "x" * 300_000}, Redactor())


def test_errors_and_repr_never_expose_configured_secrets():
    secret = "visible-configured-secret"
    redactor = Redactor((secret,))
    assert secret not in repr(redactor)
    with pytest.raises(ValueError) as raised:
        redactor.redact("x" * 300_000)
    assert secret not in str(raised.value)

    class Bad:
        def __str__(self):
            return secret

    with pytest.raises(TypeError) as raised:
        safe_json_value(Bad(), redactor)
    assert secret not in str(raised.value)


def test_overlapping_configured_values_count_one_span_and_secret_key_shapes_are_closed():
    redactor = Redactor(("super-secret", "secret"))
    output, count = redactor.redact("credential=super-secret")
    assert "super-secret" not in output and count == 1
    value = {
        "database_password": "one",
        "clientSecret": "two",
        "access-token": "three",
        "safe_count": 4,
    }
    serialized = json.dumps(safe_json_value(value, Redactor()), sort_keys=True)
    assert all(secret not in serialized for secret in ("one", "two", "three"))
    assert '"safe_count": 4' in serialized
